package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/howtomakeaname/univpn-cli/internal/netstack"
	"github.com/howtomakeaname/univpn-cli/internal/proxy"
	"github.com/howtomakeaname/univpn-cli/internal/vpn"
	"github.com/howtomakeaname/univpn-cli/internal/wire"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// Exercise real TLS, two VPN channels, MFA, both IP stacks, and HTTP CONNECT.
func TestTLSMFATunnelConcurrentProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cfg := certServer.TLS.Clone()
	sum := sha256.Sum256(certServer.Certificate().Raw)
	certServer.Close()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := tls.NewListener(raw, cfg)
	defer l.Close()
	remote, err := netstack.New(netip.MustParseAddr("10.44.0.2"), 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	echo, err := gonet.ListenTCP(remote.Stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(remote.IP.AsSlice()), Port: 2222}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	token := bytes.Repeat([]byte{0x42}, 32)
	gwErr := make(chan error, 3)
	var gw sync.WaitGroup
	gw.Add(1)
	go func() {
		defer gw.Done()
		ctl, e := l.Accept()
		if e != nil {
			gwErr <- e
			return
		}
		defer ctl.Close()
		stop := context.AfterFunc(ctx, func() { ctl.Close() })
		defer stop()
		hello := make([]byte, 340)
		if _, e = io.ReadFull(ctl, hello); e != nil {
			gwErr <- e
			return
		}
		wire.Write(ctl, 0, make([]byte, 4))
		if _, e = wire.Expect(ctl, 1); e != nil {
			gwErr <- e
			return
		}
		wire.Write(ctl, 1, wire.AppendTLV([]byte{0, 0, 0, 1, 0, 0, 0, 0}, 2, []byte{1}))
		otp, e := wire.Expect(ctl, 2)
		if e != nil {
			gwErr <- e
			return
		}
		if len(otp) != 33 || string(otp[1:7]) != "123456" {
			gwErr <- fmt.Errorf("invalid second factor")
			return
		}
		wire.Write(ctl, 1, wire.AppendTLV(make([]byte, 8), 3, token))
		if _, e = wire.Expect(ctl, 3); e != nil {
			gwErr <- e
			return
		}
		wire.Write(ctl, 3, wire.AppendTLV(make([]byte, 4), 1, []byte{10, 44, 0, 1, 0}))
		data, e := l.Accept()
		if e != nil {
			gwErr <- e
			return
		}
		defer data.Close()
		stopData := context.AfterFunc(ctx, func() { data.Close() })
		defer stopData()
		if p, e := wire.Expect(data, 0x64); e != nil || !bytes.Equal(p, token) {
			gwErr <- fmt.Errorf("invalid data bind: %v", e)
			return
		}
		wire.Write(data, 0x64, []byte{0})
		var mu sync.Mutex
		write := func(cmd byte, p []byte) error { mu.Lock(); defer mu.Unlock(); return wire.Write(data, cmd, p) }
		gw.Add(2)
		go func() {
			defer gw.Done()
			for {
				f, e := wire.Read(ctl)
				if e != nil {
					return
				}
				if e = wire.Write(ctl, f.Command, f.Payload); e != nil {
					return
				}
			}
		}()
		go func() {
			defer gw.Done()
			for {
				p, e := remote.Receive(ctx)
				if e != nil {
					return
				}
				if e = write(wire.DataPacket, append(make([]byte, 8), p...)); e != nil {
					return
				}
			}
		}()
		for {
			f, e := wire.Read(data)
			if e != nil {
				return
			}
			switch f.Command {
			case wire.DataAlive:
				write(wire.DataAlive, nil)
			case wire.DataPacket:
				if len(f.Payload) < 28 {
					gwErr <- fmt.Errorf("short packet")
					return
				}
				if e = remote.Inject(f.Payload[8:]); e != nil {
					gwErr <- e
					return
				}
			}
		}
	}()
	defer func() { cancel(); l.Close(); gw.Wait() }()
	s, err := vpn.Login(ctx, vpn.Options{TLS: vpn.TLSOptions{Gateway: l.Addr().String(), PinSHA256: hex.EncodeToString(sum[:])}, Username: "test-user", Password: []byte("test-password"), OTP: func(context.Context) ([]byte, error) { return []byte("123456"), nil }})
	if err != nil {
		select {
		case e := <-gwErr:
			t.Log(e)
		default:
		}
		t.Fatal(err)
	}
	defer s.Close()
	local, err := netstack.New(s.VIP, 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	policy := netstack.Policy{Net: local, Allow: []netip.Prefix{netip.MustParsePrefix("10.44.0.2/32")}, Hosts: map[string]netip.Addr{"atlas.internal": remote.IP}}
	pl, err := proxy.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() { done <- s.Run(ctx, local.Inject, local.Receive) }()
	go func() { done <- (&proxy.Server{Dial: policy.DialContext}).Serve(ctx, pl) }()
	defer func() { cancel(); s.Close(); pl.Close(); <-done; <-done }()
	var clients sync.WaitGroup
	for i := range 8 {
		clients.Add(1)
		go func(i int) {
			defer clients.Done()
			c, e := net.Dial("tcp", pl.Addr().String())
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			fmt.Fprint(c, "CONNECT atlas.internal:2222 HTTP/1.1\r\nHost: atlas.internal:2222\r\n\r\n")
			r := bufio.NewReader(c)
			response, e := http.ReadResponse(r, nil)
			if e != nil || response.StatusCode != 200 {
				t.Errorf("CONNECT failed: %v", e)
				return
			}
			payload := bytes.Repeat([]byte{byte(i + 1)}, 256<<10)
			written := make(chan error, 1)
			go func() { _, e := c.Write(payload); written <- e }()
			b := make([]byte, len(payload))
			_, e = io.ReadFull(r, b)
			if e != nil || !bytes.Equal(b, payload) {
				t.Errorf("data mismatch: %v", e)
			}
			if e = <-written; e != nil {
				t.Error(e)
			}
		}(i)
	}
	clients.Wait()
}

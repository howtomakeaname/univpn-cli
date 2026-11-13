package netstack

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestConcurrentTCPWithPacketLoss(t *testing.T) {
	a, err := New(netip.MustParseAddr("10.44.0.1"), 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(netip.MustParseAddr("10.44.0.2"), 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var pumps sync.WaitGroup
	for _, pair := range [][2]*Network{{a, b}, {b, a}} {
		pair := pair
		pumps.Add(1)
		go func() {
			defer pumps.Done()
			drop := pair[0] == a
			for {
				p, e := pair[0].Receive(ctx)
				if e != nil {
					return
				}
				if drop {
					drop = false
					continue
				}
				if e = pair[1].Inject(p); e != nil {
					return
				}
			}
		}()
	}
	defer func() { cancel(); pumps.Wait() }()
	l, err := gonet.ListenTCP(b.Stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(b.IP.AsSlice()), Port: 2222}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	p := Policy{Net: a, Allow: []netip.Prefix{netip.MustParsePrefix("10.44.0.2/32")}, Hosts: map[string]netip.Addr{"atlas.internal": b.IP}}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, e := p.DialContext(ctx, "tcp", "atlas.internal:2222")
			if e != nil {
				errs <- e
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte{byte(i + 1)}, 128<<10)
			go func() { c.Write(payload); c.(interface{ CloseWrite() error }).CloseWrite() }()
			out, e := io.ReadAll(c)
			if e == nil && !bytes.Equal(out, payload) {
				e = io.ErrUnexpectedEOF
			}
			errs <- e
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
}

func TestNoDirectFallbackAndPolicy(t *testing.T) {
	p := Policy{Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "8.8.8.8", "::1"} {
		if p.Allowed(netip.MustParseAddr(ip)) {
			t.Fatal("allowed", ip)
		}
	}
	for _, target := range []string{"8.8.8.8:443", "localhost:80", "unconfigured.internal:22", "[::1]:80", "10.0.0.2:0", "10.0.0.2:70000"} {
		// A nil network proves every rejected target stops before any dial.
		if _, err := p.DialContext(context.Background(), "tcp", target); err == nil {
			t.Fatal("accepted", target)
		}
	}
}

func TestRejectIPForOtherSession(t *testing.T) {
	n, e := New(netip.MustParseAddr("10.44.0.1"), 1400)
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	b := make([]byte, 20)
	b[0] = 0x45
	b[3] = 20
	copy(b[16:], []byte{10, 44, 0, 2})
	if n.Inject(b) == nil {
		t.Fatal("injected packet for another session")
	}
	if n.Inject([]byte{0x45}) == nil {
		t.Fatal("injected truncated packet")
	}
}

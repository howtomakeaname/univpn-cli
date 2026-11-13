package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/howtomakeaname/univpn-cli/internal/config"
	"github.com/howtomakeaname/univpn-cli/internal/vpn"
	"github.com/howtomakeaname/univpn-cli/internal/wire"
)

// The gateway requests fresh authentication, then revokes the replacement. Each
// attempt must verify TLS, send a different code, bind a new token, and close its
// listener and both old channels before another login starts.
func TestTLSReconnectRequiresFreshMFAAndStopsOnRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsConfig := certServer.TLS.Clone()
	pin := sha256.Sum256(certServer.Certificate().Raw)
	certServer.Close()
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stopGateway := context.AfterFunc(ctx, func() { l.Close() })
	defer stopGateway()
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddress := port.Addr().String()
	port.Close()

	gatewayDone := make(chan error, 1)
	go func() {
		for index, code := range []string{"111111", "222222"} {
			if err := func() error {
				ctl, err := l.Accept()
				if err != nil {
					return err
				}
				defer ctl.Close()
				ctl.SetDeadline(time.Now().Add(5 * time.Second))
				hello := make([]byte, 340)
				if _, err := io.ReadFull(ctl, hello); err != nil {
					return err
				}
				if err := wire.Write(ctl, wire.FirstConnect, make([]byte, 4)); err != nil {
					return err
				}
				p, err := wire.Expect(ctl, wire.Auth)
				if err != nil {
					return err
				}
				if len(p) < 260 {
					return errors.New("short authentication request")
				}
				fields, err := wire.ParseTLVs(p[260:])
				if err != nil || len(fields) != 3 || string(fields[0].Value) != "test-user\x00" || string(fields[1].Value) != "test-password\x00" {
					return errors.New("fresh password authentication missing")
				}
				if err := wire.Write(ctl, wire.Auth, wire.AppendTLV([]byte{0, 0, 0, 1, 0, 0, 0, 0}, 2, []byte{1})); err != nil {
					return err
				}
				p, err = wire.Expect(ctl, wire.SecondAuth)
				if err != nil {
					return err
				}
				if len(p) != 33 || p[0] != 1 || string(p[1:7]) != code {
					return errors.New("second factor reused or missing")
				}
				token := bytes.Repeat([]byte{byte(index + 1)}, 32)
				if err := wire.Write(ctl, wire.Auth, wire.AppendTLV(make([]byte, 8), 3, token)); err != nil {
					return err
				}
				p, err = wire.Expect(ctl, wire.RequestVIP)
				if err != nil || !bytes.Equal(p, token) {
					return fmt.Errorf("reused VIP token: %v", err)
				}
				if err := wire.Write(ctl, wire.RequestVIP, wire.AppendTLV(make([]byte, 4), 1, []byte{10, 44, 0, 1, 0})); err != nil {
					return err
				}
				data, err := l.Accept()
				if err != nil {
					return err
				}
				defer data.Close()
				data.SetDeadline(time.Now().Add(5 * time.Second))
				p, err = wire.Expect(data, wire.DataConnect)
				if err != nil || !bytes.Equal(p, token) {
					return fmt.Errorf("reused data token: %v", err)
				}
				if err := wire.Write(data, wire.DataConnect, []byte{0}); err != nil {
					return err
				}
				command := byte(wire.SecondAuth)
				if index == 1 {
					command = 0x32
				}
				if err := wire.Write(ctl, command, nil); err != nil {
					return err
				}
				for _, c := range []net.Conn{ctl, data} {
					if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
						return fmt.Errorf("old channel remained open: %v", err)
					}
				}
				return nil
			}(); err != nil {
				gatewayDone <- err
				return
			}
		}
		gatewayDone <- nil
	}()
	c := config.Config{Gateway: l.Addr().String(), Domain: "vpn.example.com", Username: "test-user", CertSHA256: hex.EncodeToString(pin[:]), Listen: proxyAddress, AllowCIDRs: []string{"10.44.0.2/32"}, MTU: 1400, MaxConnections: 8}
	input := bufio.NewReader(strings.NewReader("test-password\n111111\ntest-password\n222222\n"))
	attempts := 0
	err = connectLoop(ctx, 3, func() error { attempts++; return connectOnce(ctx, c, input, true, true) }, func(context.Context, time.Duration) error {
		conn, err := net.DialTimeout("tcp", proxyAddress, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return errors.New("old listener remained open during backoff")
		}
		return nil
	})
	if !errors.Is(err, vpn.ErrSessionRevoked) || attempts != 2 {
		t.Fatalf("attempts=%d error=%v", attempts, err)
	}
	if err := <-gatewayDone; err != nil {
		t.Fatal(err)
	}
}

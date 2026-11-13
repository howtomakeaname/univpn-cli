package vpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/howtomakeaname/univpn-cli/internal/wire"
)

func TestEndpointRequirementsFailBeforeDataChannel(t *testing.T) {
	for _, flags := range []byte{1, 0x11, 0x21, 0x10, 0xff} {
		t.Run(fmt.Sprintf("flags-%02x", flags), func(t *testing.T) {
			ctl, gateway := net.Pipe()
			defer gateway.Close()
			dials := 0
			go func() {
				hello := make([]byte, 340)
				if _, err := io.ReadFull(gateway, hello); err != nil {
					return
				}
				if wire.Write(gateway, wire.FirstConnect, make([]byte, 4)) != nil {
					return
				}
				if _, err := wire.Expect(gateway, wire.Auth); err != nil {
					return
				}
				p := make([]byte, 8)
				p[5] = flags
				_ = wire.Write(gateway, wire.Auth, wire.AppendTLV(p, 3, bytes.Repeat([]byte{0x42}, 32)))
			}()
			_, err := Login(context.Background(), Options{TLS: TLSOptions{Gateway: "vpn.example.com:443"}, Username: "u", Password: []byte("p"), Dial: func(context.Context) (net.Conn, error) { dials++; return ctl, nil }})
			var requirement *EndpointRequirement
			if !errors.Is(err, ErrEndpointComplianceRequired) || !errors.As(err, &requirement) || requirement.Check != flags&15 || requirement.Mode != flags>>4 {
				t.Fatalf("incorrect requirement: %v", err)
			}
			if dials != 1 {
				t.Fatal("opened a data channel before endpoint checks")
			}
			if Reconnectable(err) {
				t.Fatal("policy rejection must not retry")
			}
		})
	}
}

func TestLifecycleEventsCloseBothChannels(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command byte
		want    error
	}{{"revocation", commandKickout, ErrSessionRevoked}, {"fresh-auth", wire.SecondAuth, ErrReauthenticationRequired}} {
		t.Run(tc.name, func(t *testing.T) {
			ctl, gwctl := net.Pipe()
			data, gwdata := net.Pipe()
			defer gwctl.Close()
			defer gwdata.Close()
			s := &Session{control: ctl, data: data, started: time.Now()}
			copy(s.token[:], bytes.Repeat([]byte{0x42}, 32))
			done := make(chan error, 1)
			go func() {
				done <- s.Run(context.Background(), func([]byte) error { return nil }, func(ctx context.Context) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() })
			}()
			if err := wire.Write(gwctl, tc.command, nil); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, tc.want) {
					t.Fatalf("got %v, want %v", err, tc.want)
				}
			case <-time.After(time.Second):
				t.Fatal("session remained open after lifecycle event")
			}
			if s.token != [32]byte{} {
				t.Fatal("session token retained after shutdown")
			}
			for _, c := range []net.Conn{gwctl, gwdata} {
				c.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("channel remained open: %v", err)
				}
			}
		})
	}
}

func TestLocalSessionLimitDoesNotWaitForTraffic(t *testing.T) {
	ctl, gwctl := net.Pipe()
	data, gwdata := net.Pipe()
	defer gwctl.Close()
	defer gwdata.Close()
	s := &Session{control: ctl, data: data, started: time.Now().Add(-time.Second), maxDuration: time.Second}
	done := make(chan error, 1)
	go func() {
		done <- s.Run(context.Background(), func([]byte) error { return nil }, func(ctx context.Context) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrSessionLimit) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("local lifetime did not close an idle tunnel")
	}
}

func TestReconnectableDistinguishesProtocolAndPolicyFailures(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{ErrReauthenticationRequired, true}, {ErrSessionLimit, true}, {ErrSessionRevoked, false},
		{&EndpointRequirement{Check: 1}, false}, {&ChannelError{Channel: "control", Err: io.EOF}, true},
		{&ChannelError{Channel: "data", Err: context.DeadlineExceeded}, true},
		{&ChannelError{Channel: "control", Err: errors.New("unsupported VPN frame magic/version")}, false},
		{errors.New("VPN authentication rejected"), false}, {io.EOF, false},
	} {
		if got := Reconnectable(tc.err); got != tc.want {
			t.Fatalf("Reconnectable(%v)=%v", tc.err, got)
		}
	}
}

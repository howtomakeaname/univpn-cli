package vpn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/howtomakeaname/univpn-cli/internal/wire"
)

func TestMFALogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctl, gwctl := net.Pipe()
	defer gwctl.Close()
	data, gwdata := net.Pipe()
	defer gwdata.Close()
	errCh := make(chan error, 2)
	token := bytes.Repeat([]byte{0x42}, 32)
	go func() {
		check := func() error {
			hello := make([]byte, 340)
			if _, e := io.ReadFull(gwctl, hello); e != nil {
				return e
			}
			if string(hello[80:95]) != "vpn.example.com" {
				return errors.New("hello domain mismatch")
			}
			if e := wire.Write(gwctl, 0, make([]byte, 4)); e != nil {
				return e
			}
			a, e := wire.Expect(gwctl, 1)
			if e != nil {
				return e
			}
			if len(a) < 260 {
				return errors.New("auth too short")
			}
			tlvs, e := wire.ParseTLVs(a[260:])
			if e != nil {
				return e
			}
			if len(tlvs) != 3 || string(tlvs[0].Value) != "u%2B%26%25\x00" || string(tlvs[1].Value) != " p%26%2B%25 \x00" {
				return errors.New("credential escaping mismatch")
			}
			challenge := make([]byte, 8)
			challenge[3] = 1
			challenge = wire.AppendTLV(challenge, 2, []byte{1})
			if e = wire.Write(gwctl, 1, challenge); e != nil {
				return e
			}
			otp, e := wire.Expect(gwctl, 2)
			if e != nil {
				return e
			}
			if len(otp) != 33 || otp[0] != 1 || string(otp[1:7]) != "123456" || !bytes.Equal(otp[7:], make([]byte, 26)) {
				return errors.New("OTP field mismatch")
			}
			if e = wire.Write(gwctl, 1, wire.AppendTLV(make([]byte, 8), 3, token)); e != nil {
				return e
			}
			p, e := wire.Expect(gwctl, 3)
			if e != nil {
				return e
			}
			if !bytes.Equal(p, token) {
				return errors.New("VIP token mismatch")
			}
			return wire.Write(gwctl, 3, wire.AppendTLV(make([]byte, 4), 1, []byte{10, 44, 0, 1, 0}))
		}
		errCh <- check()
	}()
	go func() {
		p, e := wire.Expect(gwdata, 0x64)
		if e == nil && !bytes.Equal(p, token) {
			e = errors.New("data token mismatch")
		}
		if e == nil {
			e = wire.Write(gwdata, 0x64, []byte{0})
		}
		errCh <- e
	}()
	var calls atomic.Int32
	s, err := Login(ctx, Options{TLS: TLSOptions{Gateway: "vpn.example.com:443"}, Domain: "vpn.example.com", Username: "u+&%", Password: []byte(" p&+% "), OTP: func(context.Context) ([]byte, error) { return []byte("123456"), nil }, Dial: func(context.Context) (net.Conn, error) {
		if calls.Add(1) == 1 {
			return ctl, nil
		}
		return data, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.VIP != netip.MustParseAddr("10.44.0.1") {
		t.Fatal("wrong VIP")
	}
	for range 2 {
		if e := <-errCh; e != nil {
			t.Fatal(e)
		}
	}
}

func TestRejectUnsupportedAuth(t *testing.T) {
	for _, p := range [][]byte{{0}, append([]byte{0, 0, 0, 0, 1, 0, 0, 0}, 0, 3, 0, 32), append(make([]byte, 8), 0, 3, 0, 33, 1)} {
		if _, _, _, err := parseAuth(p); err == nil {
			t.Fatal("accepted unsafe authentication response")
		}
	}
	status, _, otp, err := parseAuth(wire.AppendTLV([]byte{0, 0, 0, 1, 0, 0, 0, 0}, 2, []byte{1}))
	if status != 1 || !otp || err != nil {
		t.Fatal("missing MFA challenge")
	}
}

func TestChannelFailureCancelsIdlePumps(t *testing.T) {
	ctl, gwctl := net.Pipe()
	data, gwdata := net.Pipe()
	defer gwdata.Close()
	s := &Session{control: ctl, data: data, started: time.Now()}
	done := make(chan error, 1)
	go func() {
		done <- s.Run(context.Background(), func([]byte) error { return nil }, func(ctx context.Context) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() })
	}()
	gwctl.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("channel failure not returned")
		}
	case <-time.After(time.Second):
		t.Fatal("packet pumps leaked after control channel failure")
	}
}

func TestCancelDuringHello(t *testing.T) {
	c, g := net.Pipe()
	defer g.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := Login(ctx, Options{TLS: TLSOptions{Gateway: "vpn.example.com:443"}, Username: "u", Password: []byte("p"), Dial: func(context.Context) (net.Conn, error) { return c, nil }})
	if err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestExpiryReminderDoesNotRequirePasswordChange(t *testing.T) {
	for _, tc := range []struct {
		flags, reason byte
		reject        bool
	}{{0x20, 0, false}, {0x21, 0, false}, {6, 1, true}, {0, 2, true}} {
		policy := make([]byte, 12)
		policy[0] = tc.flags
		policy[1] = tc.reason
		p := wire.AppendTLV(make([]byte, 8), 1, policy)
		p = wire.AppendTLV(p, 3, bytes.Repeat([]byte{1}, 32))
		_, _, _, err := parseAuth(p)
		if (err != nil) != tc.reject {
			t.Fatalf("flags=%02x reason=%d error=%v", tc.flags, tc.reason, err)
		}
	}
}

func TestLoginMACWireTLV3(t *testing.T) {
	defaultHash := sha256.Sum256([]byte("alice|vpn.example.com:443"))
	defaultHash[0] = (defaultHash[0] | 2) & 0xfe
	wantDefault := fmt.Sprintf("%02X%02X-%02X%02X-%02X%02X", defaultHash[0], defaultHash[1], defaultHash[2], defaultHash[3], defaultHash[4], defaultHash[5])

	for _, tc := range []struct {
		name, mac, want string
	}{
		{"default deterministic", "", wantDefault},
		{"hyphen octets", "02-11-22-33-44-55", "0211-2233-4455"},
		{"colon octets", "02:11:22:33:44:55", "0211-2233-4455"},
		{"hyphen groups", "0211-2233-4455", "0211-2233-4455"},
		{"dot groups", "0211.2233.4455", "0211-2233-4455"},
		{"mixed case", "02-aB-cD-33-44-eF", "02AB-CD33-44EF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctl, gwctl := net.Pipe()
			defer gwctl.Close()
			gotCh := make(chan string, 1)
			errCh := make(chan error, 1)
			go func() {
				hello := make([]byte, 340)
				if _, err := io.ReadFull(gwctl, hello); err != nil {
					errCh <- err
					return
				}
				if err := wire.Write(gwctl, wire.FirstConnect, make([]byte, 4)); err != nil {
					errCh <- err
					return
				}
				a, err := wire.Expect(gwctl, wire.Auth)
				if err != nil {
					errCh <- err
					return
				}
				if len(a) < 260 {
					errCh <- errors.New("auth too short")
					return
				}
				tlvs, err := wire.ParseTLVs(a[260:])
				if err != nil {
					errCh <- err
					return
				}
				for _, tlv := range tlvs {
					if tlv.Type == 3 {
						gotCh <- string(tlv.Value)
					}
				}
				// Reject with status 2 to end Login cleanly after capturing TLV 3.
				errCh <- wire.Write(gwctl, wire.Auth, []byte{0, 0, 0, 2, 0, 0, 0, 0})
			}()
			_, _ = Login(ctx, Options{
				TLS:      TLSOptions{Gateway: "vpn.example.com:443"},
				Domain:   "vpn.example.com",
				Username: "alice",
				Password: []byte("secret"),
				MAC:      tc.mac,
				Dial:     func(context.Context) (net.Conn, error) { return ctl, nil },
			})
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-gotCh:
				if got != tc.want {
					t.Fatalf("TLV 3 = %q, want %q", got, tc.want)
				}
			default:
				t.Fatal("missing TLV 3")
			}
		})
	}
}

func TestLoginRejectsInvalidMAC(t *testing.T) {
	for _, bad := range []string{
		"02:11:22:33:44",
		"02:11:22:33:44:55:66:77",
		"02:11:22:33:44:gg",
		"02:11-22:33:44:55",
		"0211-2233.4455",
		" 02:11:22:33:44:55",
		"02:11:22:33:44:55 ",
		"00:00:00:00:00:00",
		"ff:ff:ff:ff:ff:ff",
		"01:00:5e:00:00:01",
		"02:11:22:33:44:55\x00",
		"02:11:22:33:44:\n5",
	} {
		t.Run(bad, func(t *testing.T) {
			_, err := Login(context.Background(), Options{
				TLS:      TLSOptions{Gateway: "vpn.example.com:443"},
				Username: "alice",
				Password: []byte("secret"),
				MAC:      bad,
				Dial: func(context.Context) (net.Conn, error) {
					t.Fatal("Dial called despite invalid MAC")
					return nil, nil
				},
			})
			if err == nil {
				t.Fatalf("accepted invalid MAC %q", bad)
			}
		})
	}
}

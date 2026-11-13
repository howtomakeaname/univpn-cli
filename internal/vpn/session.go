package vpn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/howtomakeaname/univpn-cli/internal/wire"
)

type Options struct {
	TLS              TLSOptions
	Domain, Username string
	Password         []byte
	OTP              func(context.Context) ([]byte, error)
	// MaxDuration caps local session use; it does not override gateway policy.
	MaxDuration time.Duration
	// Dial is injectable for isolated protocol tests; CLI always uses verified TLS.
	Dial func(context.Context) (net.Conn, error)
}

type Session struct {
	control, data     net.Conn
	controlMu, dataMu sync.Mutex
	closeOnce         sync.Once
	token             [32]byte
	VIP               netip.Addr
	started           time.Time
	maxDuration       time.Duration
}

// Hello does not authenticate or send credentials.
func Hello(c net.Conn, domain string) error {
	b, err := wire.Hello(domain)
	if err != nil {
		return err
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := wire.WriteAll(c, b); err != nil {
		return err
	}
	p, err := wire.Expect(c, wire.FirstConnect)
	if err != nil {
		return err
	}
	if len(p) < 4 || binary.BigEndian.Uint32(p) != 0 {
		return errors.New("VPN FirstConnect rejected")
	}
	return nil
}

func Login(ctx context.Context, o Options) (_ *Session, err error) {
	if o.Domain == "" {
		o.Domain, _, _ = net.SplitHostPort(o.TLS.Gateway)
	}
	domain, err := wire.Domain(o.Domain)
	if err != nil {
		return nil, err
	}
	if len(o.Username) == 0 || len(o.Username) > 256 || len(o.Password) == 0 || len(o.Password) > 128 || strings.ContainsRune(o.Username, 0) || bytes.IndexByte(o.Password, 0) >= 0 {
		return nil, errors.New("VPN username/password missing, too long or contains NUL")
	}
	dial := o.Dial
	if dial == nil {
		dial = func(ctx context.Context) (net.Conn, error) { return DialTLS(ctx, o.TLS) }
	}
	if o.MaxDuration < 0 {
		return nil, errors.New("session maximum duration cannot be negative")
	}
	s := &Session{started: time.Now(), maxDuration: o.MaxDuration}
	defer func() {
		if err != nil {
			s.Close()
			clear(s.token[:])
		}
	}()
	s.control, err = dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("control TLS: %w", err)
	}
	// Each cancellation callback only touches an already assigned connection.
	stopCtl := context.AfterFunc(ctx, func() { s.control.Close() })
	defer stopCtl()
	if err = Hello(s.control, o.Domain); err != nil {
		return nil, err
	}
	u := escape([]byte(o.Username))
	pw := escape(o.Password)
	defer clear(pw)
	auth := append(domain, 0, 0, 0, 0)
	auth = wire.AppendTLV(auth, 1, append(u, 0))
	auth = wire.AppendTLV(auth, 2, append(pw, 0))
	h := sha256.Sum256([]byte(o.Username + "|" + o.TLS.Gateway))
	h[0] = (h[0] | 2) & 0xfe
	mac := fmt.Sprintf("%02X%02X-%02X%02X-%02X%02X", h[0], h[1], h[2], h[3], h[4], h[5])
	auth = wire.AppendTLV(auth, 3, []byte(mac))
	err = wire.Write(s.control, wire.Auth, auth)
	clear(auth)
	if err != nil {
		return nil, err
	}
	p, err := wire.Expect(s.control, wire.Auth)
	if err != nil {
		return nil, err
	}
	status, token, needOTP, err := parseAuth(p)
	clear(p)
	if err != nil {
		return nil, err
	}
	if status == 1 && needOTP {
		if o.OTP == nil {
			return nil, errors.New("gateway requires SMS/email verification code")
		}
		otpCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		code, e := o.OTP(otpCtx)
		cancel()
		if e != nil {
			return nil, e
		}
		defer clear(code)
		if len(code) < 1 || len(code) > 31 || bytes.IndexByte(code, 0) >= 0 {
			return nil, errors.New("verification code must be 1..31 bytes without NUL")
		}
		// Encode the second factor with subtype 1 and a fixed, NUL-padded field.
		otp := make([]byte, 33)
		otp[0] = 1
		copy(otp[1:], code)
		s.control.SetDeadline(time.Now().Add(15 * time.Second))
		err = wire.Write(s.control, wire.SecondAuth, otp)
		clear(otp)
		if err != nil {
			return nil, err
		}
		// Second-factor completion returns the common authentication response.
		p, err = wire.Expect(s.control, wire.Auth)
		if err != nil {
			return nil, err
		}
		status, token, _, err = parseAuth(p)
		clear(p)
		if err != nil {
			return nil, err
		}
	}
	if status != 0 {
		return nil, fmt.Errorf("VPN authentication rejected (status %d); no automatic retry", status)
	}
	if len(token) != 32 {
		return nil, errors.New("VPN authentication supplied no session token")
	}
	copy(s.token[:], token)
	clear(token)
	s.control.SetDeadline(time.Now().Add(15 * time.Second))
	if err = wire.Write(s.control, wire.RequestVIP, s.token[:]); err != nil {
		return nil, err
	}
	p, err = wire.Expect(s.control, wire.RequestVIP)
	if err != nil {
		return nil, err
	}
	if len(p) < 4 || p[0] != 0 {
		return nil, errors.New("VPN virtual IP request rejected")
	}
	tlvs, err := wire.ParseTLVs(p[4:])
	if err != nil {
		return nil, err
	}
	for _, t := range tlvs {
		if t.Type == 1 && len(t.Value) == 5 {
			s.VIP = netip.AddrFrom4([4]byte(t.Value[:4]))
		}
	}
	if !s.VIP.Is4() || s.VIP.IsUnspecified() || s.VIP.IsMulticast() || s.VIP.IsLoopback() {
		return nil, errors.New("VPN supplied invalid virtual IPv4 address")
	}
	s.data, err = dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("data TLS: %w", err)
	}
	stopData := context.AfterFunc(ctx, func() { s.data.Close() })
	defer stopData()
	s.data.SetDeadline(time.Now().Add(15 * time.Second))
	if err = wire.Write(s.data, wire.DataConnect, s.token[:]); err != nil {
		return nil, err
	}
	p, err = wire.Expect(s.data, wire.DataConnect)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p, []byte{0}) {
		return nil, errors.New("VPN data-channel bind rejected")
	}
	s.control.SetDeadline(time.Time{})
	s.data.SetDeadline(time.Time{})
	s.started = time.Now()
	return s, nil
}

func escape(b []byte) []byte {
	var out []byte
	for _, c := range b {
		switch c {
		case '%':
			out = append(out, "%25"...)
		case '&':
			out = append(out, "%26"...)
		case '+':
			out = append(out, "%2B"...)
		default:
			out = append(out, c)
		}
	}
	return out
}

func parseAuth(p []byte) (uint32, []byte, bool, error) {
	if len(p) < 8 {
		return 0, nil, false, errors.New("short VPN authentication response")
	}
	status := binary.BigEndian.Uint32(p)
	if status > 1 {
		return status, nil, false, nil
	}
	// The low nibble requests endpoint checks and the high nibble selects their mode.
	// Never report a successful health check without executing the required policy.
	if p[5] != 0 {
		return 0, nil, false, &EndpointRequirement{Check: p[5] & 15, Mode: p[5] >> 4}
	}
	if p[4] != 0 {
		return 0, nil, false, errors.New("gateway requires unsupported authentication result flags; use the official client")
	}
	tlvs, err := wire.ParseTLVs(p[8:])
	if err != nil {
		return 0, nil, false, err
	}
	var token []byte
	var otp bool
	for _, t := range tlvs {
		if t.Type == 2 && len(t.Value) == 1 && t.Value[0] == 1 {
			otp = true
		}
		if t.Type == 3 && len(t.Value) >= 32 {
			token = append([]byte(nil), t.Value[:32]...)
		}
		if t.Type == 1 {
			if len(t.Value) != 12 {
				return 0, nil, false, errors.New("invalid VPN password-policy field")
			}
			// Bit 5 enables expiry reminders; it does not require a password change.
			// A mandatory change is identified by the reason and force/notice bits.
			flags, reason := t.Value[0], t.Value[1]
			if status == 0 && (reason == 2 || (reason == 1 && flags&6 == 6)) {
				return 0, nil, false, errors.New("gateway requires a password change; use vendor client")
			}
		}
	}
	return status, token, otp, nil
}

func (s *Session) Close() {
	s.closeOnce.Do(func() {
		if s.control != nil {
			s.control.Close()
		}
		if s.data != nil {
			s.data.Close()
		}
	})
}

// Run closes both channels and cancels the packet pumps on ANY channel failure.
// recv/send must honor ctx; all queues downstream are bounded.
func (s *Session) Run(parent context.Context, send func([]byte) error, recv func(context.Context) ([]byte, error)) error {
	ctx, cancel := context.WithCancel(parent)
	var lifetime <-chan time.Time
	if s.maxDuration > 0 {
		timer := time.NewTimer(time.Until(s.started.Add(s.maxDuration)))
		defer timer.Stop()
		lifetime = timer.C
	}
	defer cancel()
	defer s.Close()
	stop := context.AfterFunc(ctx, s.Close)
	defer stop()
	errs := make(chan error, 6)
	packets := make(chan []byte, 64)
	var wg sync.WaitGroup
	start := func(fn func() error) { wg.Add(1); go func() { defer wg.Done(); errs <- fn() }() }
	start(func() error {
		for {
			s.control.SetReadDeadline(time.Now().Add(60 * time.Second))
			f, e := wire.Read(s.control)
			if e != nil {
				return &ChannelError{Channel: "control", Err: e}
			}
			switch f.Command {
			case wire.Keepalive:
			case wire.SecondAuth:
				return ErrReauthenticationRequired
			case commandKickout:
				return ErrSessionRevoked
			default:
				return fmt.Errorf("unexpected control command 0x%02x", f.Command)
			}
		}
	})
	start(func() error {
		for {
			s.data.SetReadDeadline(time.Now().Add(60 * time.Second))
			f, e := wire.Read(s.data)
			if e != nil {
				return &ChannelError{Channel: "data", Err: e}
			}
			switch f.Command {
			case wire.DataAlive:
			case wire.DataPacket:
				if len(f.Payload) < 28 {
					return errors.New("short VPN IP frame")
				}
				if e = send(f.Payload[8:]); e != nil {
					return e
				}
			default:
				return fmt.Errorf("unexpected data command 0x%02x", f.Command)
			}
		}
	})
	start(func() error {
		for {
			p, e := recv(ctx)
			if e != nil {
				return e
			}
			select {
			case packets <- p:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	start(func() error {
		batch := make([]byte, 0, 64<<10)
		for {
			var p []byte
			select {
			case p = <-packets:
			case <-ctx.Done():
				return ctx.Err()
			}
			batch = batch[:0]
			for count := 0; ; count++ {
				payload := make([]byte, 8+len(p))
				copy(payload[8:], p)
				var e error
				batch, e = wire.AppendFrame(batch, wire.DataPacket, payload)
				if e != nil {
					return e
				}
				if count >= 31 {
					break
				}
				select {
				case p = <-packets:
					continue
				default:
				}
				break
			}
			// Coalesce only queued packets: interactive traffic incurs no timer delay.
			s.dataMu.Lock()
			s.data.SetWriteDeadline(time.Now().Add(15 * time.Second))
			e := wire.WriteAll(s.data, batch)
			s.dataMu.Unlock()
			if e != nil {
				return &ChannelError{Channel: "data", Err: e}
			}
		}
	})
	start(func() error { return s.heartbeat(ctx, true, 10*time.Second) })
	start(func() error { return s.heartbeat(ctx, false, 15*time.Second) })
	var err error
	select {
	case <-parent.Done():
		err = parent.Err()
	case <-lifetime:
		err = ErrSessionLimit
	case err = <-errs:
	}
	cancel()
	s.Close()
	wg.Wait()
	clear(s.token[:])
	return err
}

func (s *Session) write(control bool, cmd byte, p []byte) error {
	c, mu := s.data, &s.dataMu
	if control {
		c, mu = s.control, &s.controlMu
	}
	mu.Lock()
	defer mu.Unlock()
	c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return wire.Write(c, cmd, p)
}

func (s *Session) heartbeat(ctx context.Context, control bool, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			cmd, p := byte(wire.DataAlive), []byte(nil)
			if control {
				cmd = wire.Keepalive
				p = make([]byte, 36)
				copy(p, s.token[:])
				binary.BigEndian.PutUint32(p[32:], uint32(time.Since(s.started).Milliseconds()))
			}
			err := s.write(control, cmd, p)
			clear(p)
			if err != nil {
				channel := "data"
				if control {
					channel = "control"
				}
				return &ChannelError{Channel: channel, Err: err}
			}
		}
	}
}

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/howtomakeaname/univpn-cli/internal/config"
	"github.com/howtomakeaname/univpn-cli/internal/netstack"
	"github.com/howtomakeaname/univpn-cli/internal/proxy"
	"github.com/howtomakeaname/univpn-cli/internal/vpn"
)

// Each attempt reserves a new listener and uses complete TLS/password/MFA login.
// Deferred cleanup finishes before another attempt can open a listener or tunnel.
func connectOnce(ctx context.Context, c config.Config, input *bufio.Reader, passwordStdin, otpStdin bool) error {
	// Reserve the port before authenticating, avoiding an unnecessary MFA request.
	l, err := proxy.Listen(c.Listen)
	if err != nil {
		return err
	}
	defer l.Close()
	var password []byte
	if passwordStdin {
		password, err = secret(ctx, "VPN password (stdin): ", input, true)
	} else if c.PasswordFile != "" {
		password, err = config.ReadPassword(c.PasswordFile)
	} else {
		password, err = secret(ctx, "VPN password: ", input, false)
	}
	if err != nil {
		return err
	}
	defer clear(password)
	if c.Username == "" {
		return errors.New("username is required in configuration")
	}
	fmt.Fprintln(os.Stderr, "Establishing verified TLS control channel...")
	s, err := vpn.Login(ctx, vpn.Options{TLS: c.TLS(), Domain: c.Domain, Username: c.Username, Password: password, MAC: c.MAC, MaxDuration: time.Duration(c.SessionMaxSeconds) * time.Second, OTP: func(ctx context.Context) ([]byte, error) {
		fmt.Fprintln(os.Stderr, "Gateway requires the SMS/email verification code.")
		return secret(ctx, "Verification code: ", input, otpStdin)
	}})
	clear(password)
	if err != nil {
		return err
	}
	defer s.Close()
	n, err := netstack.New(s.VIP, c.MTU)
	if err != nil {
		return err
	}
	defer n.Close()
	policy, err := c.Policy(n)
	if err != nil {
		return err
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	errs := make(chan error, 2)
	go func() { errs <- s.Run(runCtx, n.Inject, n.Receive) }()
	server := &proxy.Server{Dial: policy.DialContext, MaxConnections: c.MaxConnections}
	go func() { errs <- server.Serve(runCtx, l) }()
	fmt.Fprintf(os.Stderr, "READY mixed SOCKS5/HTTP proxy %s; %d allowed CIDR(s); Ctrl-C to stop.\n", l.Addr(), len(c.AllowCIDRs))
	err = <-errs
	stop()
	s.Close()
	l.Close()
	<-errs // Join both workers before closing the TCP/IP stack.
	return err
}

// connectLoop never resumes tokens. Retryable tunnel endings require a fresh
// authentication, and any login rejection stops the loop to avoid account locks.
func connectLoop(ctx context.Context, attempts int, attempt func() error, wait func(context.Context, time.Duration) error) error {
	if attempts < 0 || attempts > 10 {
		return errors.New("reconnect-attempts must be 0..10")
	}
	for completed := 0; ; completed++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := attempt()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil || completed >= attempts || !vpn.Reconnectable(err) {
			return err
		}
		delay := time.Second << min(completed, 5)
		fmt.Fprintf(os.Stderr, "Tunnel closed: %v. Fresh login %d/%d in %s; new MFA may be required.\n", err, completed+1, attempts, delay)
		if err := wait(ctx, delay); err != nil {
			return err
		}
	}
}

func waitReconnect(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

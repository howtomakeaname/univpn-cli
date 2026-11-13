package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/howtomakeaname/univpn-cli/internal/config"
	"github.com/howtomakeaname/univpn-cli/internal/netstack"
	"github.com/howtomakeaname/univpn-cli/internal/proxy"
	"github.com/howtomakeaname/univpn-cli/internal/vpn"
	"golang.org/x/term"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "uvpn:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: uvpn <connect|probe|inspect-cert|version> -config FILE")
	}
	command := os.Args[1]
	if command == "dial" {
		return dialProxy(os.Args[2:])
	}
	if command == "version" {
		fmt.Println("uvpn 0.1.0 experimental (UniVPN v1 / IPv4 / TLS)")
		return nil
	}
	if command != "connect" && command != "probe" && command != "inspect-cert" {
		return errors.New("unknown command; use connect, probe, inspect-cert or version")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	file := fs.String("config", "uvpn.local.json", "JSON configuration")
	passwordStdin := fs.Bool("password-stdin", false, "read VPN password from stdin (one line)")
	otpStdin := fs.Bool("otp-stdin", false, "read requested verification code from stdin (one line)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	c, err := config.Load(*file)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if command == "inspect-cert" {
		return inspect(ctx, c)
	}
	if command == "probe" {
		pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		conn, err := vpn.DialTLS(pctx, c.TLS())
		if err != nil {
			return err
		}
		defer conn.Close()
		if err = vpn.Hello(conn, c.Domain); err != nil {
			return err
		}
		fmt.Println("TLS identity verified; UniVPN v1 FirstConnect accepted. No credentials sent.")
		return nil
	}
	// Reserve the port before authenticating, avoiding an unnecessary MFA request.
	l, err := proxy.Listen(c.Listen)
	if err != nil {
		return err
	}
	defer l.Close()
	input := bufio.NewReader(os.Stdin)
	var password []byte
	if *passwordStdin {
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
	s, err := vpn.Login(ctx, vpn.Options{TLS: c.TLS(), Domain: c.Domain, Username: c.Username, Password: password, OTP: func(ctx context.Context) ([]byte, error) {
		fmt.Fprintln(os.Stderr, "Gateway requires the SMS/email verification code.")
		return secret(ctx, "Verification code: ", input, *otpStdin)
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

func readLine(r *bufio.Reader) ([]byte, error) {
	b, err := r.ReadSlice('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(b) > 0) {
		return nil, err
	}
	b = append([]byte(nil), b...)
	b = []byte(strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"))
	if len(b) > 128 {
		return nil, errors.New("secret input too long")
	}
	return b, nil
}

func secret(ctx context.Context, prompt string, r *bufio.Reader, stdin bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	// Restore echo on cancellation even if a terminal read is still blocked.
	if !stdin && term.IsTerminal(int(os.Stdin.Fd())) {
		state, err := term.GetState(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		defer term.Restore(int(os.Stdin.Fd()), state)
	}
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result)
	go func() {
		var b []byte
		var err error
		if stdin {
			b, err = readLine(r)
		} else if term.IsTerminal(int(os.Stdin.Fd())) {
			b, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
		} else {
			err = errors.New("interactive terminal required; use password_file / explicit stdin flags for automation")
		}
		select {
		case done <- result{b, err}:
		case <-ctx.Done():
			clear(b)
		}
	}()
	select {
	case res := <-done:
		return res.b, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// inspect never sends application data, secrets, or an authentication request.
// Its unverified fingerprint is an observation, never automatically trusted.
func inspect(ctx context.Context, c config.Config) error {
	host, _, _ := net.SplitHostPort(c.Gateway)
	name := c.ServerName
	if name == "" {
		name = host
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, InsecureSkipVerify: true}}
	conn, err := d.DialContext(ctx, "tcp", c.Gateway)
	if err != nil {
		return err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("server sent no certificate")
	}
	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	fmt.Println("UNVERIFIED observation. Confirm the CA/fingerprint with the environment provider before trusting it.")
	fmt.Println("Certificate subject:", leaf.Subject.String())
	fmt.Println("Issuer:", leaf.Issuer.String())
	fmt.Println("DNS names:", strings.Join(leaf.DNSNames, ", "))
	fmt.Println("Validity:", leaf.NotBefore.Format(time.RFC3339), "..", leaf.NotAfter.Format(time.RFC3339))
	fmt.Println("cert_sha256:", hex.EncodeToString(sum[:]))
	return nil
}

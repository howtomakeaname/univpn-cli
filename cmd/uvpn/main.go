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
	"github.com/howtomakeaname/univpn-cli/internal/vpn"
	"golang.org/x/term"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "uvpn:", err)
		os.Exit(1)
	}
}

var version = "dev"

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: uvpn <connect|probe|inspect-cert|version> -config FILE")
	}
	command := os.Args[1]
	if command == "help" || command == "-h" || command == "--help" {
		fmt.Println("usage: uvpn <connect|probe|inspect-cert|dial|version> [options]")
		fmt.Println("Run uvpn COMMAND -h for options. connect requires a private JSON config.")
		return nil
	}
	if command == "dial" {
		return dialProxy(os.Args[2:])
	}
	if command == "version" {
		fmt.Printf("uvpn %s experimental (UniVPN v1 / IPv4 / TLS)\n", version)
		return nil
	}
	if command != "connect" && command != "probe" && command != "inspect-cert" {
		return errors.New("unknown command; use connect, probe, inspect-cert or version")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	file := fs.String("config", "uvpn.local.json", "JSON configuration")
	passwordStdin := fs.Bool("password-stdin", false, "read VPN password from stdin (one line)")
	otpStdin := fs.Bool("otp-stdin", false, "read requested verification code from stdin (one line)")
	reconnectAttempts := fs.Int("reconnect-attempts", 0, "maximum fresh logins after tunnel interruption (0..10; default disabled)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *reconnectAttempts < 0 || *reconnectAttempts > 10 {
		return errors.New("reconnect-attempts must be 0..10")
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
	input := bufio.NewReader(os.Stdin)
	return connectLoop(ctx, *reconnectAttempts, func() error {
		return connectOnce(ctx, c, input, *passwordStdin, *otpStdin)
	}, waitReconnect)
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

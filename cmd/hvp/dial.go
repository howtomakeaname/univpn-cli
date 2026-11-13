package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// dialProxy connects stdin/stdout through SOCKS5 for use as SSH ProxyCommand.
func dialProxy(args []string) error {
	fs := flag.NewFlagSet("dial", flag.ContinueOnError)
	address := fs.String("proxy", "127.0.0.1:7890", "local SOCKS5 proxy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hvp dial [-proxy 127.0.0.1:7890] host:port")
	}
	host, portText, err := net.SplitHostPort(fs.Arg(0))
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || len(host) == 0 || len(host) > 255 {
		return errors.New("invalid target host:port")
	}
	ph, _, err := net.SplitHostPort(*address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(ph); ip == nil || !ip.IsLoopback() {
		return errors.New("dial proxy must be a numeric loopback address")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", *address)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var greeting [2]byte
	if _, err = io.ReadFull(c, greeting[:]); err != nil {
		return err
	}
	if greeting != [2]byte{5, 0} {
		return errors.New("SOCKS5 authentication negotiation failed")
	}
	packet := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	packet = append(packet, byte(port>>8), byte(port))
	if _, err = c.Write(packet); err != nil {
		return err
	}
	var h [4]byte
	if _, err = io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 5 || h[1] != 0 || h[2] != 0 {
		return errors.New("VPN destination unavailable or denied")
	}
	var n int
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var b [1]byte
		if _, err = io.ReadFull(c, b[:]); err != nil {
			return err
		}
		n = int(b[0])
	default:
		return errors.New("invalid SOCKS5 reply")
	}
	if _, err = io.CopyN(io.Discard, c, int64(n+2)); err != nil {
		return err
	}
	c.SetDeadline(time.Time{})
	go func() {
		io.Copy(c, os.Stdin)
		if tcp, ok := c.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()
	_, err = io.Copy(os.Stdout, c)
	return err
}

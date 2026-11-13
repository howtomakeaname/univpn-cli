// Package proxy serves SOCKS5 TCP/UDP and HTTP proxies on one loopback port.
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DialFunc func(context.Context, string, string) (net.Conn, error)

type Server struct {
	Dial           DialFunc
	MaxConnections int
	IdleTimeout    time.Duration
}

func Listen(address string) (net.Listener, error) {
	h, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(h)
	if err != nil || !ip.IsLoopback() {
		return nil, errors.New("proxy listener must use a numeric loopback address")
	}
	return net.Listen("tcp", address)
}

func (s *Server) Serve(parent context.Context, l net.Listener) error {
	ctx, cancel := context.WithCancel(parent)
	max := s.MaxConnections
	if max == 0 {
		max = 256
	}
	idle := s.IdleTimeout
	if idle == 0 {
		idle = 15 * time.Minute
	}
	sem := make(chan struct{}, max)
	var wg sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	defer func() { cancel(); l.Close(); wg.Wait() }()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		c, err := s.Dial(ctx, n, a)
		if err != nil {
			return nil, err
		}
		return &idleConn{Conn: c, timeout: idle}, nil
	}, DisableKeepAlives: true, ResponseHeaderTimeout: 20 * time.Second, TLSHandshakeTimeout: 15 * time.Second, MaxResponseHeaderBytes: 64 << 10}
	defer transport.CloseIdleConnections()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReaderSize(c, 8192)
			b, e := r.Peek(1)
			if e != nil {
				return
			}
			if b[0] == 5 {
				s.socks(ctx, c, r, idle)
			} else {
				s.http(ctx, c, r, idle, transport)
			}
		}()
	}
}

func (s *Server) dial(ctx context.Context, addr string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return s.Dial(dctx, "tcp", addr)
}

func (s *Server) socks(ctx context.Context, c net.Conn, r *bufio.Reader, idle time.Duration) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}
	noauth := false
	for _, m := range methods {
		if m == 0 {
			noauth = true
		}
	}
	if !noauth {
		c.Write([]byte{5, 255})
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(r, req[:]); err != nil || req[0] != 5 || req[2] != 0 {
		return
	}
	reply := func(code byte) { c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if req[1] != 1 && req[1] != 3 {
		reply(7)
		return
	} // BIND is not supported.
	var host string
	switch req[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(ip).String()
	case 3:
		n, err := r.ReadByte()
		if err != nil || n == 0 {
			return
		}
		b := make([]byte, int(n))
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = string(b)
	default:
		reply(8)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return
	}
	if req[1] == 3 {
		s.udpAssociate(ctx, c, r, host, binary.BigEndian.Uint16(pb[:]), idle)
		return
	}
	remote, err := s.dial(ctx, net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:])))))
	if err != nil {
		reply(2)
		return
	}
	defer remote.Close()
	reply(0)
	c.SetDeadline(time.Time{})
	relay(ctx, c, remote, r, idle)
}

func (s *Server) http(ctx context.Context, c net.Conn, r *bufio.Reader, idle time.Duration, t *http.Transport) {
	// Use an explicit bounded header read, preserving bytes pipelined after CONNECT.
	var header strings.Builder
	for header.Len() < 32<<10 {
		line, err := r.ReadSlice('\n')
		if err != nil {
			return
		}
		header.Write(line)
		if string(line) == "\r\n" {
			break
		}
	}
	if header.Len() >= 32<<10 {
		return
	}
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(header.String())))
	if err != nil {
		return
	}
	fail := func(code int, msg string) { http.Error(&connResponse{c: c}, msg, code) }
	if req.Method == http.MethodConnect {
		if req.ContentLength > 0 || len(req.TransferEncoding) > 0 {
			fail(400, "CONNECT body unsupported")
			return
		}
		if _, _, err := net.SplitHostPort(req.Host); err != nil {
			fail(400, "CONNECT requires host:port")
			return
		}
		remote, err := s.dial(ctx, req.Host)
		if err != nil {
			fail(502, "VPN destination unavailable or denied")
			return
		}
		defer remote.Close()
		if _, err = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		c.SetDeadline(time.Time{})
		relay(ctx, c, remote, r, idle)
		return
	}
	if req.URL.Scheme != "http" || req.URL.Host == "" || req.URL.User != nil {
		fail(400, "absolute http URL required; use CONNECT for HTTPS")
		return
	}
	if req.Header.Get("Upgrade") != "" {
		fail(501, "use CONNECT for upgraded connections")
		return
	}
	// Reparse together with the body only after deciding this is ordinary HTTP.
	req, err = http.ReadRequest(bufio.NewReader(io.MultiReader(strings.NewReader(header.String()), r)))
	if err != nil {
		return
	}
	req.RequestURI = ""
	req.Host = req.URL.Host
	req.Close = true
	req = req.WithContext(ctx)
	stripHop(req.Header)
	// CONNECT parsing above must never read ahead; for HTTP, reuse the actual
	// body reader generated by ReadRequest (including any prefetched bytes).
	c.SetDeadline(time.Time{})
	c.SetReadDeadline(time.Now().Add(idle))
	resp, err := t.RoundTrip(req)
	if err != nil {
		fail(502, "VPN destination unavailable or denied")
		return
	}
	defer resp.Body.Close()
	stripHop(resp.Header)
	resp.Close = true
	resp.Write(&idleConn{Conn: c, timeout: idle})
}

func stripHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(name)
	}
}

// connResponse writes a bounded, fixed error without reflecting a target or headers.
type connResponse struct {
	c      net.Conn
	header http.Header
	wrote  bool
}

func (w *connResponse) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *connResponse) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	io.WriteString(w.c, "HTTP/1.1 "+strconv.Itoa(code)+" "+http.StatusText(code)+"\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n")
}
func (w *connResponse) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	return w.c.Write(b)
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}
func (c *idleConn) Write(b []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(b)
}

type readWithDeadline struct {
	r       io.Reader
	c       net.Conn
	timeout time.Duration
}

func (r *readWithDeadline) Read(b []byte) (int, error) {
	r.c.SetReadDeadline(time.Now().Add(r.timeout))
	return r.r.Read(b)
}

func relay(ctx context.Context, local, remote net.Conn, r io.Reader, idle time.Duration) {
	stop := context.AfterFunc(ctx, func() { local.Close(); remote.Close() })
	defer stop()
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn, reader io.Reader) {
		_, err := io.Copy(&idleConn{Conn: dst, timeout: idle}, &readWithDeadline{r: reader, c: src, timeout: idle})
		if err != nil {
			local.Close()
			remote.Close()
		} else if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go copyOne(remote, local, r)
	go copyOne(local, remote, remote)
	<-done
	<-done
}

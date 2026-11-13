package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func startProxy(t *testing.T, dial DialFunc) string {
	t.Helper()
	l, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{Dial: dial}).Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("proxy failed to stop")
		}
	})
	return l.Addr().String()
}

func echoDial(_ context.Context, _, _ string) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { defer b.Close(); io.Copy(b, b) }()
	return a, nil
}

func TestConnectPreservesPipelinedBytes(t *testing.T) {
	addr := startProxy(t, echoDial)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("CONNECT atlas.internal:22 HTTP/1.1\r\nHost: atlas.internal:22\r\n\r\nSSH-early-payload"))
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil || !strings.Contains(line, " 200 ") {
		t.Fatal(line, err)
	}
	if _, err = r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("SSH-early-payload"))
	if _, err = io.ReadFull(r, b); err != nil || string(b) != "SSH-early-payload" {
		t.Fatal(string(b), err)
	}
}

func TestSOCKS5AndUnsupportedCommands(t *testing.T) {
	addr := startProxy(t, echoDial)
	for _, cmd := range []byte{1, 2} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte{5, 1, 0})
		b := make([]byte, 2)
		io.ReadFull(c, b)
		if !bytes.Equal(b, []byte{5, 0}) {
			t.Fatal("greeting", b)
		}
		c.Write([]byte{5, cmd, 0, 1, 10, 44, 0, 2, 0, 22})
		b = make([]byte, 10)
		io.ReadFull(c, b)
		if cmd == 2 {
			if b[1] != 7 {
				t.Fatal("BIND was accepted")
			}
		} else {
			if b[1] != 0 {
				t.Fatal("CONNECT rejected")
			}
			c.Write([]byte("payload"))
			b = make([]byte, 7)
			_, err = io.ReadFull(c, b)
			if err != nil || string(b) != "payload" {
				t.Fatal(string(b), err)
			}
		}
		c.Close()
	}
}

func TestHTTPBodyAndHeaderFiltering(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
			t.Error("hop-by-hop header leaked")
		}
		io.Copy(w, r.Body)
	}))
	defer origin.Close()
	addr := startProxy(t, (&net.Dialer{}).DialContext)
	u, _ := url.Parse("http://" + addr)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	data := strings.Repeat("upload payload ", 1024)
	req, _ := http.NewRequest("POST", origin.URL, strings.NewReader(data))
	req.Header.Set("Proxy-Authorization", "sensitive")
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "remove me")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || string(b) != data {
		t.Fatal("body mismatch", len(b), err)
	}
}

func TestProxyDenialAndLoopback(t *testing.T) {
	if l, err := Listen("0.0.0.0:0"); err == nil {
		l.Close()
		t.Fatal("accepted public listener")
	}
	addr := startProxy(t, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("denied") })
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprint(c, "CONNECT forbidden.internal:443 HTTP/1.1\r\nHost: forbidden.internal:443\r\n\r\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(line, " 502 ") {
		t.Fatal(line, err)
	}
}

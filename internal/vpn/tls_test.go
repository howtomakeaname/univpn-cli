package vpn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTLSVerification(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	defer s.Close()
	sum := sha256.Sum256(s.Certificate().Raw)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		o    TLSOptions
		ok   bool
	}{
		{"system rejects unknown CA", TLSOptions{}, false},
		{"private CA", TLSOptions{CAFile: ca}, true},
		{"correct explicit pin", TLSOptions{PinSHA256: hex.EncodeToString(sum[:])}, true},
		{"wrong pin", TLSOptions{PinSHA256: strings.Repeat("0", 64)}, false},
		{"wrong hostname", TLSOptions{CAFile: ca, ServerName: "wrong.invalid"}, false},
		{"short pin", TLSOptions{PinSHA256: "abcd"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.o
			o.Gateway = s.Listener.Addr().String()
			c, err := DialTLS(context.Background(), o)
			if c != nil {
				c.Close()
			}
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
		})
	}
}

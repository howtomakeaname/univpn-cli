package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivatePasswordPreservesSpaces(t *testing.T) {
	p := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(p, []byte(" p&+% \r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := ReadPassword(p)
	if err != nil || string(b) != " p&+% " {
		t.Fatal("password changed", err)
	}
	os.Chmod(p, 0644)
	if _, err = ReadPassword(p); err == nil {
		t.Fatal("accepted world-readable password")
	}
}

func TestConfigValidation(t *testing.T) {
	base := `{"gateway":"vpn.example.com:443","listen":"127.0.0.1:7890","allow_cidrs":["10.44.0.2/32"]}`
	for _, tc := range []struct {
		name, text string
		ok         bool
	}{
		{"valid", base, true},
		{"public listener", strings.Replace(base, "127.0.0.1", "0.0.0.0", 1), false},
		{"missing policy", strings.Replace(base, `["10.44.0.2/32"]`, `[]`, 1), false},
		{"unknown key", strings.Replace(base, `"gateway"`, `"password":"unsafe","gateway"`, 1), false},
		{"second object", base + `{}`, false},
		{"bad port", strings.Replace(base, ":443", ":65536", 1), false},
		{"truncated pin", strings.Replace(base, `"gateway"`, `"cert_sha256":"1234","gateway"`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.json")
			os.WriteFile(p, []byte(tc.text), 0600)
			_, err := Load(p)
			if (err == nil) != tc.ok {
				t.Fatalf("expected ok=%v, err=%v", tc.ok, err)
			}
		})
	}
}

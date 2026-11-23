package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrivatePasswordPreservesSpaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions; Windows uses prompt/stdin")
	}
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
		{"local session limit", strings.Replace(base, `"gateway"`, `"session_max_seconds":3600,"gateway"`, 1), true},
		{"short session limit", strings.Replace(base, `"gateway"`, `"session_max_seconds":59,"gateway"`, 1), false},
		{"negative session limit", strings.Replace(base, `"gateway"`, `"session_max_seconds":-1,"gateway"`, 1), false},
		{"excessive session limit", strings.Replace(base, `"gateway"`, `"session_max_seconds":604801,"gateway"`, 1), false},
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

func TestConfigMACValidation(t *testing.T) {
	base := `{"gateway":"vpn.example.com:443","listen":"127.0.0.1:7890","allow_cidrs":["10.44.0.2/32"]}`
	for _, tc := range []struct {
		name, raw, want string
		ok              bool
	}{
		{"omitted", "", "", true},
		{"hyphen octets", "02-11-22-33-44-55", "0211-2233-4455", true},
		{"colon octets", "02:11:22:33:44:55", "0211-2233-4455", true},
		{"hyphen groups", "0211-2233-4455", "0211-2233-4455", true},
		{"dot groups", "0211.2233.4455", "0211-2233-4455", true},
		{"mixed case", "02-aB-cD-33-44-eF", "02AB-CD33-44EF", true},
		{"global unicast", "00:11:22:33:44:55", "0011-2233-4455", true},
		{"too short", "02:11:22:33:44", "", false},
		{"too long", "02:11:22:33:44:55:66:77", "", false},
		{"non-hex", "02:11:22:33:44:gg", "", false},
		{"mixed separators", "02:11-22:33:44:55", "", false},
		{"mixed group separators", "0211-2233.4455", "", false},
		{"leading whitespace", " 02:11:22:33:44:55", "", false},
		{"trailing whitespace", "02:11:22:33:44:55 ", "", false},
		{"all-zero", "00:00:00:00:00:00", "", false},
		{"broadcast", "ff:ff:ff:ff:ff:ff", "", false},
		{"multicast", "01:00:5e:00:00:01", "", false},
		{"nul byte", `02:11:22:33:44:55\u0000`, "", false},
		{"control char", `02:11:22:33:44:\n5`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := base
			if tc.raw != "" {
				text = strings.Replace(base, `"gateway"`, `"mac":"`+tc.raw+`","gateway"`, 1)
			}
			p := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(p, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(p)
			if (err == nil) != tc.ok {
				t.Fatalf("mac=%q expected ok=%v, err=%v", tc.raw, tc.ok, err)
			}
			if tc.ok && c.MAC != tc.want {
				t.Fatalf("mac=%q got %q, want %q", tc.raw, c.MAC, tc.want)
			}
		})
	}
}

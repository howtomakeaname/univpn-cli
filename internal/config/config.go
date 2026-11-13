package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/howtomakeaname/univpn-cli/internal/netstack"
	"github.com/howtomakeaname/univpn-cli/internal/vpn"
	"github.com/howtomakeaname/univpn-cli/internal/wire"
)

type Config struct {
	Gateway        string            `json:"gateway"`
	Domain         string            `json:"domain,omitempty"`
	Username       string            `json:"username,omitempty"`
	PasswordFile   string            `json:"password_file,omitempty"`
	ServerName     string            `json:"server_name,omitempty"`
	CAFile         string            `json:"ca_file,omitempty"`
	CertSHA256     string            `json:"cert_sha256,omitempty"`
	Listen         string            `json:"listen"`
	AllowCIDRs     []string          `json:"allow_cidrs"`
	Hosts          map[string]string `json:"hosts,omitempty"`
	DNS            []string          `json:"dns,omitempty"`
	MTU            int               `json:"mtu,omitempty"`
	MaxConnections int               `json:"max_connections,omitempty"`
}

func Load(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 64<<10))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("configuration must contain one JSON object")
	}
	base := filepath.Dir(path)
	for _, p := range []*string{&c.PasswordFile, &c.CAFile} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:7890"
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 256
	}
	host, port, err := net.SplitHostPort(c.Gateway)
	if err != nil || host == "" {
		return c, errors.New("gateway must be host:port")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return c, errors.New("invalid gateway port")
	}
	if c.Domain == "" {
		c.Domain = host
	}
	if _, err = wire.Domain(c.Domain); err != nil {
		return c, err
	}
	host, _, err = net.SplitHostPort(c.Listen)
	ip, e := netip.ParseAddr(host)
	if err != nil || e != nil || !ip.IsLoopback() {
		return c, errors.New("listen must be a numeric loopback address:port")
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return c, errors.New("mtu must be 576..9000")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 4096 {
		return c, errors.New("max_connections must be 1..4096")
	}
	if _, err = c.Policy(nil); err != nil {
		return c, err
	}
	if _, err = c.TLS().Config(); err != nil {
		return c, err
	}
	return c, nil
}

func (c Config) TLS() vpn.TLSOptions {
	return vpn.TLSOptions{Gateway: c.Gateway, ServerName: c.ServerName, CAFile: c.CAFile, PinSHA256: c.CertSHA256}
}

func (c Config) Policy(n *netstack.Network) (*netstack.Policy, error) {
	p := &netstack.Policy{Net: n, Hosts: make(map[string]netip.Addr)}
	if len(c.AllowCIDRs) == 0 {
		return nil, errors.New("allow_cidrs must explicitly list permitted VPN destinations")
	}
	for _, s := range c.AllowCIDRs {
		prefix, err := netip.ParsePrefix(s)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("invalid IPv4 allow_cidrs entry %q", s)
		}
		p.Allow = append(p.Allow, prefix.Masked())
	}
	for name, s := range c.Hosts {
		ip, err := netip.ParseAddr(s)
		if err != nil || !p.Allowed(ip) {
			return nil, errors.New("hosts entry must point to an allowed IPv4 address")
		}
		if name == "" || strings.ContainsAny(name, "\x00:/ ") {
			return nil, errors.New("invalid static hostname")
		}
		p.Hosts[strings.ToLower(strings.TrimSuffix(name, "."))] = ip
	}
	for _, s := range c.DNS {
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("dns must contain explicit unicast IPv4 addresses")
		}
		p.DNS = append(p.DNS, ip)
	}
	return p, nil
}

func ReadPassword(path string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("password_file requires Unix permission checks; on Windows use the interactive prompt or --password-stdin")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("password_file must be a regular file with mode 0600 or stricter")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nil, err
	}
	// Strip one line ending only. Spaces and punctuation are part of the secret.
	b = bytesTrimEOL(b)
	if len(b) == 0 || len(b) > 128 {
		clear(b)
		return nil, errors.New("password_file must contain 1..128 bytes")
	}
	return b, nil
}

func bytesTrimEOL(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
		if len(b) > 0 && b[len(b)-1] == '\r' {
			b = b[:len(b)-1]
		}
	}
	return b
}

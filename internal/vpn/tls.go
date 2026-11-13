package vpn

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"time"
)

type TLSOptions struct {
	Gateway    string
	ServerName string
	CAFile     string
	// PinSHA256 is a full SHA256 of the DER leaf certificate, from a trusted source.
	PinSHA256 string
}

func (o TLSOptions) Config() (*tls.Config, error) {
	host, _, err := net.SplitHostPort(o.Gateway)
	if err != nil {
		return nil, errors.New("gateway must be host:port")
	}
	name := o.ServerName
	if name == "" {
		name = host
	}
	c := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file has no certificates")
		}
		c.RootCAs = pool
	}
	if o.PinSHA256 != "" {
		pin, err := hex.DecodeString(o.PinSHA256)
		if err != nil || len(pin) != sha256.Size {
			return nil, errors.New("cert_sha256 must be exactly 64 hexadecimal characters")
		}
		// Explicit pin replaces CA/name trust; VerifyConnection still checks identity
		// and validity, on BOTH channels. There is no insecure login option.
		c.InsecureSkipVerify = true
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			leaf := cs.PeerCertificates[0]
			sum := sha256.Sum256(leaf.Raw)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errors.New("VPN certificate pin mismatch")
			}
			if time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
				return errors.New("pinned VPN certificate is expired or not yet valid")
			}
			return nil
		}
	}
	return c, nil
}

func DialTLS(ctx context.Context, o TLSOptions) (*tls.Conn, error) {
	c, err := o.Config()
	if err != nil {
		return nil, err
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}, Config: c}
	conn, err := d.DialContext(ctx, "tcp", o.Gateway)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

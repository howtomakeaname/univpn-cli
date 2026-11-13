package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/howtomakeaname/univpn-cli/internal/config"
	"github.com/howtomakeaname/univpn-cli/internal/vpn"
	"github.com/howtomakeaname/univpn-cli/internal/wire"
)

// The gateway requests fresh authentication, then revokes the replacement. Each
// attempt must verify TLS, send a different code, bind a new token, and close its
// listener, live UDP association, and both old channels before another login starts.
func TestTLSReconnectRequiresFreshMFAAndStopsOnRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsConfig := certServer.TLS.Clone()
	pin := sha256.Sum256(certServer.Certificate().Raw)
	certServer.Close()
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stopGateway := context.AfterFunc(ctx, func() { l.Close() })
	defer stopGateway()
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddress := port.Addr().String()
	port.Close()

	gatewayDone := make(chan error, 1)
	go func() {
		var oldUDP []*reconnectUDPClient
		defer func() {
			for _, old := range oldUDP {
				old.close()
			}
		}()
		for index, code := range []string{"111111", "222222"} {
			if err := func() error {
				ctl, err := l.Accept()
				if err != nil {
					return err
				}
				defer ctl.Close()
				ctl.SetDeadline(time.Now().Add(5 * time.Second))
				hello := make([]byte, 340)
				if _, err := io.ReadFull(ctl, hello); err != nil {
					return err
				}
				if err := wire.Write(ctl, wire.FirstConnect, make([]byte, 4)); err != nil {
					return err
				}
				p, err := wire.Expect(ctl, wire.Auth)
				if err != nil {
					return err
				}
				if len(p) < 260 {
					return errors.New("short authentication request")
				}
				fields, err := wire.ParseTLVs(p[260:])
				if err != nil || len(fields) != 3 || string(fields[0].Value) != "test-user\x00" || string(fields[1].Value) != "test-password\x00" {
					return errors.New("fresh password authentication missing")
				}
				if err := wire.Write(ctl, wire.Auth, wire.AppendTLV([]byte{0, 0, 0, 1, 0, 0, 0, 0}, 2, []byte{1})); err != nil {
					return err
				}
				p, err = wire.Expect(ctl, wire.SecondAuth)
				if err != nil {
					return err
				}
				if len(p) != 33 || p[0] != 1 || string(p[1:7]) != code {
					return errors.New("second factor reused or missing")
				}
				token := bytes.Repeat([]byte{byte(index + 1)}, 32)
				if err := wire.Write(ctl, wire.Auth, wire.AppendTLV(make([]byte, 8), 3, token)); err != nil {
					return err
				}
				p, err = wire.Expect(ctl, wire.RequestVIP)
				if err != nil || !bytes.Equal(p, token) {
					return fmt.Errorf("reused VIP token: %v", err)
				}
				if err := wire.Write(ctl, wire.RequestVIP, wire.AppendTLV(make([]byte, 4), 1, []byte{10, 44, 0, 1, 0})); err != nil {
					return err
				}
				data, err := l.Accept()
				if err != nil {
					return err
				}
				defer data.Close()
				data.SetDeadline(time.Now().Add(5 * time.Second))
				p, err = wire.Expect(data, wire.DataConnect)
				if err != nil || !bytes.Equal(p, token) {
					return fmt.Errorf("reused data token: %v", err)
				}
				if err := wire.Write(data, wire.DataConnect, []byte{0}); err != nil {
					return err
				}
				udp, err := openReconnectUDP(proxyAddress)
				if err != nil {
					return err
				}
				oldUDP = append(oldUDP, udp)
				message := []byte(fmt.Sprintf("round-%d", index))
				if err := udp.send(message); err != nil {
					return err
				}
				packet, err := wire.Expect(data, wire.DataPacket)
				if err != nil {
					return err
				}
				reply, err := reconnectUDPReply(packet, message)
				if err != nil {
					return err
				}
				if err := wire.Write(data, wire.DataPacket, reply); err != nil {
					return err
				}
				if err := udp.receive(message); err != nil {
					return err
				}
				// The replacement session has a live UDP flow before probing the old
				// relay. A stale client must neither reach this tunnel nor receive a reply.
				if index > 0 {
					old := oldUDP[0]
					if err := old.send([]byte("stale-session")); err != nil {
						return err
					}
					data.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					if _, err := wire.Read(data); err == nil {
						return errors.New("old UDP relay forwarded into the replacement tunnel")
					} else {
						var timeout net.Error
						if !errors.As(err, &timeout) || !timeout.Timeout() {
							return fmt.Errorf("checking stale relay: %w", err)
						}
					}
					data.SetReadDeadline(time.Now().Add(5 * time.Second))
					old.client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					if _, _, err := old.client.ReadFromUDP(make([]byte, 100)); err == nil {
						return errors.New("old UDP client received data after reconnection")
					}
				}
				command := byte(wire.SecondAuth)
				if index == 1 {
					command = 0x32
				}
				if err := wire.Write(ctl, command, nil); err != nil {
					return err
				}
				for _, c := range []net.Conn{ctl, data} {
					if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
						return fmt.Errorf("old channel remained open: %v", err)
					}
				}
				udp.control.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := udp.control.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					return fmt.Errorf("UDP control survived session shutdown: %v", err)
				}
				deadline := time.Now().Add(time.Second)
				for {
					probe, err := net.ListenUDP("udp4", udp.relay)
					if err == nil {
						probe.Close()
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("UDP relay survived session shutdown: %w", err)
					}
					time.Sleep(5 * time.Millisecond)
				}
				return nil
			}(); err != nil {
				gatewayDone <- err
				return
			}
		}
		gatewayDone <- nil
	}()
	c := config.Config{Gateway: l.Addr().String(), Domain: "vpn.example.com", Username: "test-user", CertSHA256: hex.EncodeToString(pin[:]), Listen: proxyAddress, AllowCIDRs: []string{"10.44.0.2/32"}, MTU: 1400, MaxConnections: 8}
	input := bufio.NewReader(strings.NewReader("test-password\n111111\ntest-password\n222222\n"))
	attempts := 0
	err = connectLoop(ctx, 3, func() error { attempts++; return connectOnce(ctx, c, input, true, true) }, func(context.Context, time.Duration) error {
		conn, err := net.DialTimeout("tcp", proxyAddress, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return errors.New("old listener remained open during backoff")
		}
		return nil
	})
	if !errors.Is(err, vpn.ErrSessionRevoked) || attempts != 2 {
		t.Fatalf("attempts=%d error=%v", attempts, err)
	}
	if err := <-gatewayDone; err != nil {
		t.Fatal(err)
	}
}

// reconnectUDPClient deliberately survives the old TCP control closure so that
// the test can try to inject from its original local source after a new login.
type reconnectUDPClient struct {
	control net.Conn
	client  *net.UDPConn
	relay   *net.UDPAddr
}

func (u *reconnectUDPClient) close() { u.control.Close(); u.client.Close() }

func openReconnectUDP(proxyAddress string) (_ *reconnectUDPClient, err error) {
	control, err := net.DialTimeout("tcp", proxyAddress, time.Second)
	if err != nil {
		return nil, err
	}
	var client *net.UDPConn
	defer func() {
		if err != nil {
			control.Close()
			if client != nil {
				client.Close()
			}
		}
	}()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = control.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var greeting [2]byte
	if _, err = io.ReadFull(control, greeting[:]); err != nil {
		return nil, err
	}
	if greeting != [2]byte{5, 0} {
		return nil, errors.New("UDP client greeting rejected")
	}
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var reply [10]byte
	if _, err = io.ReadFull(control, reply[:]); err != nil {
		return nil, err
	}
	if reply[1] != 0 || reply[3] != 1 {
		return nil, errors.New("UDP association rejected")
	}
	client, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	control.SetDeadline(time.Time{})
	return &reconnectUDPClient{control: control, client: client, relay: &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))}}, nil
}

func (u *reconnectUDPClient) send(payload []byte) error {
	packet := append([]byte{0, 0, 0, 1, 10, 44, 0, 2, 0x14, 0xe9}, payload...)
	_, err := u.client.WriteToUDP(packet, u.relay)
	return err
}

func (u *reconnectUDPClient) receive(payload []byte) error {
	u.client.SetReadDeadline(time.Now().Add(time.Second))
	var reply [100]byte
	n, _, err := u.client.ReadFromUDP(reply[:])
	if err != nil {
		return err
	}
	if n < 10 || !bytes.Equal(reply[:10], []byte{0, 0, 0, 1, 10, 44, 0, 2, 0x14, 0xe9}) || !bytes.Equal(reply[10:n], payload) {
		return errors.New("UDP round trip mismatch")
	}
	return nil
}

// The simulator echoes one small unfragmented IPv4 UDP packet. Zero UDP checksum
// is valid for IPv4; the IP header checksum must be recomputed after swapping IPs.
func reconnectUDPReply(frame, message []byte) ([]byte, error) {
	if len(frame) < 36 {
		return nil, errors.New("short UDP tunnel frame")
	}
	packet := append([]byte(nil), frame...)
	ip := packet[8:]
	header := int(ip[0]&15) * 4
	if ip[0]>>4 != 4 || header < 20 || len(ip) < header+8 || ip[9] != 17 || !bytes.Equal(ip[16:20], []byte{10, 44, 0, 2}) || binary.BigEndian.Uint16(ip[header+2:]) != 5353 || !bytes.Equal(ip[header+8:], message) {
		return nil, errors.New("wrong UDP tunnel packet")
	}
	a := [4]byte(ip[12:16])
	copy(ip[12:16], ip[16:20])
	copy(ip[16:20], a[:])
	port := [2]byte(ip[header:])
	copy(ip[header:header+2], ip[header+2:header+4])
	copy(ip[header+2:header+4], port[:])
	clear(ip[header+6 : header+8])
	clear(ip[10:12])
	var sum uint32
	for offset := 0; offset < header; offset += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[offset:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))
	return packet, nil
}

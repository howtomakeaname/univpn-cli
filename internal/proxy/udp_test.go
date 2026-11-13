package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func startUDPAssociation(t *testing.T, proxyAddress string, sourcePort uint16) (net.Conn, *net.UDPAddr) {
	t.Helper()
	control, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	control.SetDeadline(time.Now().Add(3 * time.Second))
	control.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err := io.ReadFull(control, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("greeting", greeting, err)
	}
	request := []byte{5, 3, 0, 1, 0, 0, 0, 0}
	request = binary.BigEndian.AppendUint16(request, sourcePort)
	control.Write(request)
	var response [10]byte
	if _, err := io.ReadFull(control, response[:]); err != nil || response[1] != 0 || response[3] != 1 {
		t.Fatal("UDP ASSOCIATE", response, err)
	}
	control.SetDeadline(time.Time{})
	return control, &net.UDPAddr{IP: net.IP(response[4:8]), Port: int(binary.BigEndian.Uint16(response[8:]))}
}

func startUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	if err := setUDPBuffers(echo); err != nil {
		t.Fatal(err)
	}
	go func() {
		var buf [65535]byte
		for {
			n, from, e := echo.ReadFromUDP(buf[:])
			if e != nil {
				return
			}
			echo.WriteToUDP(buf[:n], from)
		}
	}()
	return echo
}

func dialUDPEcho(ctx context.Context, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	if err := setUDPBuffers(c.(*net.UDPConn)); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func TestUDPAssociateDatagramsAndControlLifetime(t *testing.T) {
	echo := startUDPEcho(t)
	var dialed atomic.Int32
	proxyAddress := startProxy(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "dns.internal:53" {
			t.Errorf("unexpected dial %q %q", network, address)
		}
		dialed.Add(1)
		return dialUDPEcho(ctx, echo.LocalAddr().String())
	})
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := setUDPBuffers(client); err != nil {
		t.Fatal(err)
	}
	control, relay := startUDPAssociation(t, proxyAddress, uint16(client.LocalAddr().(*net.UDPAddr).Port))
	header := append([]byte{0, 0, 0, 3, 12}, "dns.internal"...)
	header = append(header, 0, 53)
	for _, size := range []int{0, 1, 8192, 60000} {
		payload := bytes.Repeat([]byte{byte(size + 1)}, size)
		client.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := client.WriteToUDP(append(append([]byte(nil), header...), payload...), relay); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, _, e := client.ReadFromUDP(buf)
		_, response, parseErr := parseUDPDatagram(buf[:n])
		if e != nil || parseErr != nil || !bytes.Equal(response, payload) {
			t.Fatal("datagram mismatch", size, n, e, parseErr)
		}
	}
	if dialed.Load() != 1 {
		t.Fatal("same destination did not reuse connected UDP endpoint", dialed.Load())
	}
	// Another local UDP socket must not reuse a live association.
	intruder, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer intruder.Close()
	intruder.SetDeadline(time.Now().Add(100 * time.Millisecond))
	intruder.WriteToUDP(append(header, 'x'), relay)
	var buf [100]byte
	if _, _, err := intruder.ReadFromUDP(buf[:]); err == nil {
		t.Fatal("datagram from another source port was relayed")
	}
	control.Close()
	// Poll for bounded cleanup after control closure: the UDP port must become
	// available again instead of surviving as an orphaned relay.
	deadline := time.Now().Add(2 * time.Second)
	for {
		probe, err := net.ListenUDP("udp4", relay)
		if err == nil {
			probe.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("UDP relay survived TCP control closure")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A zero-port request learns its source from the first valid datagram. Once
// learned, a different local socket must neither inject into an existing flow
// nor open another destination through that association.
func TestUDPZeroPortAssociationPinsFirstSource(t *testing.T) {
	echo := startUDPEcho(t)
	var dialed atomic.Int32
	proxyAddress := startProxy(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Add(1)
		return dialUDPEcho(ctx, echo.LocalAddr().String())
	})
	_, relay := startUDPAssociation(t, proxyAddress, 0)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	intruder, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer intruder.Close()
	send := func(c *net.UDPConn, port uint16, payload string) {
		t.Helper()
		packet := binary.BigEndian.AppendUint16([]byte{0, 0, 0, 1, 10, 44, 0, 2}, port)
		packet = append(packet, payload...)
		if _, err := c.WriteToUDP(packet, relay); err != nil {
			t.Fatal(err)
		}
	}
	receive := func(want string) {
		t.Helper()
		client.SetReadDeadline(time.Now().Add(time.Second))
		var packet [100]byte
		n, _, err := client.ReadFromUDP(packet[:])
		_, payload, parseErr := parseUDPDatagram(packet[:n])
		if err != nil || parseErr != nil || string(payload) != want {
			t.Fatalf("source binding response=%q read=%v parse=%v", payload, err, parseErr)
		}
	}
	send(client, 53, "bind-first-source")
	receive("bind-first-source")
	send(intruder, 53, "inject-existing-flow")
	send(intruder, 54, "inject-new-flow")
	for _, c := range []*net.UDPConn{client, intruder} {
		c.SetReadDeadline(time.Now().Add(75 * time.Millisecond))
		if _, _, err := c.ReadFromUDP(make([]byte, 100)); err == nil {
			t.Fatal("another source port injected a UDP packet")
		} else {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatal(err)
			}
		}
	}
	send(client, 53, "original-source-still-works")
	receive("original-source-still-works")
	if dialed.Load() != 1 {
		t.Fatalf("untrusted source opened another UDP flow: %d", dialed.Load())
	}
}

func TestUDPAssociationIdleCountsOnlyValidClientPackets(t *testing.T) {
	for _, traffic := range []string{"other-source", "malformed", "valid-client"} {
		t.Run(traffic, func(t *testing.T) {
			t.Parallel()
			const idle = 400 * time.Millisecond
			echo := startUDPEcho(t)
			listener, err := Listen("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			server := &Server{IdleTimeout: idle, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialUDPEcho(ctx, echo.LocalAddr().String())
			}}
			go func() { done <- server.Serve(ctx, listener) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("idle UDP server failed to stop")
				}
			})
			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			control, relay := startUDPAssociation(t, listener.Addr().String(), uint16(client.LocalAddr().(*net.UDPAddr).Port))
			packet := []byte{0, 0, 0, 1, 10, 44, 0, 2, 0, 53, 'x'}
			exchange := func() {
				t.Helper()
				client.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := client.WriteToUDP(packet, relay); err != nil {
					t.Fatal(err)
				}
				var response [100]byte
				n, _, err := client.ReadFromUDP(response[:])
				if err != nil || n < 10 || !bytes.Equal(response[10:n], []byte{'x'}) {
					t.Fatalf("valid client datagram failed: n=%d error=%v", n, err)
				}
			}
			exchange()
			closed := make(chan error, 1)
			control.SetReadDeadline(time.Now().Add(3 * time.Second))
			go func() { _, err := control.Read(make([]byte, 1)); closed <- err }()
			if traffic == "valid-client" {
				// Keep exchanging beyond the initial deadline. Every valid packet must
				// extend the association before it can expire from client inactivity.
				for range 6 {
					timer := time.NewTimer(idle / 4)
					select {
					case err := <-closed:
						timer.Stop()
						t.Fatalf("active UDP association expired: %v", err)
					case <-timer.C:
					}
					exchange()
				}
			} else {
				sender := client
				noise := append([]byte(nil), packet...)
				if traffic == "other-source" {
					sender, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					defer sender.Close()
				} else {
					noise[2] = 1
				} // Unsupported SOCKS fragment from the correct source.
				stopNoise := make(chan struct{})
				noiseDone := make(chan struct{})
				defer func() { close(stopNoise); <-noiseDone }()
				go func() {
					defer close(noiseDone)
					ticker := time.NewTicker(idle / 10)
					defer ticker.Stop()
					for {
						select {
						case <-stopNoise:
							return
						case <-ticker.C:
							sender.WriteToUDP(noise, relay)
						}
					}
				}()
			}
			select {
			case err := <-closed:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("idle association did not close cleanly: %v", err)
				}
			case <-time.After(3 * idle):
				t.Fatal("discarded traffic extended UDP association idle time")
			}
		})
	}
}

func TestUDPAssociationFlowLimit(t *testing.T) {
	echo := startUDPEcho(t)
	var dialed atomic.Int32
	proxyAddress := startProxy(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Add(1)
		return dialUDPEcho(ctx, echo.LocalAddr().String())
	})
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, relay := startUDPAssociation(t, proxyAddress, 0)
	send := func(port int, expectReply bool) {
		t.Helper()
		packet := []byte{0, 0, 0, 1, 10, 44, 0, 2}
		packet = binary.BigEndian.AppendUint16(packet, uint16(port))
		packet = append(packet, 'x')
		client.SetDeadline(time.Now().Add(time.Second))
		if !expectReply {
			client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
		if _, err := client.WriteToUDP(packet, relay); err != nil {
			t.Fatal(err)
		}
		var reply [32]byte
		_, _, err := client.ReadFromUDP(reply[:])
		if (err == nil) != expectReply {
			t.Fatalf("reply=%t, expected=%t, error=%v", err == nil, expectReply, err)
		}
	}
	for i := range maxUDPFlows {
		send(10000+i, true)
	}
	send(20000, false)
	send(10000, true) // Capacity rejects only the new destination.
	if dialed.Load() != maxUDPFlows {
		t.Fatal("association exceeded flow limit", dialed.Load())
	}
}

func TestUDPDatagramValidation(t *testing.T) {
	for _, packet := range [][]byte{
		nil, {0, 0, 0}, {1, 0, 0, 1, 10, 0, 0, 1, 0, 53},
		{0, 0, 1, 1, 10, 0, 0, 1, 0, 53}, // SOCKS fragments are unsupported.
		{0, 0, 0, 1, 10, 0, 0}, {0, 0, 0, 3, 0, 0, 53},
		{0, 0, 0, 3, 20, 'a', 0, 53}, {0, 0, 0, 4},
		{0, 0, 0, 1, 10, 0, 0, 1, 0, 0},
	} {
		if _, _, err := parseUDPDatagram(packet); err == nil {
			t.Fatal("accepted invalid UDP datagram", packet)
		}
	}
	header, err := udpReplyHeader(net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.44.0.2:53")))
	if err != nil {
		t.Fatal(err)
	}
	if target, payload, err := parseUDPDatagram(append(header, 'x')); err != nil || target != "10.44.0.2:53" || string(payload) != "x" {
		t.Fatal(target, payload, err)
	}
}

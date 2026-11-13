package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
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

func TestUDPAssociateDatagramsAndControlLifetime(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
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
	var dialed atomic.Int32
	proxyAddress := startProxy(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "dns.internal:53" {
			t.Errorf("unexpected dial %q %q", network, address)
		}
		dialed.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, echo.LocalAddr().String())
	})
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	control, relay := startUDPAssociation(t, proxyAddress, uint16(client.LocalAddr().(*net.UDPAddr).Port))
	header := append([]byte{0, 0, 0, 3, 12}, "dns.internal"...)
	header = append(header, 0, 53)
	for _, size := range []int{0, 1, 8192} {
		payload := bytes.Repeat([]byte{byte(size + 1)}, size)
		client.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := client.WriteToUDP(append(append([]byte(nil), header...), payload...), relay); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16384)
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
	// Wait for the server to acknowledge control closure, then its UDP socket
	// must be gone. No deadline-based sleeps are required to join the worker.
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

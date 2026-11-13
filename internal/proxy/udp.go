package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const (
	maxUDPFlows = 32
	udpFlowIdle = 60 * time.Second
)

// parseUDPDatagram implements the unfragmented SOCKS5 UDP wire format. IP
// fragmentation remains the VPN stack's job; SOCKS fragmentation is rejected.
func parseUDPDatagram(packet []byte) (target string, payload []byte, err error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", nil, errors.New("invalid or fragmented SOCKS UDP datagram")
	}
	var host string
	offset := 4
	switch packet[3] {
	case 1:
		if len(packet) < offset+4+2 {
			return "", nil, io.ErrUnexpectedEOF
		}
		host = netip.AddrFrom4([4]byte(packet[offset:])).String()
		offset += 4
	case 3:
		if len(packet) < offset+1 {
			return "", nil, io.ErrUnexpectedEOF
		}
		n := int(packet[offset])
		offset++
		if n == 0 || len(packet) < offset+n+2 {
			return "", nil, io.ErrUnexpectedEOF
		}
		host = string(packet[offset : offset+n])
		offset += n
	default:
		return "", nil, errors.New("unsupported SOCKS UDP address type")
	}
	port := binary.BigEndian.Uint16(packet[offset:])
	if port == 0 {
		return "", nil, errors.New("invalid SOCKS UDP destination port")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), packet[offset+2:], nil
}

func udpReplyHeader(addr net.Addr) ([]byte, error) {
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().Is4() {
		return nil, errors.New("UDP peer is not IPv4")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid UDP peer port")
	}
	header := make([]byte, 10)
	header[3] = 1
	a := ip.Unmap().As4()
	copy(header[4:8], a[:])
	binary.BigEndian.PutUint16(header[8:], uint16(port))
	return header, nil
}

type udpFlow struct {
	conn net.Conn
	done chan struct{}
}

func (s *Server) udpAssociate(parent context.Context, control net.Conn, reader *bufio.Reader, host string, port uint16, idle time.Duration) {
	reject := func(code byte) { control.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	peerHost, _, err := net.SplitHostPort(control.RemoteAddr().String())
	if err != nil {
		return
	}
	peerIP, err := netip.ParseAddr(peerHost)
	if err != nil || !peerIP.IsLoopback() {
		reject(2)
		return
	}
	requestedIP, err := netip.ParseAddr(host)
	if err != nil || (!requestedIP.IsUnspecified() && requestedIP.Unmap() != peerIP.Unmap()) {
		reject(2)
		return
	}
	localHost, _, err := net.SplitHostPort(control.LocalAddr().String())
	if err != nil {
		return
	}
	localIP := net.ParseIP(localHost)
	if localIP == nil || !localIP.IsLoopback() {
		reject(2)
		return
	}
	udpNetwork := "udp4"
	if localIP.To4() == nil {
		udpNetwork = "udp6"
	}
	relay, err := net.ListenUDP(udpNetwork, &net.UDPAddr{IP: localIP})
	if err != nil {
		reject(1)
		return
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(ctx, func() { relay.Close(); control.Close() })
	defer stop()
	flows := make(map[string]*udpFlow)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		relay.Close()
		control.Close()
		for _, flow := range flows {
			flow.conn.Close()
		}
		workers.Wait()
	}()
	// The association belongs to the TCP control connection. Closing that
	// connection closes the relay and every connected VPN UDP endpoint.
	control.SetDeadline(time.Time{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		io.Copy(io.Discard, reader)
		cancel()
	}()
	bound := relay.LocalAddr().(*net.UDPAddr)
	var reply []byte
	if ip4 := bound.IP.To4(); ip4 != nil {
		reply = append([]byte{5, 0, 0, 1}, ip4...)
	} else {
		reply = append([]byte{5, 0, 0, 4}, bound.IP.To16()...)
	}
	reply = binary.BigEndian.AppendUint16(reply, uint16(bound.Port))
	if _, err := control.Write(reply); err != nil {
		return
	}
	if idle > 5*time.Minute {
		idle = 5 * time.Minute
	}
	var source *net.UDPAddr
	if port != 0 {
		source = &net.UDPAddr{IP: net.ParseIP(peerHost), Port: int(port)}
	}
	packet := make([]byte, 65535)
	for {
		relay.SetReadDeadline(time.Now().Add(idle))
		n, from, err := relay.ReadFromUDP(packet)
		if err != nil {
			return
		}
		// Bind a zero-port request to its first well-formed datagram; later
		// packets from any other local socket cannot inject or redirect it.
		if !from.IP.Equal(net.ParseIP(peerHost)) || (source != nil && from.Port != source.Port) {
			continue
		}
		target, payload, err := parseUDPDatagram(packet[:n])
		if err != nil {
			continue
		}
		if source == nil {
			source = from
		}
		flow := flows[target]
		if flow != nil {
			select {
			case <-flow.done:
				delete(flows, target)
				flow = nil
			default:
			}
		}
		if flow == nil {
			for key, old := range flows {
				select {
				case <-old.done:
					delete(flows, key)
				default:
				}
			}
			if len(flows) >= maxUDPFlows {
				continue
			}
			dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
			remote, e := s.Dial(dialCtx, "udp", target)
			dialCancel()
			if e != nil {
				continue // Denied or unavailable destinations never use host routing.
			}
			header, e := udpReplyHeader(remote.RemoteAddr())
			if e != nil {
				remote.Close()
				continue
			}
			flow = &udpFlow{conn: remote, done: make(chan struct{})}
			flows[target] = flow
			workers.Add(1)
			go func(flow *udpFlow, destination *net.UDPAddr) {
				defer workers.Done()
				defer close(flow.done)
				defer flow.conn.Close()
				response := make([]byte, 65535)
				copy(response, header)
				for {
					flow.conn.SetReadDeadline(time.Now().Add(udpFlowIdle))
					n, e := flow.conn.Read(response[len(header):])
					if e != nil {
						return
					}
					if len(header)+n > 65507 {
						continue // The SOCKS header must also fit the local UDP packet.
					}
					relay.SetWriteDeadline(time.Now().Add(15 * time.Second))
					if _, e = relay.WriteToUDP(response[:len(header)+n], destination); e != nil {
						return
					}
				}
			}(flow, source)
		}
		flow.conn.SetReadDeadline(time.Now().Add(udpFlowIdle))
		flow.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := flow.conn.Write(payload); err != nil {
			flow.conn.Close()
		}
	}
}

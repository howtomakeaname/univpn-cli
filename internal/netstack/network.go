// Package netstack exposes TCP sockets backed exclusively by VPN IP packets.
package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Network struct {
	Stack    *stack.Stack
	Endpoint *channel.Endpoint
	IP       netip.Addr
	once     sync.Once
}

func New(ip netip.Addr, mtu int) (_ *Network, err error) {
	if !ip.Is4() || mtu < 576 || mtu > 9000 {
		return nil, errors.New("invalid IPv4/MTU")
	}
	n := &Network{IP: ip, Stack: stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	}), Endpoint: channel.New(512, uint32(mtu), "")}
	defer func() {
		if err != nil {
			n.Close()
		}
	}()
	sack := tcpip.TCPSACKEnabled(true)
	if e := n.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); e != nil {
		return nil, fmt.Errorf("TCP SACK: %s", e)
	}
	if e := n.Stack.CreateNIC(1, n.Endpoint); e != nil {
		return nil, fmt.Errorf("NIC: %s", e)
	}
	addr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix()}
	if e := n.Stack.AddProtocolAddress(1, addr, stack.AddressProperties{}); e != nil {
		return nil, fmt.Errorf("address: %s", e)
	}
	n.Stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return n, nil
}

func (n *Network) Close() { n.once.Do(func() { n.Stack.Close(); n.Endpoint.Close(); n.Stack.Wait() }) }

func (n *Network) Receive(ctx context.Context) ([]byte, error) {
	p := n.Endpoint.ReadContext(ctx)
	if p == nil {
		return nil, io.EOF
	}
	defer p.DecRef()
	v := p.ToView()
	defer v.Release()
	return append([]byte(nil), v.AsSlice()...), nil
}

func (n *Network) Inject(p []byte) error {
	if len(p) < 20 || p[0]>>4 != 4 || int(p[0]&15)*4 < 20 || int(p[0]&15)*4 > len(p) || int(binary.BigEndian.Uint16(p[2:])) != len(p) {
		return errors.New("malformed IPv4 packet")
	}
	if netip.AddrFrom4([4]byte(p[16:20])) != n.IP {
		return errors.New("VPN packet addressed to another virtual IP")
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
	defer pkt.DecRef()
	n.Endpoint.InjectInbound(ipv4.ProtocolNumber, pkt)
	return nil
}

func (n *Network) DialIP(ctx context.Context, ip netip.Addr, port uint16) (net.Conn, error) {
	if !ip.Is4() {
		return nil, errors.New("only IPv4 VPN destinations are supported")
	}
	return gonet.DialContextTCP(ctx, n.Stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: port}, ipv4.ProtocolNumber)
}

// Policy resolves names without consulting host DNS, then checks EVERY final IP.
type Policy struct {
	Net   *Network
	Allow []netip.Prefix
	Hosts map[string]netip.Addr
	DNS   []netip.Addr
}

func (p *Policy) Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip == netip.MustParseAddr("255.255.255.255") {
		return false
	}
	for _, prefix := range p.Allow {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("proxy supports TCP only")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("destination must be host:port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid destination port")
	}
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		name := strings.ToLower(strings.TrimSuffix(host, "."))
		if ip, ok := p.Hosts[name]; ok {
			ips = []netip.Addr{ip}
		} else {
			if len(p.DNS) == 0 {
				return nil, errors.New("name has no static hosts entry; configure VPN DNS or use an IPv4 address")
			}
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// DNS packets also pass through the VPN. Never use system resolv.conf servers.
				server := p.DNS[0]
				addr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(server.AsSlice()), Port: 53}
				var c net.Conn
				var err error
				if strings.HasPrefix(network, "tcp") {
					c, err = gonet.DialContextTCP(ctx, p.Net.Stack, addr, ipv4.ProtocolNumber)
				} else {
					c, err = gonet.DialUDP(p.Net.Stack, nil, &addr, ipv4.ProtocolNumber)
				}
				if err == nil {
					deadline := time.Now().Add(5 * time.Second)
					if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
						deadline = d
					}
					c.SetDeadline(deadline)
				}
				return c, err
			}}
			ips, err = resolver.LookupNetIP(ctx, "ip4", name)
			if err != nil {
				return nil, errors.New("VPN DNS resolution failed")
			}
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("no IPv4 destination")
	}
	// Reject mixed allowed/disallowed answers, including DNS rebinding attempts.
	for _, ip := range ips {
		if !p.Allowed(ip) {
			return nil, errors.New("destination denied by allow_cidrs")
		}
	}
	for _, ip := range ips {
		c, e := p.Net.DialIP(ctx, ip, uint16(port))
		if e == nil {
			return c, nil
		}
		err = e
	}
	return nil, err
}

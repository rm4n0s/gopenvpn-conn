// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"context"
	"net"
	"net/netip"
	"strconv"

	"github.com/rm4n0s/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Tags of the errors of DialContext, Listen and ListenPacket.
const (
	// TagUnsupportedNetwork: the network is not "tcp", "tcp4", "tcp6", "udp",
	// "udp4" or "udp6" (or, for Listen, not a TCP one; for ListenPacket, not a UDP
	// one). Metadata: "network".
	TagUnsupportedNetwork = "NetUnsupportedNetwork"
	// TagBadAddress: the address is not "host:port" with an IP address for the host
	// (host names are for DialContext only) and a port, or the address
	// is not of the family that the network names. Metadata: "network", "address",
	// "reason".
	TagBadAddress = "NetBadAddress"
	// TagDialFailed: the connection could not be made. The cause (a refused
	// connection, the context) is behind the error. Metadata: "network", "address".
	TagDialFailed = "NetDialFailed"
	// TagResolveFailed: the host name could not be looked up through the tunnel (no
	// DNS server was pushed, the servers do not know it, none answered), or it has no
	// address that the tunnel can reach. The cause is behind the error. Metadata:
	// "network", "address".
	TagResolveFailed = "NetResolveFailed"
	// TagListenFailed: the listener could not be made (the port is taken, the
	// address is not one of the tunnel). Metadata: "network", "address", "reason".
	TagListenFailed = "NetListenFailed"
)

// maxListenBacklog is the backlog of a listener, the same that the Go net package
// takes as the most on Linux.
const maxListenBacklog = 4096

// target is a network and an address, read and checked.
type target struct {
	stream bool // TCP; false is UDP
	family tcpip.NetworkProtocolNumber
	v6only bool       // the network is "tcp6" or "udp6"
	addr   netip.Addr // the zero Addr is any (only for a listener)
	host   string     // a host name, when the address has one (only for DialContext)
	port   uint16
}

// parse reads network and address. wildcard allows an empty host, and names allows a
// host name in place of an IP address.
func parse(network, address string, wildcard, names bool) (target, error) {
	var t target
	var want string // "4", "6" or "" for either
	switch network {
	case "tcp", "udp":
	case "tcp4", "udp4":
		want = "4"
	case "tcp6", "udp6":
		want = "6"
	default:
		return t, errors.New(TagUnsupportedNetwork, "the network is not supported", "network", network)
	}
	t.stream = network[0] == 't'
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return t, errors.New(TagBadAddress, "the address is not host:port", "network", network, "address", address, "reason", "not host:port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return t, errors.New(TagBadAddress, "the port is not a number from 0 to 65535", "network", network, "address", address, "reason", "bad port")
	}
	t.port = uint16(port & 0xffff)
	if host == "" {
		if !wildcard {
			return t, errors.New(TagBadAddress, "the address has no host", "network", network, "address", address, "reason", "no host")
		}
		t.family, t.v6only = ipv6.ProtocolNumber, want == "6"
		if want == "4" {
			t.family = ipv4.ProtocolNumber
		}
		return t, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil && names && validHostName(host) {
		t.host = host
		return t, nil
	}
	if err != nil || ip.Zone() != "" {
		return t, errors.New(TagBadAddress, "the host is not an IP address", "network", network, "address", address, "reason", "not an IP address")
	}
	ip = ip.Unmap()
	if (want == "4" && !ip.Is4()) || (want == "6" && !ip.Is6()) {
		return t, errors.New(TagBadAddress, "the address is not of the family of the network", "network", network, "address", address, "reason", "wrong family")
	}
	t.addr = ip
	t.family = ipv4.ProtocolNumber
	if ip.Is6() {
		t.family = ipv6.ProtocolNumber
	}
	return t, nil
}

// full is the address in the stack's form.
func (t target) full() tcpip.FullAddress {
	f := tcpip.FullAddress{Port: t.port}
	if t.addr.IsValid() {
		f.Addr = tcpipAddr(t.addr)
	}
	return f
}

// DialContext connects to address through the tunnel. network is "tcp", "tcp4",
// "tcp6", "udp", "udp4" or "udp6", and address is a host and a port. A host that is
// not an IP address is looked up with Resolver, through the tunnel, and the
// addresses that it has (of the families that the tunnel has and the network allows)
// are tried in order. The connection is a net.Conn whose errors are the ones of
// gVisor's gonet, which behave as those of the net package. ctx bounds the looking
// up and the connecting only. After Close, and after the tunnel has ended,
// DialContext returns the error that ended the Net: net.ErrClosed after Close.
func (n *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := n.err(); err != nil {
		return nil, err
	}
	t, err := parse(network, address, false, true)
	if err != nil {
		return nil, err
	}
	if t.host == "" {
		return n.dialTarget(ctx, network, address, t)
	}
	addrs, err := n.resolver.LookupNetIP(ctx, n.lookupNetwork(network), t.host)
	if err != nil {
		return nil, errors.NewErr(TagResolveFailed, err).SetMetadata("network", network, "address", address)
	}
	var lastErr error
	for _, ip := range addrs {
		ip = ip.Unmap()
		if (ip.Is4() && !n.has4) || (ip.Is6() && !n.has6) {
			continue
		}
		c := t
		c.addr, c.family = ip, ipv4.ProtocolNumber
		if ip.Is6() {
			c.family = ipv6.ProtocolNumber
		}
		conn, err := n.dialTarget(ctx, network, address, c)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		return nil, errors.New(TagResolveFailed, "the host has no address that the tunnel can reach", "network", network, "address", address)
	}
	return nil, lastErr
}

// lookupNetwork is the network of the lookup for a dial: the families that the
// network names and the tunnel has.
func (n *Net) lookupNetwork(network string) string {
	switch {
	case network == "tcp4" || network == "udp4":
		return "ip4"
	case network == "tcp6" || network == "udp6":
		return "ip6"
	case n.has4 && n.has6:
		return "ip"
	case n.has6:
		return "ip6"
	}
	return "ip4"
}

// dialTarget connects to t, which has an IP address.
func (n *Net) dialTarget(ctx context.Context, network, address string, t target) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.NewErr(TagDialFailed, err).SetMetadata("network", network, "address", address)
	}
	if t.stream {
		conn, err := gonet.DialContextTCP(ctx, n.stack, t.full(), t.family)
		if err != nil {
			return nil, errors.NewErr(TagDialFailed, err).SetMetadata("network", network, "address", address)
		}
		return conn, nil
	}
	remote := t.full()
	conn, err := gonet.DialUDP(n.stack, nil, &remote, t.family)
	if err != nil {
		return nil, errors.NewErr(TagDialFailed, err).SetMetadata("network", network, "address", address)
	}
	return conn, nil
}

// validHostName reports whether s can be looked up as a host name: letters, digits,
// hyphens, underscores and dots, at most 253 bytes.
func validHostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// Listen listens for TCP connections at an address of the tunnel. network is "tcp",
// "tcp4" or "tcp6"; address is "ip:port", or ":port" for every address (for "tcp",
// IPv4 and IPv6 both); a port of 0 takes a free one, which Addr of the listener
// tells. Another program reaches the listener at the address that the server pushed.
func (n *Net) Listen(network, address string) (net.Listener, error) {
	if err := n.err(); err != nil {
		return nil, err
	}
	t, err := parse(network, address, true, false)
	if err != nil {
		return nil, err
	}
	if !t.stream {
		return nil, errors.New(TagUnsupportedNetwork, "Listen takes a TCP network", "network", network)
	}
	var wq waiter.Queue
	ep, terr := n.stack.NewEndpoint(tcp.ProtocolNumber, t.family, &wq)
	if terr != nil {
		return nil, errors.New(TagListenFailed, "the stack made no endpoint", "network", network, "address", address, "reason", terr.String())
	}
	ep.SocketOptions().SetV6Only(t.v6only)
	if terr := ep.Bind(t.full()); terr != nil {
		ep.Close()
		return nil, errors.New(TagListenFailed, "the address could not be bound", "network", network, "address", address, "reason", terr.String())
	}
	if terr := ep.Listen(maxListenBacklog); terr != nil {
		ep.Close()
		return nil, errors.New(TagListenFailed, "the endpoint could not listen", "network", network, "address", address, "reason", terr.String())
	}
	return gonet.NewTCPListener(n.stack, &wq, ep), nil
}

// ListenPacket listens for UDP datagrams at an address of the tunnel; network is
// "udp", "udp4" or "udp6", and address is as in Listen.
func (n *Net) ListenPacket(network, address string) (net.PacketConn, error) {
	if err := n.err(); err != nil {
		return nil, err
	}
	t, err := parse(network, address, true, false)
	if err != nil {
		return nil, err
	}
	if t.stream {
		return nil, errors.New(TagUnsupportedNetwork, "ListenPacket takes a UDP network", "network", network)
	}
	var wq waiter.Queue
	ep, terr := n.stack.NewEndpoint(udp.ProtocolNumber, t.family, &wq)
	if terr != nil {
		return nil, errors.New(TagListenFailed, "the stack made no endpoint", "network", network, "address", address, "reason", terr.String())
	}
	ep.SocketOptions().SetV6Only(t.v6only)
	if terr := ep.Bind(t.full()); terr != nil {
		ep.Close()
		return nil, errors.New(TagListenFailed, "the address could not be bound", "network", network, "address", address, "reason", terr.String())
	}
	return gonet.NewUDPConn(&wq, ep), nil
}

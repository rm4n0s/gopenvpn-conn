// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"context"
	"net"
	"net/netip"

	"github.com/rm4n0s/errors"
)

// Tags of the errors of the resolver.
const (
	// TagNoDNSServers: the server pushed no DNS server, so a name cannot be looked up
	// through the tunnel. Reached through the errors of Resolver.
	TagNoDNSServers = "NetNoDNSServers"
)

// dnsPort is the port of the DNS servers of the VPN.
const dnsPort = "53"

// Resolver returns a *net.Resolver whose queries go through the tunnel to the DNS
// servers that the VPN server pushed, one after the other: a server whose answers fail
// (an error, or no answer in time) is left, and the next one is tried at the next
// attempt of the resolver. With no DNS server pushed every lookup fails (the
// *net.DNSError says that there is no server: the standard library keeps the text of
// the error of a Dial function, not the error).
//
// The resolver is Go's own (PreferGo) with a Dial function that ignores the address
// that the resolver wants: the standard library still reads the host's /etc/hosts
// and resolv.conf (the search list, the number of attempts, the timeout) where they
// exist, besides the servers.
func (n *Net) Resolver() *net.Resolver { return n.resolver }

// dnsServers are the pushed DNS servers that the tunnel can reach, in the order that
// the server gave them.
func (n *Net) dnsServers() []netip.Addr {
	var out []netip.Addr
	for _, a := range n.state.DNSServers {
		a = a.Unmap()
		if (a.Is4() && n.has4) || (a.Is6() && n.has6) {
			out = append(out, a)
		}
	}
	return out
}

// dialDNS is the Dial function of the resolver. It connects to the first DNS server
// that takes a connection, from the one that worked last; the address that the
// resolver asked for is not used.
func (n *Net) dialDNS(ctx context.Context, network, _ string) (net.Conn, error) {
	servers := n.dnsServers()
	if len(servers) == 0 {
		return nil, errors.New(TagNoDNSServers, "the server pushed no DNS server that the tunnel can reach")
	}
	start := int(n.dnsStart.Load())
	var lastErr error
	for i := range servers {
		idx := (start + i) % len(servers)
		server := servers[idx]
		conn, err := n.DialContext(ctx, network, net.JoinHostPort(server.String(), dnsPort))
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		c := dnsConn{Conn: conn, n: n, index: idx, count: len(servers)}
		if pc, ok := conn.(net.PacketConn); ok {
			// The resolver tells a datagram connection from a stream by the type.
			return &dnsPacketConn{dnsConn: c, pc: pc}, nil
		}
		return &c, nil
	}
	return nil, lastErr
}

// dnsConn is a connection to a DNS server that tells the Net how the server did: the
// first server whose read fails is left for the next one.
type dnsConn struct {
	net.Conn
	n     *Net
	index int // the server in dnsServers
	count int
}

// note records the result of a read: a server that answered is the one to start with;
// one that failed gives its place to the next, unless another connection has moved on.
func (c *dnsConn) note(err error) {
	if err == nil {
		c.n.dnsStart.Store(int32(c.index & 0xff))
		return
	}
	c.n.dnsStart.CompareAndSwap(int32(c.index&0xff), int32((c.index+1)%c.count&0xff))
}

func (c *dnsConn) Read(b []byte) (int, error) {
	size, err := c.Conn.Read(b)
	c.note(err)
	return size, err
}

// dnsPacketConn is dnsConn for UDP: it is also a net.PacketConn, as the resolver asks.
type dnsPacketConn struct {
	dnsConn
	pc net.PacketConn
}

func (c *dnsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	size, addr, err := c.pc.ReadFrom(b)
	c.note(err)
	return size, addr, err
}

func (c *dnsPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) { return c.pc.WriteTo(b, addr) }

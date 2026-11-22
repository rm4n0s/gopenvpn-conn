// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/rm4n0s/errors"
)

// Tags of the errors of the resolver.
const (
	// TagNoDNSServers: there is no DNS server that the tunnel can reach (the VPN server
	// pushed none and Options.DNSServers has none), so a name cannot be looked up
	// through the tunnel. Returned by LookupNetIP; reached through the errors of Resolver.
	TagNoDNSServers = "NetNoDNSServers"
)

// dnsPort is the port of a DNS server whose port is not given.
const dnsPort = 53

// Resolver returns a *net.Resolver whose queries go through the tunnel to the DNS
// servers of Options.DNSServers, or, when there are none, to the ones that the VPN
// server pushed, one after the other: a server whose answers fail (an error, or no
// answer in time) is tried after the others for a while (dnsCooldown), so the next
// attempt of the resolver goes to the next one. With no DNS server (none pushed, none in Options) every lookup fails (the
// *net.DNSError says that there is no server: the standard library keeps the text of
// the error of a Dial function, not the error).
//
// The resolver is Go's own (PreferGo) with a Dial function that ignores the address
// that the resolver wants: the standard library still reads the host's /etc/hosts
// and resolv.conf (the search list, the number of attempts, the timeout) where they
// exist, besides the servers. A program that must not read them uses Net.LookupNetIP
// and Net.LookupHost, the DNS client of this package, which reads nothing of the host
// (and so does DialContext).
func (n *Net) Resolver() *net.Resolver { return n.resolver }

// dnsServers are the DNS servers that the tunnel can reach: those of Options.DNSServers,
// or, when it has none, the pushed ones (port 53), in the order given.
func (n *Net) dnsServers() []netip.AddrPort {
	var out []netip.AddrPort
	add := func(a netip.AddrPort) {
		ip := a.Addr().Unmap()
		if (ip.Is4() && n.has4) || (ip.Is6() && n.has6) {
			out = append(out, netip.AddrPortFrom(ip, a.Port()))
		}
	}
	if len(n.opts.DNSServers) > 0 {
		for _, a := range n.opts.DNSServers {
			if a.Port() == 0 {
				a = netip.AddrPortFrom(a.Addr(), dnsPort)
			}
			add(a)
		}
		return out
	}
	for _, a := range n.state.DNSServers {
		add(netip.AddrPortFrom(a, dnsPort))
	}
	return out
}

// dnsCooldown is how long a DNS server that failed is tried after the others. Then it
// has its place again: the first server of the list is the one that the VPN means to
// be asked (an internal one before a public one, say), so one lost answer must not
// move the lookups to the next server for good.
const dnsCooldown = 30 * time.Second

// dnsOrder is the order in which count servers are tried: the ones that have not
// failed lately in the order of the list, then the ones that have, so that every
// server is tried when the good ones fail.
func (n *Net) dnsOrder(count int) []int {
	now := time.Now().UnixNano()
	order := make([]int, 0, count)
	var down []int
	for i := range count {
		if i < len(n.dnsDown) && n.dnsDown[i].Load() > now {
			down = append(down, i)
			continue
		}
		order = append(order, i)
	}
	return append(order, down...)
}

// noteDNS records how the server at index did: one that failed (an error, no answer
// in time) is tried after the others for dnsCooldown; one that answered is in its
// place. "No such name" is an answer.
func (n *Net) noteDNS(index int, err error) {
	if index >= len(n.dnsDown) {
		return
	}
	if err == nil {
		n.dnsDown[index].Store(0)
		return
	}
	n.dnsDown[index].Store(time.Now().Add(dnsCooldown).UnixNano())
}

// dialDNS is the Dial function of the resolver. It connects to the first DNS server
// that takes a connection, in the order of dnsOrder; the address that the resolver
// asked for is not used.
func (n *Net) dialDNS(ctx context.Context, network, _ string) (net.Conn, error) {
	servers := n.dnsServers()
	if len(servers) == 0 {
		return nil, errors.New(TagNoDNSServers, "no DNS server that the tunnel can reach: none was pushed and Options.DNSServers has none")
	}
	var lastErr error
	for _, idx := range n.dnsOrder(len(servers)) {
		server := servers[idx]
		conn, err := n.DialContext(ctx, network, server.String())
		if err != nil {
			n.noteDNS(idx, err)
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		c := dnsConn{Conn: conn, n: n, index: idx}
		if pc, ok := conn.(net.PacketConn); ok {
			// The resolver tells a datagram connection from a stream by the type.
			return &dnsPacketConn{dnsConn: c, pc: pc}, nil
		}
		return &c, nil
	}
	return nil, lastErr
}

// dnsConn is a connection to a DNS server that tells the Net how the server did: a
// server whose read fails is tried after the others for a while.
type dnsConn struct {
	net.Conn
	n     *Net
	index int // the server in dnsServers
}

// note records the result of a read.
func (c *dnsConn) note(err error) { c.n.noteDNS(c.index, err) }

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

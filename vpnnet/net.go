// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rm4n0s/errors"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
)

// Tags of the errors of New.
const (
	// TagNilConn: New was given no connection.
	TagNilConn = "NetNilConn"
	// TagNotConnected: the handshake of the connection is not complete, so there
	// is no tunnel address yet. Dial the Conn (or call HandshakeContext) first.
	TagNotConnected = "NetNotConnected"
	// TagStackSetupFailed: the TCP/IP stack refused the interface or an address of
	// the tunnel. Metadata: "step", "reason".
	TagStackSetupFailed = "NetStackSetupFailed"
)

// nicID is the one interface of the stack: the tunnel.
const nicID tcpip.NICID = 1

// queueSize is how many outgoing packets the stack can queue before it waits for the
// tunnel.
const queueSize = 512

// Options are the settings of a Net. The zero value is valid.
type Options struct {
	// CloseConn makes Close close the *openvpn.Conn too. By default the Conn is
	// the caller's and stays open.
	CloseConn bool
	// DNSServers are the DNS servers for the names that DialContext, LookupNetIP,
	// LookupHost and Resolver look up, asked through the tunnel in this order. A port of
	// 0 is port 53. When there are some, the servers that the VPN server pushed are not
	// used; with none, the pushed ones are. Servers of a family that the tunnel has no
	// address for are skipped.
	DNSServers []netip.AddrPort
	// Logger gets the events of the Net (the end of the tunnel, a packet that was
	// dropped). Nil is no log.
	Logger *slog.Logger
}

// Net is a userspace network over an *openvpn.Conn. Its methods are safe to call
// from several goroutines.
type Net struct {
	conn   *openvpn.Conn
	stack  *stack.Stack
	ep     *channel.Endpoint
	opts   Options
	logger *slog.Logger
	state  openvpn.ConnectionState
	has4   bool // the tunnel has an IPv4 address
	has6   bool // the tunnel has an IPv6 address

	resolver *net.Resolver
	dnsStart atomic.Int32 // the index in dnsServers() where the next lookup starts

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	downOnce sync.Once // the stack is destroyed once

	mu     sync.Mutex
	endErr error // what ended the Net: net.ErrClosed after Close, else what ended the tunnel
}

// New makes a Net over conn, whose handshake must be complete. The stack gets the
// addresses that the server pushed and a default route for IPv4 and for IPv6 into
// the tunnel.
func New(conn *openvpn.Conn, opts *Options) (*Net, error) {
	if conn == nil {
		return nil, errors.New(TagNilConn, "the connection is nil")
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		return nil, errors.New(TagNotConnected, "the handshake of the connection is not complete")
	}
	s, ep, err := newStack(state)
	if err != nil {
		return nil, err
	}
	var o Options
	if opts != nil {
		o = *opts
		o.DNSServers = slices.Clone(opts.DNSServers) // the caller may change its slice
	}
	n := &Net{conn: conn, stack: s, ep: ep, opts: o, logger: o.Logger, state: state}
	for _, p := range state.Addrs {
		n.has4 = n.has4 || p.Addr().Unmap().Is4()
		n.has6 = n.has6 || p.Addr().Unmap().Is6()
	}
	n.resolver = &net.Resolver{PreferGo: true, Dial: n.dialDNS}
	if n.logger == nil {
		n.logger = slog.New(slog.DiscardHandler)
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	n.wg.Add(2)
	go n.readTunnel()
	go n.writeTunnel()
	return n, nil
}

// newStack makes the stack of the tunnel: the protocols, the interface with the MTU
// of the tunnel, its addresses and the default routes.
func newStack(state openvpn.ConnectionState) (*stack.Stack, *channel.Endpoint, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	ep := channel.New(queueSize, uint32(state.MTU&0xffff), "")
	if terr := s.CreateNIC(nicID, ep); terr != nil {
		s.Destroy() // the stack has goroutines: a stack that is not used must not stay
		return nil, nil, errors.New(TagStackSetupFailed, "the stack refused the interface", "step", "create-nic", "reason", terr.String())
	}
	for _, prefix := range state.Addrs {
		addr := prefix.Addr().Unmap()
		pa := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpipAddr(addr), PrefixLen: prefix.Bits()},
		}
		pa.Protocol = ipv4.ProtocolNumber
		if addr.Is6() {
			pa.Protocol = ipv6.ProtocolNumber
		}
		if terr := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); terr != nil {
			s.Destroy()
			return nil, nil, errors.New(TagStackSetupFailed, "the stack refused an address of the tunnel",
				"step", "add-address", "address", prefix.String(), "reason", terr.String())
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	return s, ep, nil
}

// tcpipAddr converts an address to the stack's type.
func tcpipAddr(a netip.Addr) tcpip.Address {
	b := a.AsSlice()
	return tcpip.AddrFromSlice(b)
}

// readTunnel gives each packet that the Conn reads to the stack, until the Conn
// fails or the Net is closed.
func (n *Net) readTunnel() {
	defer n.wg.Done()
	mtu := max(n.state.MTU, 576)
	buf := make([]byte, mtu)
	for {
		size, err := n.conn.Read(buf)
		if err != nil {
			if n.ctx.Err() == nil {
				n.fail(err)
			}
			return
		}
		var proto tcpip.NetworkProtocolNumber
		switch buf[0] >> 4 {
		case 4:
			proto = ipv4.ProtocolNumber
		case 6:
			proto = ipv6.ProtocolNumber
		default:
			n.logger.Debug("a packet that is not IP was dropped", "size", size)
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[:size])})
		n.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

// writeTunnel writes each packet that the stack sends to the Conn, until the Net is
// closed or the Conn fails.
func (n *Net) writeTunnel() {
	defer n.wg.Done()
	for {
		pkt := n.ep.ReadContext(n.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		_, err := n.conn.Write(view.AsSlice())
		view.Release()
		pkt.DecRef()
		if err != nil {
			if n.ctx.Err() == nil {
				n.fail(err)
			}
			return
		}
	}
}

// fail ends the Net because the tunnel ended: every connection of the stack fails
// and the later calls return err. Only the first cause counts.
func (n *Net) fail(err error) {
	n.mu.Lock()
	if n.endErr == nil {
		n.endErr = err
	}
	n.mu.Unlock()
	n.logger.Info("the tunnel ended", "err", err)
	n.down()
}

// down stops the goroutines and destroys the stack, which fails the connections that
// it holds. It does not wait for the goroutines.
func (n *Net) down() {
	n.downOnce.Do(func() {
		n.cancel()
		n.stack.Destroy()
	})
}

// err is what ended the Net, or nil while it runs.
func (n *Net) err() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.endErr
}

// Close ends the Net: its connections and listeners fail, its goroutines stop and,
// with Options.CloseConn, the Conn is closed. When Close returns no goroutine of the
// Net runs. Without CloseConn the read deadline of the Conn is cleared at the end.
// Close may be called more than once.
func (n *Net) Close() error {
	n.mu.Lock()
	if n.endErr == nil {
		n.endErr = net.ErrClosed
	}
	n.mu.Unlock()
	n.cancel()
	var closeErr error
	if n.opts.CloseConn {
		closeErr = n.conn.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
	} else if err := n.conn.SetReadDeadline(time.Unix(1, 0)); err != nil && !errors.Is(err, net.ErrClosed) {
		// The Conn has ended on its own: its Read has failed already.
		n.logger.Debug("the read of the connection could not be interrupted", "err", err)
	}
	n.down()
	n.wg.Wait()
	if !n.opts.CloseConn {
		if err := n.conn.SetReadDeadline(time.Time{}); err != nil && !errors.Is(err, net.ErrClosed) {
			n.logger.Debug("the read deadline of the connection could not be cleared", "err", err)
		}
	}
	return closeErr
}

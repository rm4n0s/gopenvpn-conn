// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/rm4n0s/errors"
)

// Tags of the errors of Dial.
const (
	// TagDialFailed: the connection to the server could not be made. The
	// cause (a refused connection, a timeout, the context) can be found with
	// errors.Is. Metadata: "network", "address".
	TagDialFailed = "DialFailed"
	// TagUnsupportedNetwork: the network is not one of "udp", "udp4", "udp6",
	// "tcp", "tcp4" or "tcp6". Metadata: "network".
	TagUnsupportedNetwork = "UnsupportedNetwork"
)

// Dial connects to the server at address and returns when the handshake is
// complete, or when it fails or ctx is done. network is "udp", "udp4", "udp6",
// "tcp", "tcp4" or "tcp6". A nil config is the zero Config.
//
// ctx bounds the connecting and the handshake; it does not bound the life of
// the Conn that is returned. Config.ServerPollTimeout bounds the connecting and the
// wait for the server's first packet, and Config.HandshakeTimeout the handshake.
//
// A name with more than one address: over TCP the addresses are tried until a
// connection is made, as net.Dialer does. Over UDP, where no connection says that
// the server is there, the next address is tried when the server at one sends
// nothing at all, each with Config.ServerPollTimeout of its own (without it, an
// address that is silent takes the time of the handshake); the error is the one
// of the last address, with the metadata "addresses" and "addresses_tried". A
// server that has answered is the server: what fails after that is returned.
func Dial(ctx context.Context, network, address string, config *Config) (*Conn, error) {
	d := Dialer{Config: config}
	return d.Dial(ctx, network, address)
}

// Dialer makes connections to servers with the same settings, as net.Dialer
// does.
type Dialer struct {
	// NetDialer makes the connection to the server (the link). Nil means the
	// zero net.Dialer. It is not used when DialContext is set.
	NetDialer *net.Dialer
	// DialContext, when set, makes the link in place of NetDialer: a way to
	// go through a proxy, or to use a link of the caller's own. It gets the
	// address as Dial got it: a name is not looked up, so its other addresses
	// are DialContext's to try.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// Config is the configuration of the connections; nil is the zero Config.
	Config *Config

	// lookup replaces the resolver of NetDialer, and makes Dial look a name up
	// with DialContext set too: the tests choose the addresses and the links.
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dial is the function Dial with the settings of the Dialer.
func (d *Dialer) Dial(ctx context.Context, network, address string) (*Conn, error) {
	var stream bool
	switch network {
	case "udp", "udp4", "udp6":
	case "tcp", "tcp4", "tcp6":
		stream = true
	default:
		return nil, errors.New(TagUnsupportedNetwork, "the network is not supported", "network", network)
	}
	dial := d.DialContext
	if dial == nil {
		netDialer := d.NetDialer
		if netDialer == nil {
			netDialer = &net.Dialer{}
		}
		dial = netDialer.DialContext
	}
	// Config.ServerPollTimeout bounds the making of the link (the lookup of a name
	// included) and, with what is left of it, the wait for the first packet of the
	// server; it does not bound the handshake.
	var poll time.Duration
	if d.Config != nil && d.Config.ServerPollTimeout > 0 {
		poll = d.Config.ServerPollTimeout
	}
	linkContext := func() (context.Context, context.CancelFunc) {
		if poll > 0 {
			return context.WithTimeout(ctx, poll)
		}
		return ctx, func() {}
	}

	// The addresses to try: the address as it is, or each address of its name when
	// the link is of datagrams. A datagram socket "connects" to any address, so the
	// dialer of the link stops at the first one, whether a server is there or not.
	//
	// OpenVPN: socket.c, init.c next_connection_entry (the next address of the
	// remote is tried before the next remote).
	start := time.Now()
	targets := []string{address}
	if lookup, host, port := d.lookupFor(network, address, stream); lookup != nil {
		linkCtx, cancel := linkContext()
		addrs, err := lookup(linkCtx, lookupNetwork(network), host)
		cancel()
		if err != nil {
			return nil, errors.NewErr(TagDialFailed, err).SetMetadata("network", network, "address", address)
		}
		targets = targets[:0]
		for _, a := range addrs {
			targets = append(targets, net.JoinHostPort(a.Unmap().String(), port))
		}
		if len(targets) == 0 {
			return nil, errors.New(TagDialFailed, "the name of the server has no address", "network", network, "address", address)
		}
	}

	var last error
	tried := 0
	for i, target := range targets {
		if i > 0 {
			start = time.Now() // the next address has the whole time to answer
		}
		tried++
		linkCtx, cancel := linkContext()
		link, err := dial(linkCtx, network, target)
		cancel()
		if err != nil {
			last = errors.NewErr(TagDialFailed, err).SetMetadata("network", network, "address", address)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		left := poll
		if poll > 0 {
			left = max(poll-time.Since(start), time.Millisecond)
		}
		conn := newConn(link, stream, d.Config, left)
		if err = conn.HandshakeContext(ctx); err == nil {
			return conn, nil
		}
		// The session has closed the link already; Close collects the rest.
		if cerr := conn.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && d.Config != nil && d.Config.Logger != nil {
			d.Config.Logger.Error("closing the connection after a failed handshake", "err", cerr)
		}
		last = err
		if ctx.Err() != nil || conn.s.SawServer() {
			break // the caller gave up, or a server is at this address: its failure is the answer
		}
		if i+1 < len(targets) && d.Config != nil && d.Config.Logger != nil {
			d.Config.Logger.Info("the server did not answer at an address of its name; trying the next", "address", target, "err", err)
		}
	}
	if len(targets) > 1 {
		// The error was tagged where it was made; the metadata does not change its route.
		if appErr, ok := errors.FromError(last); ok {
			return nil, appErr.SetMetadata("addresses", len(targets), "addresses_tried", tried)
		}
	}
	return nil, last
}

// lookupFor is the function that looks up the name of address, with the name and
// the port, when Dial is to try the addresses of the name itself: a link of
// datagrams, made by NetDialer, to an address that is a name. Otherwise it is nil.
func (d *Dialer) lookupFor(network, address string, stream bool) (lookup func(ctx context.Context, network, host string) ([]netip.Addr, error), host, port string) {
	if stream || (d.DialContext != nil && d.lookup == nil) {
		return nil, "", ""
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, "", "" // the dialer of the link says what is wrong with it
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, "", ""
	}
	if d.lookup != nil {
		return d.lookup, host, port
	}
	resolver := net.DefaultResolver
	if d.NetDialer != nil && d.NetDialer.Resolver != nil {
		resolver = d.NetDialer.Resolver
	}
	return resolver.LookupNetIP, host, port
}

// lookupNetwork is the network of the lookup for a network of datagrams: the
// family that the network names, or both.
func lookupNetwork(network string) string {
	switch network {
	case "udp4":
		return "ip4"
	case "udp6":
		return "ip6"
	}
	return "ip"
}

// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"context"
	"net"

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
// the Conn that is returned.
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
	// go through a proxy, or to use a link of the caller's own.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// Config is the configuration of the connections; nil is the zero Config.
	Config *Config
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
	link, err := dial(ctx, network, address)
	if err != nil {
		return nil, errors.NewErr(TagDialFailed, err).SetMetadata("network", network, "address", address)
	}
	conn := newConn(link, stream, d.Config)
	if err := conn.HandshakeContext(ctx); err != nil {
		// The session has closed the link already; Close collects the rest.
		if cerr := conn.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && d.Config != nil && d.Config.Logger != nil {
			d.Config.Logger.Error("closing the connection after a failed handshake", "err", cerr)
		}
		return nil, err
	}
	return conn, nil
}

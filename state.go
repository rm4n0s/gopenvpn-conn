// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"crypto/tls"
	"net/netip"
	"slices"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
	"github.com/rm4n0s/gopenvpn-conn/internal/session"
)

// undefinedPeerID is the peer id of a session whose server pushed none: OpenVPN's
// "no peer id", the largest of the 24 bits.
const undefinedPeerID = 0xffffff

// Route is a route that the server pushed.
type Route struct {
	// Prefix is the network that the route leads to.
	Prefix netip.Prefix
	// Gateway is the next hop when the server named one; the zero Addr means
	// the gateway of the VPN (ConnectionState.Gateway).
	Gateway netip.Addr
	// Metric is the metric, or 0 when the server gave none.
	Metric int
}

// ConnectionState is what was negotiated and what the server pushed. Before the
// handshake is complete only the MTU of the Config is set.
type ConnectionState struct {
	// HandshakeComplete is true when the server's PUSH_REPLY has been read.
	HandshakeComplete bool
	// TLS is the state of the TLS session of the control channel.
	TLS tls.ConnectionState
	// Cipher is the data cipher that the server chose, for example
	// "AES-256-GCM"; empty when it chose none.
	Cipher string
	// PeerID is the peer id that the server gave this client, or 0xffffff when
	// it gave none.
	PeerID uint32
	// Addrs are the addresses of the tunnel: the IPv4 address with the length of
	// its network (ifconfig and topology) and the IPv6 address (ifconfig-ipv6).
	Addrs []netip.Prefix
	// Gateway is the address of the server inside the tunnel (route-gateway).
	Gateway netip.Addr
	// Routes are the routes that the server pushed.
	Routes []Route
	// RedirectGateway is true when the server asks for all the traffic of the
	// client to go through the VPN.
	RedirectGateway bool
	// DNSServers are the DNS servers that the server pushed (dhcp-option DNS and
	// DNS6, and the dns option).
	DNSServers []netip.Addr
	// SearchDomains are the DNS search domains that the server pushed
	// (dhcp-option DOMAIN and DOMAIN-SEARCH, and the dns option).
	SearchDomains []string
	// MTU is the MTU of the tunnel: the one the server pushed, or the one of the
	// Config. It is the size of the largest IP packet that Write takes.
	MTU int
	// PingInterval is the keepalive interval that the server pushed (ping); zero
	// when it pushed none.
	PingInterval time.Duration
	// PingTimeout is the keepalive timeout that the server pushed (ping-restart);
	// zero when it pushed none.
	PingTimeout time.Duration
	// PushedOptions are the options of the PUSH_REPLY as the server sent them,
	// the unknown ones too. The value of auth-token is left out: it is a secret.
	PushedOptions []string
}

// ConnectionState returns what was negotiated. It is safe to call at any time and
// from any goroutine; it returns a copy.
func (c *Conn) ConnectionState() ConnectionState {
	state := ConnectionState{MTU: c.mtu, PeerID: undefinedPeerID}
	pushed := c.s.Pushed()
	if pushed == nil {
		return state
	}
	state.HandshakeComplete = true
	state.TLS = c.s.TLS().ConnectionState()
	state.Cipher = pushed.Cipher
	if pushed.HasPeerID {
		state.PeerID = pushed.PeerID
	}
	state.Addrs = slices.Clone(pushed.Addrs)
	state.Gateway = pushed.Gateway
	for _, r := range pushed.Routes {
		state.Routes = append(state.Routes, Route{Prefix: r.Prefix, Gateway: r.Gateway, Metric: r.Metric})
	}
	state.RedirectGateway = pushed.RedirectGateway
	state.DNSServers = slices.Clone(pushed.DNSServers)
	state.SearchDomains = slices.Clone(pushed.SearchDomains)
	if pushed.MTU != 0 {
		state.MTU = pushed.MTU
	}
	state.PingInterval = pushed.PingInterval
	state.PingTimeout = pushed.PingRestart
	state.PushedOptions = slices.Clone(pushed.Options)
	return state
}

// Tags of the errors about what the server pushed.
const (
	// TagUnsupportedPushedOption: the server pushed an option that changes what
	// is on the wire in a way this library does not implement (compression,
	// fragmentation, a data cipher that is not AEAD). Metadata: "option".
	TagUnsupportedPushedOption = ctrlmsg.TagUnsupportedPushedOption
	// TagCipherNegotiationFailed: the server pushed a data cipher that the
	// client did not offer. Metadata: "cipher".
	TagCipherNegotiationFailed = ctrlmsg.TagCipherNegotiationFailed
	// TagPushedOptionRejected: a pull filter with the action PullReject matched a
	// pushed option. Metadata: "option" (its name, never its arguments).
	TagPushedOptionRejected = ctrlmsg.TagPushedOptionRejected
	// TagControlChannelFailed: reading or writing the control channel failed
	// after the key exchange: the server ended the TLS session, or the
	// connection broke. Metadata: "op" ("read" or "write").
	TagControlChannelFailed = session.TagControlChannelFailed
)

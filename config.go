// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"context"
	"crypto/tls"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
)

// Credentials are the user name and password of auth-user-pass. The server
// accepts at most 127 bytes of each.
type Credentials struct {
	// Username is the user name; at most 127 bytes.
	Username string
	// Password is the password; at most 127 bytes. It is never logged and never in
	// an error.
	Password string
}

// The defaults of Config.
const (
	// DefaultMTU is the tunnel MTU when Config.MTU is zero: OpenVPN's tun-mtu.
	DefaultMTU = 1500
	// minMTU and maxMTU bound Config.MTU. OpenVPN accepts 68 to 65535; below
	// the minimum IPv6 does not work and above 9000 there are no packets.
	minMTU = 576
	maxMTU = 9000
	// peerInfoMaxEntries, peerInfoMaxName and peerInfoMaxValue keep the peer
	// info far from the 64 KB that a message can carry.
	peerInfoMaxEntries = 32
	peerInfoMaxName    = 64
	peerInfoMaxValue   = 256
)

// defaultDataCiphers is OpenVPN's data-ciphers default, with ChaCha20 last.
var defaultDataCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}

// cipherKeyBits is the key size of each data cipher that is supported.
var cipherKeyBits = map[string]int{
	"AES-128-GCM":       128,
	"AES-192-GCM":       192,
	"AES-256-GCM":       256,
	"CHACHA20-POLY1305": 256,
}

// PullAction is what a PullFilter does with the pushed options that it matches.
type PullAction int

const (
	// PullAccept keeps the option; it is there to let some options through a later
	// filter that ignores more.
	PullAccept PullAction = iota
	// PullIgnore removes the option, as if the server had not pushed it.
	PullIgnore
	// PullReject ends the handshake with TagPushedOptionRejected.
	PullReject
)

// PullFilter is one pull-filter line of a profile: the pushed options that start with
// Prefix get Action.
type PullFilter struct {
	// Action is what is done with a matching option.
	Action PullAction
	// Prefix is compared with the start of the pushed option as the server sent it
	// (for example "route " or "dhcp-option DNS").
	Prefix string
}

// DefaultHandshakeTimeout is how long the handshake may take when
// Config.HandshakeTimeout is zero: OpenVPN's --hand-window.
const DefaultHandshakeTimeout = 60 * time.Second

// DefaultRenegotiateAfter is how long a key is used when Config.RenegotiateAfter is
// zero: OpenVPN's --reneg-sec.
const DefaultRenegotiateAfter = time.Hour

// Config is the configuration of a client, as tls.Config is for TLS. The zero
// value of a field means its default. A Config is not changed by the library
// and may be shared by connections.
type Config struct {
	// TLS is the configuration of the TLS client of the control channel: the
	// server's certificate is verified with it, and its Certificates are the
	// client's. It is required. NewTLSConfig builds one that verifies the
	// server the way OpenVPN does. The library uses a copy, and raises a
	// MinVersion below TLS 1.2 to it.
	TLS *tls.Config

	// ControlWrap protects the control channel with a key shared in advance:
	// the value of NewTLSAuth, NewTLSCrypt or NewTLSCryptV2. Nil means no
	// protection, which the servers that are set up for it refuse.
	ControlWrap ControlWrap

	// Credentials gives the user name and password that the server asks for
	// (the profile's auth-user-pass). It is called once for each connection,
	// when the key exchange starts, with a context that ends with the
	// connection. Nil means no credentials. The password is never logged and
	// never in an error.
	Credentials func(ctx context.Context) (Credentials, error)

	// AuthNoCache makes the client forget the user name and password once the first key
	// exchange is done (the profile's auth-nocache). A renegotiation then uses the auth
	// token that the server pushed, or, when it pushed none, calls Credentials again.
	AuthNoCache bool

	// DataCiphers are the ciphers of the data channel that the client offers to
	// the server, best first (the profile's data-ciphers). The server picks one.
	// The default is AES-256-GCM, AES-128-GCM and CHACHA20-POLY1305; AES-192-GCM
	// is also supported.
	DataCiphers []string

	// MTU is the MTU of the tunnel (the profile's tun-mtu). Zero means 1500.
	MTU int

	// PeerInfo are variables that the server's scripts get with the other
	// information about the client (the profile's setenv UV_name value). Each
	// name starts with "UV_".
	PeerInfo map[string]string

	// HandshakeTimeout is how long the handshake may take; zero means
	// DefaultHandshakeTimeout. It is OpenVPN's --hand-window.
	HandshakeTimeout time.Duration

	// ServerPollTimeout is how long the client waits for the server to answer: in
	// Dial, for the link to be made and for the first packet of the server; with
	// Client and PacketClient, for the first packet, from the start of the handshake.
	// When it passes the connection fails with TagDialFailed (the link) or
	// TagServerPollTimeout (no packet). Once the server has answered it bounds
	// nothing more: HandshakeTimeout bounds the handshake. It is OpenVPN's
	// --connect-timeout (--server-poll-timeout). Zero means no limit of its own;
	// negative is invalid.
	ServerPollTimeout time.Duration

	// PingInterval is how long the connection may be idle before the client sends
	// a keepalive ping (OpenVPN's --ping). A value that the server pushes (ping)
	// wins. Zero means no ping unless the server pushes one; negative is invalid.
	PingInterval time.Duration

	// PingTimeout is how long the client waits for anything from the server before
	// it ends the session with TagPingTimeout (--ping-restart). A value that the
	// server pushes (ping-restart) wins. Zero means no timeout unless the server
	// pushes one; negative is invalid.
	PingTimeout time.Duration

	// RenegotiateAfter is how long a key is used before the client makes a new one,
	// without a break in the traffic (the profile's reneg-sec); zero means
	// DefaultRenegotiateAfter and a negative value means never. A value that the
	// server pushes does not change it: the server renegotiates by its own time too,
	// and whoever is first starts it. Early renegotiations when a key is nearly used up
	// happen whatever this is.
	RenegotiateAfter time.Duration

	// RetransmitTimeout is how long the client waits for the acknowledgement of a
	// control packet before it sends it again; each repetition waits twice as long
	// (the profile's tls-timeout). Zero means 2 seconds.
	RetransmitTimeout time.Duration

	// PullFilters decide, in order, about each option that the server pushes: the
	// first filter whose Prefix the option starts with decides, and an option that no
	// filter matches is accepted (the profile's pull-filter). An ignored option is
	// not seen by the library and is not in ConnectionState.
	PullFilters []PullFilter

	// RouteNoPull ignores the pushed options about routes and DNS (route, route-ipv6,
	// route-gateway, redirect-gateway, redirect-private, dhcp-option, dns and
	// block-outside-dns) and accepts the others (the profile's route-nopull).
	RouteNoPull bool

	// Logger gets the events of the connection, with the error of a failure
	// as the attribute "err". It never gets a key, a password or a packet's
	// bytes. Nil means no logs.
	Logger *slog.Logger

	// resetOnly makes the handshake end with the exchange of resets, with no
	// TLS: for the tests of that exchange, which need no certificates.
	resetOnly bool

	// noEpoch makes the client not announce the epoch data format (IV_PROTO bit
	// 10), so that a server uses the format with 32-bit packet ids: for the tests
	// that go through that format against a real server. epochUsageLimit replaces
	// the usage limit of the epoch keys, so that a test goes through many epochs
	// with a few packets.
	noEpoch bool
	// noCCExit makes the client not announce the exit message of the control
	// channel (IV_PROTO bit 7), so that Close uses the older one of the data channel.
	noCCExit        bool
	epochUsageLimit uint64
}

// Validate reports whether the Config can be used: it returns the error that a Conn
// made with it would fail with, or nil. The error names the field and never carries a
// value that could be a secret.
func (c *Config) Validate() error { return c.validate() }

// validate checks the fields of a Config that can be wrong before there is a
// connection. The error names the field and never carries a value that could be a
// secret.
func (c *Config) validate() error {
	switch {
	case c.HandshakeTimeout < 0:
		return errors.New(tagInvalidConfig, "the handshake timeout is negative", "field", "HandshakeTimeout")
	case c.ServerPollTimeout < 0:
		return errors.New(tagInvalidConfig, "the server poll timeout is negative", "field", "ServerPollTimeout")
	case c.PingInterval < 0:
		return errors.New(tagInvalidConfig, "the ping interval is negative", "field", "PingInterval")
	case c.PingTimeout < 0:
		return errors.New(tagInvalidConfig, "the ping timeout is negative", "field", "PingTimeout")
	case c.RetransmitTimeout < 0:
		return errors.New(tagInvalidConfig, "the retransmit timeout is negative", "field", "RetransmitTimeout")
	case c.TLS == nil && !c.resetOnly:
		return errors.New(tagInvalidConfig, "Config.TLS is required: the server must be verified", "field", "TLS")
	case c.MTU != 0 && (c.MTU < minMTU || c.MTU > maxMTU):
		return errors.New(tagInvalidConfig, "the MTU is out of range", "field", "MTU", "min", minMTU, "max", maxMTU)
	}
	for _, name := range c.DataCiphers {
		if _, ok := cipherKeyBits[strings.ToUpper(name)]; !ok {
			return errors.New(tagInvalidConfig, "a data cipher is not supported", "field", "DataCiphers", "cipher", name)
		}
	}
	for _, f := range c.PullFilters {
		if f.Action < PullAccept || f.Action > PullReject {
			return errors.New(tagInvalidConfig, "a pull filter has an action that is not known", "field", "PullFilters")
		}
	}
	if len(c.PeerInfo) > peerInfoMaxEntries {
		return errors.New(tagInvalidConfig, "too many peer info variables", "field", "PeerInfo", "max", peerInfoMaxEntries)
	}
	for name, value := range c.PeerInfo {
		if !validUVName(name) || len(name) > peerInfoMaxName {
			return errors.New(tagInvalidConfig, "a peer info name is not UV_ and letters, digits and underscores", "field", "PeerInfo", "name", name)
		}
		if len(value) > peerInfoMaxValue || strings.ContainsAny(value, "\n\x00") {
			return errors.New(tagInvalidConfig, "a peer info value is too long or has a newline or NUL", "field", "PeerInfo", "name", name)
		}
	}
	return nil
}

// validUVName reports whether name is UV_ and at least one letter, digit or
// underscore after it: a name that cannot break a line of the peer info.
func validUVName(name string) bool {
	rest, ok := strings.CutPrefix(name, "UV_")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if !isNameRune(r) {
			return false
		}
	}
	return true
}

// isNameRune reports whether r is a letter, a digit or an underscore, in ASCII.
func isNameRune(r rune) bool {
	return r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

const tagInvalidConfig = "InvalidConfig"

// pullFilter makes the function that the session asks for each pushed option from
// PullFilters and RouteNoPull, or nil when nothing is filtered.
func (c *Config) pullFilter() func(option string) ctrlmsg.Verdict {
	if len(c.PullFilters) == 0 && !c.RouteNoPull {
		return nil
	}
	filters := slices.Clone(c.PullFilters)
	noPull := c.RouteNoPull
	return func(option string) ctrlmsg.Verdict {
		for _, f := range filters {
			if strings.HasPrefix(option, f.Prefix) {
				switch f.Action {
				case PullIgnore:
					return ctrlmsg.Ignore
				case PullReject:
					return ctrlmsg.Reject
				}
				return ctrlmsg.Accept
			}
		}
		if noPull {
			name, _, _ := strings.Cut(strings.TrimSpace(option), " ")
			if slices.Contains(routeNoPullOptions, name) {
				return ctrlmsg.Ignore
			}
		}
		return ctrlmsg.Accept
	}
}

// routeNoPullOptions are the pushed options that route-nopull does not take: those
// that OpenVPN files under routes and under DNS.
//
// OpenVPN: init.c pull_permission_mask (OPT_P_ROUTE, OPT_P_DHCPDNS).
var routeNoPullOptions = []string{
	"route", "route-ipv6", "route-gateway", "redirect-gateway", "redirect-private",
	"dhcp-option", "dns", "block-outside-dns",
}

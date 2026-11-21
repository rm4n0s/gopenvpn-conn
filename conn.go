// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"context"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/session"
)

// Tags of the errors that a caller may branch on, with errors.FromError and
// the Tag field of the error.
const (
	// TagHandshakeTimeout: the handshake did not finish within
	// Config.HandshakeTimeout. Metadata: "timeout".
	TagHandshakeTimeout = session.TagHandshakeTimeout
	// TagLinkFailed: reading or writing the link to the server failed. The
	// cause (an io.EOF, a closed connection) can be found with errors.Is.
	// Metadata: "op" ("read" or "write").
	TagLinkFailed = session.TagLinkFailed
	// TagKeyExchangeFailed: the connection ended while the key exchange
	// message was written or read. Metadata: "op" ("read" or "write").
	TagKeyExchangeFailed = session.TagKeyExchangeFailed
	// TagCredentialsFailed: Config.Credentials returned an error; the cause can
	// be found with errors.Is.
	TagCredentialsFailed = session.TagCredentialsFailed
	// TagTLSHandshakeFailed: the TLS handshake with the server failed: a
	// certificate that does not verify, a client certificate that the server
	// refuses, no TLS version in common. The cause, a crypto/tls or x509
	// error, can be found with errors.Is and errors.As.
	TagTLSHandshakeFailed = session.TagTLSHandshakeFailed
)

// Conn is one session with a server.
//
// The data channel (Read and Write of IP packets) and the rest of net.Conn come
// with the later steps of the library; so far a Conn completes the TLS
// handshake with the server.
type Conn struct {
	s   *session.Session
	mtu int // the tunnel MTU of the Config, for ConnectionState before the server pushes one
}

// Client makes a Conn over conn, which is a stream (TCP framing). It returns at
// once and starts nothing: the handshake runs at HandshakeContext. The Conn
// takes conn over: Close closes it, and so does the end of the session. A nil
// config is the zero Config.
func Client(conn net.Conn, config *Config) *Conn {
	return newConn(conn, true, config)
}

// PacketClient is Client for a connected datagram socket: each Read and Write
// of conn is one packet.
func PacketClient(conn net.Conn, config *Config) *Conn {
	return newConn(conn, false, config)
}

func newConn(link net.Conn, stream bool, config *Config) *Conn {
	if config == nil {
		config = &Config{}
	}
	opts := session.Options{
		Link: link, Stream: stream, Logger: config.Logger,
		HandshakeTimeout: config.HandshakeTimeout,
		TLS:              config.TLS, ResetOnly: config.resetOnly,
	}
	if err := config.validate(); err != nil {
		opts.Err = err
		return &Conn{s: session.New(opts), mtu: tunnelMTU(config)}
	}
	if config.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if config.ControlWrap == nil {
		opts.Wrapper = ctrlwrap.NewPlain()
	} else {
		w, err := config.ControlWrap.wrapper(time.Now)
		if err != nil {
			opts.Err = err
			return &Conn{s: session.New(opts), mtu: tunnelMTU(config)}
		}
		opts.Wrapper = w
	}
	opts.Options, opts.PeerInfo, opts.Ciphers = keyExchangeStrings(config, link, stream)
	if config.Credentials != nil {
		credentials := config.Credentials
		opts.Credentials = func(ctx context.Context) (string, string, error) {
			c, err := credentials(ctx)
			return c.Username, c.Password, err
		}
	}
	return &Conn{s: session.New(opts), mtu: tunnelMTU(config)}
}

// keyExchangeStrings are the options string and the peer info of the key exchange
// message, made from the Config and the link, and the data ciphers that are offered.
func keyExchangeStrings(config *Config, link net.Conn, stream bool) (options, peerInfo string, ciphers []string) {
	ciphers = defaultDataCiphers
	if len(config.DataCiphers) > 0 {
		ciphers = make([]string, len(config.DataCiphers))
		for i, name := range config.DataCiphers {
			ciphers[i] = strings.ToUpper(name)
		}
	}
	mtu := config.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	options = ctrlmsg.OptionsString(ctrlmsg.OptionsParams{
		Stream: stream, IPv6: isIPv6(link.RemoteAddr()), TunMTU: mtu,
		Cipher: ciphers[0], KeySizeBits: cipherKeyBits[ciphers[0]],
	})
	info := ctrlmsg.PeerInfo{
		Version:  "gopenvpn-conn " + libraryVersion,
		Platform: platform(),
		// The largest MTU the client can take; OpenVPN's own default is 1600.
		MTU:     max(1600, mtu),
		Ciphers: ciphers,
		Proto:   implementedProto,
		UV:      config.PeerInfo,
	}
	return options, info.String(), ciphers
}

// isIPv6 reports whether the link is to an IPv6 address.
func isIPv6(addr net.Addr) bool {
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	}
	return ip != nil && ip.To4() == nil
}

// platform is IV_PLAT: the name OpenVPN gives the system.
func platform() string {
	switch runtime.GOOS {
	case "windows":
		return "win"
	case "darwin":
		return "mac"
	}
	return runtime.GOOS
}

// libraryVersion is what IV_VER says after the name of the library.
const libraryVersion = "0.2.0"

// implementedProto is IV_PROTO: the bits of the features that this client has.
// Each step that adds a feature adds its bit (SPEC §8.2).
const implementedProto = ctrlmsg.IVProtoDataV2 | ctrlmsg.IVProtoRequestPush | ctrlmsg.IVProtoTLSKeyExport

// HandshakeContext runs the handshake if it has not run, and returns when it is
// complete, when it fails, or when ctx is done. A done ctx ends the session: the
// Conn is then unusable and the caller closes it. Calls after the handshake
// returns the same result.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	return c.s.Handshake(ctx)
}

// Close ends the session, closes the connection to the server and waits for the
// goroutines of the Conn. After Close, every method returns net.ErrClosed.
func (c *Conn) Close() error {
	return c.s.Close()
}

// LocalAddr is the local address of the link to the server.
func (c *Conn) LocalAddr() net.Addr { return c.s.Link().LocalAddr() }

// RemoteAddr is the address of the server on the link.
func (c *Conn) RemoteAddr() net.Addr { return c.s.Link().RemoteAddr() }

// NetConn returns the connection to the server that was given to Client or
// PacketClient. Reading or writing it breaks the session.
func (c *Conn) NetConn() net.Conn { return c.s.Link() }

// tunnelMTU is the MTU of the Config, or the default.
func tunnelMTU(config *Config) int {
	if config.MTU == 0 {
		return DefaultMTU
	}
	return config.MTU
}

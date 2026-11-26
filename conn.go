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
	"github.com/rm4n0s/gopenvpn-conn/internal/datachan"
	"github.com/rm4n0s/gopenvpn-conn/internal/mss"
	"github.com/rm4n0s/gopenvpn-conn/internal/session"
)

// Tags of the errors that a caller may branch on, with errors.FromError and
// the Tag field of the error.
const (
	// TagHandshakeTimeout: the handshake did not finish within
	// Config.HandshakeTimeout. Metadata: "timeout".
	TagHandshakeTimeout = session.TagHandshakeTimeout
	// TagServerPollTimeout: no packet of the server came within
	// Config.ServerPollTimeout: the server is not there, or a firewall drops the
	// packets. Metadata: "timeout".
	TagServerPollTimeout = session.TagServerPollTimeout
	// TagLinkFailed: reading or writing the link to the server failed. The
	// cause (an io.EOF, a closed connection) can be found with errors.Is.
	// Metadata: "op" ("read" or "write").
	TagLinkFailed = session.TagLinkFailed
	// TagAuthFailed: the server refused the credentials (AUTH_FAILED). Metadata:
	// "reason" (the server's text), "session" (the form "SESSION:", a token
	// that has expired), "temporary" (the form "TEMP": try again later),
	// "backoff" (seconds the server asks to wait), "advance" ("no", "remote",
	// "addr" or "": what it says about the next server).
	TagAuthFailed = session.TagAuthFailed
	// TagServerHalt: the server told the client to stop (HALT). Metadata: "reason".
	TagServerHalt = session.TagServerHalt
	// TagServerRestart: the server asked the client to connect again (RESTART).
	// Metadata: "reason", "flags" (P keeps the credentials, N goes to the next server).
	TagServerRestart = session.TagServerRestart
	// TagKeyExchangeFailed: the connection ended while the key exchange
	// message was written or read. Metadata: "op" ("read" or "write").
	TagKeyExchangeFailed = session.TagKeyExchangeFailed
	// TagCredentialsFailed: Config.Credentials returned an error; the cause can
	// be found with errors.Is.
	TagCredentialsFailed = session.TagCredentialsFailed
	// TagKeyExchangeTooLong: the user name and the password that Config.Credentials
	// returned do not fit, with the peer info, in the one message of 2048 bytes
	// that a server reads. Nothing of them was sent. Metadata: "length", "max".
	TagKeyExchangeTooLong = ctrlmsg.TagKeyExchangeTooLong
	// TagTLSHandshakeFailed: the TLS handshake with the server failed: a
	// certificate that does not verify, a client certificate that the server
	// refuses, no TLS version in common. The cause, a crypto/tls or x509
	// error, can be found with errors.Is and errors.As.
	TagTLSHandshakeFailed = session.TagTLSHandshakeFailed
	// TagKeyDerivationUnsupported: the server did not ask for the keys of the TLS
	// exporter (key-derivation tls-ekm), the only derivation this library has.
	// Metadata: "key_derivation".
	TagKeyDerivationUnsupported = session.TagKeyDerivationUnsupported
	// TagKeyExportFailed: the TLS session could not export the key material of the
	// data channel (a TLS 1.2 session without the extended master secret); the
	// cause is the crypto/tls error.
	TagKeyExportFailed = session.TagKeyExportFailed
	// TagPacketTooLarge: Write got a packet larger than the MTU of the tunnel.
	// Metadata: "len" and "mtu".
	TagPacketTooLarge = session.TagPacketTooLarge
	// TagPingTimeout: nothing authentic arrived from the server for PingTimeout (the
	// pushed ping-restart, else Config.PingTimeout): the server or the path to it is
	// gone. Metadata: "timeout".
	TagPingTimeout = session.TagPingTimeout
	// TagServerExit: the server said EXIT before the handshake was complete. After
	// it, the same message ends the session with io.EOF from Read (SPEC §5.3).
	TagServerExit = session.TagServerExit
	// TagPacketIDExhausted: every packet id of the data key was used (4 billion
	// packets), and the session ended rather than repeat a nonce: the last resort
	// of the rule of SPEC §10.
	TagPacketIDExhausted = datachan.TagPacketIDExhausted
)

// Conn is one session with a server and a net.Conn of IP packets: Read returns one
// IP packet that the server sent, and Write sends one (SPEC §5.1).
//
// The error that ends a Conn is one value: every later call returns that same
// error, to every goroutine, and its route begins at the call that started the
// session (Dial, HandshakeContext, or a first Read or Write). It is shared, so a
// program must not change it (SetMetadata) (SPEC §14.2).
type Conn struct {
	s   *session.Session
	mtu int // the tunnel MTU of the Config, for ConnectionState before the server pushes one
}

// Client makes a Conn over conn, which is a stream (TCP framing). It returns at
// once and starts nothing: the handshake runs at HandshakeContext. The Conn
// takes conn over: Close closes it, and so does the end of the session. A nil
// config is the zero Config.
func Client(conn net.Conn, config *Config) *Conn {
	return newConn(conn, true, config, 0)
}

// PacketClient is Client for a connected datagram socket: each Read and Write
// of conn is one packet.
func PacketClient(conn net.Conn, config *Config) *Conn {
	return newConn(conn, false, config, 0)
}

// newConn makes a Conn over link. poll, when it is not zero, is what is left of
// Config.ServerPollTimeout after Dial made the link.
func newConn(link net.Conn, stream bool, config *Config, poll time.Duration) *Conn {
	if config == nil {
		config = &Config{}
	}
	if poll == 0 {
		poll = config.ServerPollTimeout
	}
	opts := session.Options{
		Link: link, Stream: stream, Logger: config.Logger,
		HandshakeTimeout: config.HandshakeTimeout, ServerPollTimeout: poll,
		TLS: config.TLS, ResetOnly: config.resetOnly, MTU: tunnelMTU(config), EpochUsageLimit: config.epochUsageLimit,
		PingInterval: config.PingInterval, PingTimeout: config.PingTimeout,
		RenegotiateAfter: renegotiateAfter(config), RetransmitTimeout: config.RetransmitTimeout,
		PullFilter: config.pullFilter(), AuthNoCache: config.AuthNoCache,
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
	opts.MSSFix = mssSettings(config, link, stream)
	if config.Credentials != nil {
		credentials := config.Credentials
		opts.Credentials = func(ctx context.Context) (string, string, error) {
			c, err := credentials(ctx)
			return c.Username, c.Password, err
		}
	}
	return &Conn{s: session.New(opts), mtu: tunnelMTU(config)}
}

// renegotiateAfter is the time after which a key is replaced: the default for zero,
// none (zero to the session) for a negative value.
func renegotiateAfter(config *Config) time.Duration {
	switch {
	case config.RenegotiateAfter < 0:
		return 0
	case config.RenegotiateAfter == 0:
		return DefaultRenegotiateAfter
	}
	return config.RenegotiateAfter
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
	proto := implementedProto
	if config.noEpoch {
		proto &^= ctrlmsg.IVProtoDataEpoch
	}
	if config.noCCExit {
		proto &^= ctrlmsg.IVProtoCCExitNotify
	}
	info := ctrlmsg.PeerInfo{
		Version:  "gopenvpn-conn " + libraryVersion,
		Platform: platform(),
		// The largest MTU the client can take; OpenVPN's own default is 1600.
		MTU:     max(1600, mtu),
		Ciphers: ciphers,
		Proto:   proto,
		UV:      config.PeerInfo,
	}
	return options, info.String(), ciphers
}

// mssSettings is how the session makes the largest MSS of a SYN: the size and
// mode of the Config, or OpenVPN's default for the MTU when the size is zero, and
// the headers of the link when the size counts them.
//
// OpenVPN: options.c options_postprocess_mutate_ce (the default of mssfix),
// mss.c get_ip_encap_overhead, socket_util.h datagram_overhead.
func mssSettings(config *Config, link net.Conn, stream bool) mss.Settings {
	size, mode := config.MSSFix, config.MSSFixMode
	switch {
	case size < 0:
		return mss.Settings{}
	case size == 0 && tunnelMTU(config) != DefaultMTU:
		// Another MTU already makes the packets smaller: only the tunnel's MTU
		// is applied.
		size, mode = tunnelMTU(config), MSSFixFixed
	case size == 0:
		size = defaultMSSFix
		if mode != MSSFixFixed {
			mode = MSSFixMTU
		}
	}
	s := mss.Settings{Size: size, Fixed: mode == MSSFixFixed}
	if mode == MSSFixMTU {
		s.Encap = 8 // UDP
		if stream {
			s.Encap = 20 // TCP
		}
		if isIPv6(link.RemoteAddr()) {
			s.Encap += 40
		} else {
			s.Encap += 20
		}
	}
	return s
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
const implementedProto = ctrlmsg.IVProtoDataV2 | ctrlmsg.IVProtoRequestPush | ctrlmsg.IVProtoTLSKeyExport |
	ctrlmsg.IVProtoAuthPendingKW | ctrlmsg.IVProtoAuthFailTemp | ctrlmsg.IVProtoDynTLSCrypt | ctrlmsg.IVProtoDataEpoch | ctrlmsg.IVProtoCCExitNotify

// Read returns the next IP packet that the server sent, waiting for it, as one
// Read of a connected UDP socket does: a buffer that is too small gets the start
// of the packet and the rest is dropped (ConnectionState().MTU is always enough).
// It runs the handshake first when that has not run. When the session ends, Read
// returns the error that ended it.
func (c *Conn) Read(b []byte) (int, error) { return c.s.Read(b) }

// Write sends one IP packet to the server. It runs the handshake first when that
// has not run. A packet larger than ConnectionState().MTU is an error
// (TagPacketTooLarge). A nil error does not mean that the packet arrived: the
// data channel does not guarantee it.
func (c *Conn) Write(b []byte) (int, error) { return c.s.Write(b) }

// SetDeadline sets the read and write deadlines of the connection, as net.Conn says:
// a Read or Write that is waiting or comes later returns os.ErrDeadlineExceeded
// (that value, a net.Error whose Timeout is true) when the time has passed, a time
// in the past unblocks the calls that are waiting, and the zero time is no deadline.
// The deadlines bound the wait for a packet and for the link, not the handshake that
// a first Read or Write may start (HandshakeTimeout does). After Close it returns
// net.ErrClosed.
func (c *Conn) SetDeadline(t time.Time) error { return c.s.SetDeadline(t) }

// SetReadDeadline sets the deadline of Read; see SetDeadline.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.s.SetReadDeadline(t) }

// SetWriteDeadline sets the deadline of Write; see SetDeadline.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.s.SetWriteDeadline(t) }

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

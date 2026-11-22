// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl.c and ssl_pkt.c (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package session

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/datachan"
	"github.com/rm4n0s/gopenvpn-conn/internal/mss"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// maxControlMessage is the longest control message, with its NUL, that is
// waited for: a message is one TLS record of 16 KB at most in OpenVPN, and a
// PUSH_REPLY that is longer comes in parts.
const maxControlMessage = 1 << 16

// maxAuthPending is the longest that AUTH_PENDING may stretch the handshake, when
// that is more than HandshakeTimeout: OpenVPN allows half of its renegotiation
// time (an hour by default).
const maxAuthPending = 30 * time.Minute

// pushRequestInterval is how often PUSH_REQUEST is sent until the server's
// reply is complete: OpenVPN sends it every 5 seconds.
const pushRequestInterval = 5 * time.Second

// DefaultRetransmitTimeout is the first wait before a control packet that is not
// acknowledged is sent again: OpenVPN's --tls-timeout.
const DefaultRetransmitTimeout = 2 * time.Second

// DefaultTransitionWindow is how long an old key stays valid after the renegotiation
// began: OpenVPN's --tran-window.
const DefaultTransitionWindow = time.Hour

// maxPacket is the size of the buffer that reads the link: the largest UDP
// datagram and the largest TCP frame.
const maxPacket = 1 << 16

// inQueue is how many packets wait between the reader and the loop, so that a
// loop that is writing does not stop the reader at once.
const inQueue = 128

// Options are what a Session needs. Link, Wrapper and HandshakeTimeout are required.
type Options struct {
	// Link is the connection to the server. The Session takes it over: it
	// closes it when the session fails and when Close is called.
	Link net.Conn
	// Stream is true when Link is a stream (TCP framing), false when each Read
	// and Write is one packet.
	Stream bool
	// Wrapper is the control channel protection. If it is a
	// ctrlwrap.WKCWrapper the client starts with CONTROL_HARD_RESET_CLIENT_V3.
	Wrapper ctrlwrap.Wrapper
	// HandshakeTimeout is how long the handshake may take.
	HandshakeTimeout time.Duration
	// ServerPollTimeout is how long to wait for the first packet of the server;
	// zero is no limit but HandshakeTimeout.
	ServerPollTimeout time.Duration
	// RetransmitTimeout is the first wait before a packet is sent again;
	// DefaultRetransmitTimeout when zero.
	RetransmitTimeout time.Duration
	// Logger gets the events of the session; nil means no logs.
	Logger *slog.Logger
	// TLS is the configuration of the TLS client that runs over the control
	// channel. It is cloned; a MinVersion below TLS 1.2 is raised to it and the
	// dynamic record sizing is turned off (a message is one record).
	// It is required unless ResetOnly is set.
	TLS *tls.Config
	// Options is the options string and PeerInfo the peer info of the key exchange
	// message (package ctrlmsg makes both). Credentials, when set, gives the user
	// name and password for it; it is called once, with a context that ends with
	// the session. Not used with ResetOnly.
	Options     string
	PeerInfo    string
	Credentials func(ctx context.Context) (username, password string, err error)
	// Ciphers are the data ciphers the client offered, in capitals; a cipher
	// that the server pushes must be one of them. The default is the usual three.
	Ciphers []string
	// MTU is the tunnel MTU when the server pushes none; 1500 when zero.
	MTU int
	// MSSFix is how the largest MSS of the TCP SYNs in the tunnel is made; the
	// zero value turns the clamp off (SPEC §10).
	MSSFix mss.Settings
	// PingInterval and PingTimeout are the keepalive when the server pushes none:
	// the idle time after which a ping is sent, and the silence after which the
	// session ends. Zero is off.
	PingInterval, PingTimeout time.Duration
	// AuthNoCache makes the session forget the user name and password after the
	// first key exchange: a renegotiation without an auth token calls Credentials
	// again (OpenVPN's --auth-nocache).
	AuthNoCache bool
	// PullFilter, when set, decides about each option that the server pushes
	// (accept, ignore or reject); nil accepts all.
	PullFilter func(option string) ctrlmsg.Verdict
	// RenegotiateAfter is how long a key is used before the client makes a new one
	// (OpenVPN's --reneg-sec). Zero or negative means the client never starts a
	// renegotiation by time; it still answers the server's, and still starts one
	// when the data channel asks for it (the packet ids, the AEAD usage limit).
	RenegotiateAfter time.Duration
	// EpochUsageLimit replaces the usage limit of the keys of the epoch data
	// format, and UsageLimit the one of the keys of the format with 32-bit packet
	// ids. Only the tests set them.
	EpochUsageLimit, UsageLimit uint64
	// PromoteDelay is how long after a new key is made the client starts to send
	// with it (the new key is used to open packets at once). Zero means the smaller
	// of HandshakeTimeout and half of RenegotiateAfter, or HandshakeTimeout when
	// RenegotiateAfter is not set; for the tests it can be anything, even negative,
	// which means no delay.
	PromoteDelay time.Duration
	// TransitionWindow is how long an old key stays valid after the renegotiation
	// began (OpenVPN's --tran-window); zero means DefaultTransitionWindow.
	TransitionWindow time.Duration
	// ResetOnly makes the handshake end with the exchange of resets, with no
	// TLS: for the tests of that exchange.
	ResetOnly bool
	// Err, when set, is the error of a session that cannot start (the caller
	// could not make its options). Only Link is needed then: Handshake returns
	// Err, and Close closes the link.
	Err error
}

// Session is one connection to a server, from the client's side.
type Session struct {
	opts    Options
	log     *slog.Logger
	sid     wire.SessionID // ours
	resetOp wire.Opcode
	dropped atomic.Uint64

	mu       sync.Mutex
	started  bool
	closed   bool
	err      error         // the error that ended the session
	closeErr error         // what closing the link returned
	done     chan struct{} // closed when err is set
	ready    chan struct{} // closed when the handshake is complete
	wg       sync.WaitGroup

	in           chan *packetBuf // from the reader to the loop
	pool         bufPool         // the buffers of the data packets
	readErr      chan error
	out          chan outMsg   // from the TLS sessions to the loop: what crypto/tls wrote
	events       chan keyEvent // from the TLS sessions of the renegotiations to the loop
	ks0          *keyState     // the control channel of key id 0
	tlsReady     chan struct{} // closed when the TLS handshake is complete
	tlsConn      *tls.Conn     // the TLS session of key id 0; set before tlsReady is closed
	tlsCfg       *tls.Config
	ctx          context.Context // ends with the session
	cancel       context.CancelFunc
	serverKX     *ctrlmsg.ServerKeyExchange       // set before tlsReady is closed
	pushed       *ctrlmsg.Pushed                  // set before tlsReady is closed
	pushDone     chan struct{}                    // closed when the push reply is complete
	dyn          atomic.Pointer[ctrlwrap.Wrapper] // the protection of the renegotiations (dynamic tls-crypt), or nil; the TLS goroutine of the first key sets it, the loop reads it for any packet of another key id
	user         string                           // the credentials of the key exchange of key id 0, kept for the renegotiations, as OpenVPN keeps them
	pass         string                           // a secret: never logged
	token        string                           // the auth token that the server pushed, the password of a renegotiation; guarded by mu; a secret
	tokenUser    string                           // its user name, base64, or ""; guarded by mu
	ctlTLS       atomic.Pointer[tls.Conn]         // the TLS session of the newest key: what EXIT is written to
	needKey      atomic.Int32                     // 1 + the key id whose data channel asked for a renegotiation, or 0
	extend       chan struct{}                    // from the control reader to the loop: extendAt has a later end for the handshake
	extendAt     time.Time                        // the latest end that AUTH_PENDING asked for; guarded by mu
	began        time.Time                        // when the handshake began
	data         atomic.Pointer[dataPath]         // the data channel, set before tlsReady is closed
	closing      atomic.Bool                      // Close was called
	ccExit       bool                             // the server pushed cc-exit; set before tlsReady is closed
	exitSent     atomic.Bool                      // the EXIT message is written: the loop watches for its acknowledgement
	rekey        atomic.Pointer[chan struct{}]    // a renegotiation is under way: the loop closes the channel when its key is made, and EXIT waits for that
	wake         chan struct{}                    // wakes the loop to look at what Close changed
	drained      chan struct{}                    // closed by the loop when everything it sent is acknowledged, after EXIT
	rdl, wdl     *deadline                        // the read and write deadlines of the connection
	linkSem      chan struct{}                    // holds a token while a writer has the link: one at a time
	ctl          chan []byte                      // from the loop to the writer of the link: control packets and pings
	ctlDone      chan struct{}                    // closed when the writer of the link has returned
	loopDone     chan struct{}                    // closed when the loop has returned
	wmu          sync.Mutex                       // guards userWriting, linkDeadline and the write deadline of the link
	userWriting  bool                             // a Write of the connection is writing to the link
	linkDeadline bool                             // the link has a write deadline that is to be cleared
	sawServer    atomic.Bool                      // a packet of the server was taken: the server is there
	wfailSince   atomic.Int64                     // since when every write of the datagram link fails, as time since base; 0 when the last one worked
	kaTimeoutNs  atomic.Int64                     // the keepalive timeout, for the writers; 0 when there is none
	base         time.Time                        // the zero of sentAt
	sentAt       atomic.Int64                     // when a packet last went to the link, as time since base
	recv         chan *packetBuf                  // decrypted IP packets for Read
	wkcLen       int                              // the wrapped key that CONTROL_WKC_V1 carries, or 0

	// Owned by the loop goroutine.
	keys          [datachan.MaxKeyID + 1]*keyState // the control channels, by key id
	primary, lame *keyState                        // the newest key (still being made, or made) and the one before it
	dirty         bool                             // the keys changed: the table is to be published again
	nextID        uint8                            // the key id of the next renegotiation
	attemptEnd    time.Time                        // when a renegotiation that is not done is given up
	sendAt        time.Time                        // when the newest key is to be sent with, zero if it is
	remote        wire.SessionID                   // the server's
	haveRemote    bool
	lastRecv      time.Time // when something authentic last came from the server
	kaInterval    time.Duration
	kaTimeout     time.Duration
	kaOn          bool // the keepalive runs: the handshake is complete
	drainedClosed bool // drained is closed
	body, packet  []byte
}

// New makes a Session. It starts nothing: the first Handshake does. It panics
// when a required option is missing, as that is a mistake in the caller.
func New(opts Options) *Session {
	if opts.Link == nil || (opts.Err == nil && (opts.Wrapper == nil || opts.HandshakeTimeout <= 0 || (opts.TLS == nil && !opts.ResetOnly))) {
		panic("session: Link, Wrapper, HandshakeTimeout and TLS (unless ResetOnly) are required")
	}
	if len(opts.Ciphers) == 0 {
		opts.Ciphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	}
	if opts.RetransmitTimeout <= 0 {
		opts.RetransmitTimeout = DefaultRetransmitTimeout
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = time.Minute // not used: the session cannot start
	}
	s := &Session{
		opts:     opts,
		log:      opts.Logger,
		sid:      wire.RandomSessionID(),
		resetOp:  wire.HardResetClientV2,
		done:     make(chan struct{}),
		ready:    make(chan struct{}),
		in:       make(chan *packetBuf, inQueue),
		readErr:  make(chan error, 1),
		recv:     make(chan *packetBuf, recvQueue),
		base:     time.Now(),
		rdl:      newDeadline(),
		drained:  make(chan struct{}),
		wake:     make(chan struct{}, 1),
		linkSem:  make(chan struct{}, 1),
		ctl:      make(chan []byte, ctlQueue),
		ctlDone:  make(chan struct{}),
		loopDone: make(chan struct{}),
		wdl:      newDeadline(),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if w, ok := opts.Wrapper.(ctrlwrap.WKCWrapper); ok {
		s.resetOp = wire.HardResetClientV3
		s.wkcLen = w.WKcLen()
	}
	if opts.TLS != nil {
		s.tlsCfg = opts.TLS.Clone()
		if s.tlsCfg.MinVersion < tls.VersionTLS12 {
			s.tlsCfg.MinVersion = tls.VersionTLS12
		}
		// One message is one TLS record. crypto/tls cuts the first writes of a
		// connection into records of about 1200 bytes (for TCP's sake), and OpenVPN
		// reads one record at a time into its message buffer: of a key exchange
		// message in two records the server reads the first, finds a password that
		// ends too early and answers AUTH_FAILED.
		//
		// OpenVPN: ssl.c key_state_read_plaintext. Observed: SPEC §21 O33.
		s.tlsCfg.DynamicRecordSizingDisabled = true
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.out = make(chan outMsg)
	s.events = make(chan keyEvent)
	s.nextID = 1
	s.tlsReady = make(chan struct{})
	s.pushDone = make(chan struct{})
	s.extend = make(chan struct{}, 1)
	if opts.Wrapper != nil {
		s.ks0 = s.newKeyState(0, opts.Wrapper)
		s.keys[0], s.primary = s.ks0, s.ks0
	}
	if opts.Err != nil {
		s.err = opts.Err
		close(s.done)
		s.cancel()
	}
	return s
}

// Handshake starts the session if it is not started, and waits until the
// handshake is complete, the session has failed, or ctx is done. A done ctx ends
// the session: the error is kept, and the caller closes the Session. After
// Close it returns net.ErrClosed.
func (s *Session) Handshake(ctx context.Context) error {
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		return net.ErrClosed
	case s.err != nil:
		err := s.err
		s.mu.Unlock()
		return err
	}
	if !s.started {
		s.start()
	}
	s.mu.Unlock()

	// A handshake that is complete is the result, whatever ctx says: a call with a ctx
	// that is done must not end a session that is up (as tls.Conn's does not).
	select {
	case <-s.ready:
		return nil
	default:
	}
	select {
	case <-s.ready:
		return nil
	case <-s.done:
		select {
		case <-s.ready:
			return nil
		default:
		}
	case <-ctx.Done():
		select {
		case <-s.ready: // it became complete at the same moment
			return nil
		default:
		}
		s.fail(errors.NewErr(tagHandshakeCanceled, ctx.Err()))
	}
	return s.result()
}

// result is the error that ended the session, or net.ErrClosed after Close.
func (s *Session) result() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	return s.err
}

// start launches the goroutines. The caller holds s.mu.
func (s *Session) start() {
	s.started = true
	s.began = time.Now()
	s.wg.Add(3)
	go s.readLoop()
	go s.loop()
	go s.writeLoop()
	if !s.opts.ResetOnly {
		s.wg.Add(1)
		go s.tlsMain(s.ks0)
	}
}

// Pushed is what the server pushed once the handshake is complete, and nil
// before.
func (s *Session) Pushed() *ctrlmsg.Pushed {
	select {
	case <-s.tlsReady:
		return s.pushed
	default:
		return nil
	}
}

// ServerKeyExchange is the server's key exchange message once the handshake is
// complete, and nil before.
func (s *Session) ServerKeyExchange() *ctrlmsg.ServerKeyExchange {
	select {
	case <-s.tlsReady:
		return s.serverKX
	default:
		return nil
	}
}

// TLS is the TLS connection of the control channel once the handshake is
// complete, and nil before.
func (s *Session) TLS() *tls.Conn {
	select {
	case <-s.tlsReady:
		return s.tlsConn
	default:
		return nil
	}
}

// fail ends the session with err, unless it has ended already. It does not wait
// for the goroutines: the loop sees done, closes the link and returns.
func (s *Session) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	s.err = err
	close(s.done)
	s.cancel()
}

// exitWait is how long Close waits for the server to acknowledge the EXIT message:
// it must not hang on a server that is gone.
const exitWait = time.Second

// Close ends the session, closes the link and waits for the goroutines. When the
// handshake is complete and the session is up it first tells the server: the EXIT
// message of the control channel when the server pushed cc-exit (waiting up to
// exitWait for its acknowledgement), else, over a datagram link, the exit message of
// the data channel. It returns net.ErrClosed when it was called before, even while
// the first call is still waiting. After a failure it still returns the error of
// closing the link, if any.
func (s *Session) Close() error {
	if !s.closing.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	select {
	case <-s.ready:
		if s.Err() == nil {
			s.goodbye()
		}
	default:
	}

	s.mu.Lock()
	s.closed = true
	if s.err == nil {
		s.err = net.ErrClosed
		close(s.done)
		s.cancel()
	}
	started := s.started
	s.mu.Unlock()

	if !started {
		if err := s.opts.Link.Close(); err != nil {
			return errors.NewErr(tagLinkCloseFailed, err)
		}
		return nil
	}
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

// SetReadDeadline, SetWriteDeadline and SetDeadline are the deadlines of net.Conn:
// a Read or Write that is waiting, or comes later, gives os.ErrDeadlineExceeded when
// the time has passed, and the zero time turns the deadline off. After Close they
// return net.ErrClosed.
func (s *Session) SetReadDeadline(t time.Time) error {
	if s.closing.Load() {
		return net.ErrClosed
	}
	s.rdl.set(t)
	return nil
}

// SetWriteDeadline is the deadline of Write; see SetReadDeadline.
func (s *Session) SetWriteDeadline(t time.Time) error {
	if s.closing.Load() {
		return net.ErrClosed
	}
	s.setWriteDeadline(t)
	return nil
}

// SetDeadline sets both deadlines; see SetReadDeadline.
func (s *Session) SetDeadline(t time.Time) error {
	if s.closing.Load() {
		return net.ErrClosed
	}
	s.rdl.set(t)
	s.setWriteDeadline(t)
	return nil
}

// Done is closed when the session has ended, by a failure or by Close.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err is the error that ended the session, or nil while it lives. After Close it
// is net.ErrClosed.
func (s *Session) Err() error {
	select {
	case <-s.done:
		return s.result()
	default:
		return nil
	}
}

// Link is the connection to the server.
func (s *Session) Link() net.Conn { return s.opts.Link }

// SawServer reports whether a packet of the server was taken: a server is at the
// other end of the link, whatever happened after.
func (s *Session) SawServer() bool { return s.sawServer.Load() }

// Dropped is how many packets were dropped: too short, with a bad protection,
// from another session, or of no use at this point of the handshake.
func (s *Session) Dropped() uint64 { return s.dropped.Load() }

const (
	tagControlMessageTooLong = "ControlMessageTooLong"

	// TagHandshakeTimeout: the handshake did not finish within HandshakeTimeout.
	TagHandshakeTimeout = "HandshakeTimeout"
	// TagServerPollTimeout: no packet of the server came within ServerPollTimeout.
	// Metadata: "timeout".
	TagServerPollTimeout = "ServerPollTimeout"
	// TagLinkFailed: reading or writing the link failed.
	TagLinkFailed = "LinkFailed"

	// TagTLSHandshakeFailed: the TLS handshake with the server failed (a
	// certificate that does not verify, a client certificate that the server
	// refuses, a version that is not shared). The cause, a crypto/tls or
	// x509 error, can be found with errors.Is and errors.As.
	TagTLSHandshakeFailed = "TLSHandshakeFailed"

	// TagKeyExchangeFailed: reading or writing the key exchange message failed
	// (the connection ended in the middle of it). A message that was read and
	// is not valid has its own tag. Metadata: "op" ("read" or "write").
	TagKeyExchangeFailed = "KeyExchangeFailed"
	// TagAuthFailed: the server refused the credentials with AUTH_FAILED.
	// Metadata: "reason" (the server's text), "session" (the form
	// "SESSION:"), "temporary" (the form "TEMP"), "backoff" (seconds), "advance"
	// ("no", "remote", "addr" or "").
	TagAuthFailed = "AuthFailed"
	// TagServerHalt: the server sent HALT. Metadata: "reason".
	TagServerHalt = "ServerHalt"
	// TagServerRestart: the server sent RESTART. Metadata: "reason", "flags".
	TagServerRestart = "ServerRestart"
	// TagPingTimeout: nothing authentic arrived from the server for the keepalive
	// timeout. Metadata: "timeout" (the duration).
	TagPingTimeout = "PingTimeout"
	// TagControlChannelFailed: reading or writing the control channel failed
	// after the key exchange (the server ended the TLS session, or the
	// connection broke). Metadata: "op" ("read" or "write").
	TagControlChannelFailed = "ControlChannelFailed"
	// TagRenegotiationFailed: a renegotiation did not finish in time (metadata:
	// "key_id", "timeout"), or the key that is in use reached the end of its life and
	// no new one was made (metadata: "key_id"). The session has ended; the caller dials
	// again. A renegotiation that fails for a reason of its own (the TLS handshake, the
	// credentials) ends the session with that error.
	TagRenegotiationFailed = "RenegotiationFailed"
	// TagCredentialsFailed: the function that gives the user name and password
	// returned an error. The cause can be found with errors.Is.
	TagCredentialsFailed = "CredentialsFailed"

	tagHandshakeCanceled = "HandshakeCanceled"
	tagLinkCloseFailed   = "LinkCloseFailed"
)

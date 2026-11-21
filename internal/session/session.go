// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl.c and ssl_pkt.c (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package session

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/reliable"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// DefaultRetransmitTimeout is the first wait before a control packet that is not
// acknowledged is sent again: OpenVPN's --tls-timeout.
const DefaultRetransmitTimeout = 2 * time.Second

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
	// RetransmitTimeout is the first wait before a packet is sent again;
	// DefaultRetransmitTimeout when zero.
	RetransmitTimeout time.Duration
	// Logger gets the events of the session; nil means no logs.
	Logger *slog.Logger
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

	in      chan []byte // from the reader to the loop
	readErr chan error

	// Owned by the loop goroutine.
	sender          *reliable.Sender
	receiver        reliable.Receiver
	remote          wire.SessionID // the server's
	haveRemote      bool
	serverResetSeen bool
	wkcAsked        bool // the server's reset asked for the wrapped key again
	wkcQueued       bool
	thirdSent       bool // an acknowledgement of the server's reset went out
	body, packet    []byte
}

// New makes a Session. It starts nothing: the first Handshake does. It panics
// when a required option is missing, as that is a mistake in the caller.
func New(opts Options) *Session {
	if opts.Link == nil || (opts.Err == nil && (opts.Wrapper == nil || opts.HandshakeTimeout <= 0)) {
		panic("session: Link, Wrapper and HandshakeTimeout are required")
	}
	if opts.RetransmitTimeout <= 0 {
		opts.RetransmitTimeout = DefaultRetransmitTimeout
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = time.Minute // not used: the session cannot start
	}
	s := &Session{
		opts:    opts,
		log:     opts.Logger,
		sid:     wire.RandomSessionID(),
		resetOp: wire.HardResetClientV2,
		done:    make(chan struct{}),
		ready:   make(chan struct{}),
		in:      make(chan []byte, inQueue),
		readErr: make(chan error, 1),
		sender:  reliable.NewSender(opts.RetransmitTimeout),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if _, ok := opts.Wrapper.(ctrlwrap.WKCWrapper); ok {
		s.resetOp = wire.HardResetClientV3
	}
	if opts.Err != nil {
		s.err = opts.Err
		close(s.done)
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

	select {
	case <-s.ready:
		return nil
	case <-s.done:
	case <-ctx.Done():
		s.fail(errors.NewErr(tagHandshakeCanceled, ctx.Err()))
	}
	select {
	case <-s.ready:
		return nil
	default:
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
	s.wg.Add(2)
	go s.readLoop()
	go s.loop()
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
}

// Close ends the session, closes the link and waits for the goroutines. It
// returns net.ErrClosed when it was called before. After a failure it still
// returns the error of closing the link, if any.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.closed = true
	if s.err == nil {
		s.err = net.ErrClosed
		close(s.done)
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

// Link is the connection to the server.
func (s *Session) Link() net.Conn { return s.opts.Link }

// Dropped is how many packets were dropped: too short, with a bad protection,
// from another session, or of no use at this point of the handshake.
func (s *Session) Dropped() uint64 { return s.dropped.Load() }

const (
	// TagHandshakeTimeout: the handshake did not finish within HandshakeTimeout.
	TagHandshakeTimeout = "HandshakeTimeout"
	// TagLinkFailed: reading or writing the link failed.
	TagLinkFailed = "LinkFailed"

	tagHandshakeCanceled = "HandshakeCanceled"
	tagLinkCloseFailed   = "LinkCloseFailed"
)

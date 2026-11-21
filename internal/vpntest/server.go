// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/reliable"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// Fault makes the server misbehave.
type Fault int

const (
	// NoFault is a server that behaves.
	NoFault Fault = iota
	// Silent reads every packet and answers none.
	Silent
	// WrongAckSessionID acknowledges the client's packets with a session id
	// that is not the client's.
	WrongAckSessionID
)

// ServerOptions say how the server end is set up.
type ServerOptions struct {
	// Stream is true when the link is a stream (TCP framing).
	Stream bool
	// Wrapper is the server end of the control channel protection: the one
	// that sends with the keys that the client receives with. Nil is no
	// protection.
	Wrapper ctrlwrap.Wrapper
	// WKcLen is the length of the wrapped key that a tls-crypt-v2 client
	// appends to CONTROL_HARD_RESET_CLIENT_V3 and CONTROL_WKC_V1 packets. The
	// server strips it before it unwraps the packet; it does not check it.
	WKcLen int
	// AskForWKc makes the server's reset ask the client for its wrapped key
	// again (the early negotiation TLV), when the client sent a V3 reset.
	AskForWKc bool
	// Fault is how the server misbehaves.
	Fault Fault
	// RetransmitTimeout is the first wait before it sends a packet again;
	// 2 seconds when zero.
	RetransmitTimeout time.Duration
}

// Server is the server side of a control channel in the same process. It
// answers the reset of a client, acknowledges what it receives and sends again
// what is not acknowledged. It stops with the test.
type Server struct {
	tb   testing.TB
	opts ServerOptions
	link net.Conn
	sid  wire.SessionID

	mu       sync.Mutex
	received []wire.Control
	dropped  int
	client   wire.SessionID

	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup

	// Owned by the loop goroutine.
	sender     *reliable.Sender
	receiver   reliable.Receiver
	remote     wire.SessionID
	haveRemote bool
	wrapper    ctrlwrap.Wrapper
	sendMu     sync.Mutex // Inject writes from the test's goroutine
}

// NewServer starts a server on link, which it takes over, and stops it when the
// test ends.
func NewServer(tb testing.TB, link net.Conn, opts ServerOptions) *Server {
	tb.Helper()
	if opts.RetransmitTimeout <= 0 {
		opts.RetransmitTimeout = 2 * time.Second
	}
	if opts.Wrapper == nil {
		opts.Wrapper = ctrlwrap.NewPlain()
	}
	s := &Server{
		tb: tb, opts: opts, link: link, sid: wire.RandomSessionID(), wrapper: opts.Wrapper,
		done: make(chan struct{}), sender: reliable.NewSender(opts.RetransmitTimeout),
	}
	in := make(chan []byte, 128) // deep enough that two ends writing a pipe do not wait for each other
	s.wg.Add(2)
	go s.read(in)
	go s.loop(in)
	tb.Cleanup(s.Close)
	return s
}

// Close stops the server and closes the link.
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.done)
		if err := s.link.Close(); err != nil {
			s.tb.Errorf("vpntest server: closing the link: %v", err)
		}
	})
	s.wg.Wait()
}

// SessionID is the server's session id.
func (s *Server) SessionID() wire.SessionID { return s.sid }

// Received is the packets that the server took from the client, that were
// protected right and parsed, in the order of arrival.
func (s *Server) Received() []wire.Control {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]wire.Control(nil), s.received...)
}

// Dropped is how many packets the server dropped.
func (s *Server) Dropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Inject sends a packet of the caller's making to the client, protected the way
// the server protects its own. The caller sets every field, the session id
// included, which lets a test send what a stranger could not (a packet with the
// right protection and the wrong session).
func (s *Server) Inject(c wire.Control) error {
	return s.write(&c)
}

func (s *Server) read(in chan<- []byte) {
	defer s.wg.Done()
	buf := make([]byte, 1<<16)
	var br *bufio.Reader
	if s.opts.Stream {
		br = bufio.NewReader(s.link)
	}
	for {
		var n int
		var err error
		if s.opts.Stream {
			var header [2]byte
			if _, err = io.ReadFull(br, header[:]); err == nil {
				n = int(binary.BigEndian.Uint16(header[:]))
				_, err = io.ReadFull(br, buf[:n])
			}
		} else {
			n, err = s.link.Read(buf)
		}
		if err != nil {
			return
		}
		select {
		case in <- append([]byte(nil), buf[:n]...):
		case <-s.done:
			return
		}
	}
}

func (s *Server) loop(in <-chan []byte) {
	defer s.wg.Done()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		s.flush()
		if at, ok := s.sender.NextDeadline(); ok {
			timer.Reset(max(0, time.Until(at)))
		} else {
			timer.Stop()
		}
		select {
		case <-s.done:
			return
		case raw := <-in:
			s.handle(raw)
		case <-timer.C:
		}
	}
}

func (s *Server) drop() {
	s.mu.Lock()
	s.dropped++
	s.mu.Unlock()
}

func (s *Server) handle(raw []byte) {
	if len(raw) < 1+wire.SessionIDSize {
		s.drop()
		return
	}
	op, keyID := wire.SplitFirstByte(raw[0])
	switch op {
	case wire.HardResetClientV2, wire.HardResetClientV3, wire.ControlV1, wire.ControlWKCV1, wire.AckV1:
	default:
		s.drop()
		return
	}
	packet := raw
	if (op == wire.HardResetClientV3 || op == wire.ControlWKCV1) && s.opts.WKcLen > 0 {
		if len(packet) <= s.opts.WKcLen {
			s.drop()
			return
		}
		packet = packet[:len(packet)-s.opts.WKcLen]
	}
	body, err := s.wrapper.Unwrap(packet)
	if err != nil {
		s.drop()
		return
	}
	c, err := wire.ParseControlBody(op, body)
	if err != nil {
		s.drop()
		return
	}
	c.KeyID = keyID
	copy(c.SessionID[:], raw[1:1+wire.SessionIDSize])

	if s.haveRemote {
		if c.SessionID != s.remote {
			s.drop()
			return
		}
	} else if op != wire.HardResetClientV2 && op != wire.HardResetClientV3 {
		s.drop()
		return
	}
	if len(c.Acks) > 0 && c.RemoteSessionID != s.sid {
		s.drop()
		return
	}
	s.mu.Lock()
	s.received = append(s.received, c)
	s.mu.Unlock()
	if s.opts.Fault == Silent {
		return
	}
	first := !s.haveRemote
	if first {
		s.remote, s.haveRemote = c.SessionID, true
		s.mu.Lock()
		s.client = c.SessionID
		s.mu.Unlock()
	}
	for _, id := range c.Acks {
		s.sender.Ack(id)
	}
	if op == wire.AckV1 {
		return
	}
	if _, ack := s.receiver.Receive(c.PacketID, c.Payload); !ack {
		s.drop()
		return
	}
	if first {
		var payload []byte
		if op == wire.HardResetClientV3 && s.opts.AskForWKc {
			payload = wire.AppendEarlyNegotiation(nil, true)
		}
		if _, err := s.sender.Queue(wire.HardResetServerV2, payload); err != nil {
			s.drop()
		}
	}
}

func (s *Server) flush() {
	for _, o := range s.sender.Due(time.Now()) {
		c := wire.Control{Opcode: o.Opcode, SessionID: s.sid, PacketID: o.ID, Payload: o.Payload}
		s.addAcks(&c)
		s.writeOrReport(&c)
	}
	if s.receiver.HasPendingAcks() {
		c := wire.Control{Opcode: wire.AckV1, SessionID: s.sid}
		s.addAcks(&c)
		s.writeOrReport(&c)
	}
}

// writeOrReport writes a packet. A failure while the server is closing is
// expected; any other fails the test.
func (s *Server) writeOrReport(c *wire.Control) {
	if err := s.write(c); err != nil {
		select {
		case <-s.done:
		default:
			s.tb.Errorf("vpntest server: write: %v", err)
		}
	}
}

func (s *Server) addAcks(c *wire.Control) {
	if !s.haveRemote {
		return
	}
	acks := s.receiver.Acks(wire.MaxAcks)
	if len(acks) == 0 {
		return
	}
	c.Acks = acks
	c.RemoteSessionID = s.remote
	if s.opts.Fault == WrongAckSessionID {
		c.RemoteSessionID = wire.RandomSessionID()
	}
}

func (s *Server) write(c *wire.Control) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	body, err := wire.AppendControlBody(nil, c)
	if err != nil {
		return err
	}
	packet, err := s.wrapper.Wrap(nil, wire.FirstByte(c.Opcode, c.KeyID), c.SessionID, body)
	if err != nil {
		return err
	}
	if s.opts.Stream {
		if packet, err = wire.AppendFrame(nil, packet); err != nil {
			return err
		}
	}
	_, err = s.link.Write(packet)
	return err
}

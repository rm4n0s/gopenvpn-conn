// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

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
	// TLS, when set, makes the server run a TLS server over the control
	// channel with this configuration, and send what it writes as control
	// packets. When nil, the payloads are kept (Payload) and nothing is sent.
	TLS *tls.Config
	// KeyExchangeReply, when set, is what the server sends in answer to the
	// client's key exchange message, in place of a well-formed one. An empty
	// non-nil slice sends nothing.
	KeyExchangeReply []byte
	// EarlyMessages are control messages that the server sends right after the
	// key exchange, before it waits for any PUSH_REQUEST.
	EarlyMessages []string
	// PushMessages are the control messages the server sends after the key
	// exchange, once ReplyAfterRequests requests have come, each in one TLS
	// record. Nil sends one PUSH_REPLY with the usual options of a server; an
	// empty non-nil slice sends nothing.
	PushMessages []string
	// ReplyAfterRequests is how many PUSH_REQUEST messages the server waits for
	// before it sends PushMessages: 0 sends them at once (push before request).
	ReplyAfterRequests int
	// CloseAfterPush makes the server end the TLS session (with its close alert)
	// once it has sent PushMessages.
	CloseAfterPush bool
	// CloseAfterKeyExchange makes the server end the TLS session (with its
	// close alert) once it has answered the key exchange message.
	CloseAfterKeyExchange bool
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

	// The TLS side: crypto/tls runs on tlsEnd, and bridge is the other end of
	// that pipe, which the server's two goroutines carry to and from the packets.
	tlsEnd, bridge net.Conn
	tlsOut         chan []byte // what TLS wrote, to be sent
	tlsIn          chan []byte // what arrived, to be given to TLS
	tlsDone        chan struct{}
	kxDone         chan struct{}
	kx             *ClientKeyExchange
	pushRequests   int
	control        *tls.Conn // the TLS session, once the key exchange is done
	tlsErr         error
	tlsState       tls.ConnectionState
	largest        int // the largest packet that came from the client, as it was on the link

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
	s.tlsDone = make(chan struct{})
	s.kxDone = make(chan struct{})
	if opts.TLS != nil {
		s.tlsEnd, s.bridge = net.Pipe()
		s.tlsOut = make(chan []byte)
		s.tlsIn = make(chan []byte, 1024)
		s.wg.Add(3)
		go s.runTLS()
		go s.bridgeRead()
		go s.bridgeWrite()
	}
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
		if s.tlsEnd != nil {
			// The pipe has no state worth reporting; closing it ends the TLS goroutines.
			if err := s.tlsEnd.Close(); err != nil {
				s.tb.Errorf("vpntest server: closing the TLS side: %v", err)
			}
			if err := s.bridge.Close(); err != nil {
				s.tb.Errorf("vpntest server: closing the bridge: %v", err)
			}
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
		var tlsOut <-chan []byte
		if s.opts.TLS != nil && s.haveRemote && s.sender.CanSend() {
			tlsOut = s.tlsOut
		}
		select {
		case chunk := <-tlsOut:
			s.queueTLS(chunk)
		default:
		}
		s.flush()
		if !s.sender.CanSend() {
			tlsOut = nil // the window is full: take no more until it opens
		}
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
		case chunk := <-tlsOut:
			s.queueTLS(chunk)
		case <-timer.C:
		}
	}
}

// queueTLS sends a chunk of what TLS wrote as a control packet.
func (s *Server) queueTLS(chunk []byte) {
	if _, err := s.sender.Queue(wire.ControlV1, chunk); err != nil {
		s.tb.Errorf("vpntest server: %v", err)
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
	s.largest = max(s.largest, len(raw))
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
	payloads, ack := s.receiver.Receive(c.PacketID, c.Payload)
	if !ack {
		s.drop()
		return
	}
	if first && len(payloads) > 0 {
		payloads = payloads[1:] // the reset has no TLS bytes
	}
	if s.opts.TLS != nil {
		for _, p := range payloads {
			select {
			case s.tlsIn <- p:
			default:
				s.tb.Errorf("vpntest server: more than %d payloads wait for TLS", cap(s.tlsIn))
			}
		}
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

// writeOrReport writes a packet. A failure because the link is closed, by the
// client or by the server's own Close, is expected; any other fails the test.
func (s *Server) writeOrReport(c *wire.Control) {
	err := s.write(c)
	if err == nil || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return
	}
	select {
	case <-s.done:
	default:
		s.tb.Errorf("vpntest server: write: %v", err)
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

// TLSDone is closed when the TLS handshake of the server has ended, in success
// or in failure. It is never closed when the server has no TLS configuration.
func (s *Server) TLSDone() <-chan struct{} { return s.tlsDone }

// TLSResult is the result of the TLS handshake, after TLSDone is closed: the
// state of the connection and the error (nil when it completed).
func (s *Server) TLSResult() (tls.ConnectionState, error) {
	return s.tlsState, s.tlsErr
}

// LargestPacket is the size of the largest packet that came from the client, as
// it was on the link (a datagram, or the packet without its TCP frame).
func (s *Server) LargestPacket() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.largest
}

// runTLS runs crypto/tls as the server over the control channel.
func (s *Server) runTLS() {
	defer s.wg.Done()
	conn := tls.Server(s.tlsEnd, s.opts.TLS)
	err := conn.Handshake()
	select {
	case <-s.done:
		return
	default:
	}
	s.tlsErr = err
	if err == nil {
		s.tlsState = conn.ConnectionState()
	}
	close(s.tlsDone)
	if err == nil {
		s.keyExchange(conn)
	}
}

// keyExchange reads the client's key exchange message, which is one TLS record,
// keeps it, and answers.
func (s *Server) keyExchange(conn *tls.Conn) {
	kxDone := false
	finish := func() {
		if !kxDone {
			kxDone = true
			close(s.kxDone)
		}
	}
	defer finish()
	buf := make([]byte, 1<<15)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	kx, problem := parseClientKX(buf[:n])
	if problem != "" {
		s.tb.Errorf("vpntest server: the client's key exchange message: %s", problem)
		return
	}
	s.mu.Lock()
	s.kx = kx
	s.mu.Unlock()
	reply := s.opts.KeyExchangeReply
	if reply == nil {
		reply = serverKX("V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server", "IV_VER=vpntest\n")
	}
	if len(reply) > 0 {
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
	finish()
	if s.opts.CloseAfterKeyExchange {
		if err := conn.Close(); err != nil {
			s.tb.Logf("vpntest server: closing the TLS session: %v", err)
		}
		return
	}
	if len(reply) == 0 {
		return // a server that says nothing at all
	}
	s.serveControl(conn, make([]byte, 1<<15))
}

// DefaultPushReply is what the server pushes when the test does not say.
const DefaultPushReply = "PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.255.255.0,route-gateway 10.8.0.1," +
	"cipher AES-256-GCM,ping 10,ping-restart 60,peer-id 0,tun-mtu 1500"

// PushRequests is how many PUSH_REQUEST messages the server has read.
func (s *Server) PushRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pushRequests
}

// serveControl sends the push messages when it is time, and counts the requests
// that come, until the TLS session ends.
func (s *Server) serveControl(conn *tls.Conn, buf []byte) {
	s.mu.Lock()
	s.control = conn
	s.mu.Unlock()
	for _, m := range s.opts.EarlyMessages {
		if _, err := conn.Write(append([]byte(m), 0)); err != nil {
			return
		}
	}
	messages := s.opts.PushMessages
	if messages == nil {
		messages = []string{DefaultPushReply}
	}
	send := func() {
		for _, m := range messages {
			if _, err := conn.Write(append([]byte(m), 0)); err != nil {
				return
			}
		}
		if s.opts.CloseAfterPush {
			if err := conn.Close(); err != nil {
				s.tb.Logf("vpntest server: closing the TLS session: %v", err)
			}
		}
	}
	sent := false
	if s.opts.ReplyAfterRequests == 0 {
		send()
		sent = true
	}
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) == "PUSH_REQUEST\x00" {
			s.mu.Lock()
			s.pushRequests++
			count := s.pushRequests
			s.mu.Unlock()
			if !sent && count >= s.opts.ReplyAfterRequests {
				send()
				sent = true
			}
		}
	}
}

// SendControl sends one control message (with its closing NUL) to the client,
// at any time after the key exchange. It fails the test when the key exchange is
// not done or the TLS session is gone.
func (s *Server) SendControl(message string) {
	s.tb.Helper()
	s.mu.Lock()
	conn := s.control
	s.mu.Unlock()
	if conn == nil {
		s.tb.Error("vpntest server: SendControl before the key exchange is done")
		return
	}
	if _, err := conn.Write(append([]byte(message), 0)); err != nil {
		s.tb.Errorf("vpntest server: SendControl: %v", err)
	}
}

// KeyExchangeDone is closed when the server has read the client's key exchange
// message and answered it, or could not.
func (s *Server) KeyExchangeDone() <-chan struct{} { return s.kxDone }

// ClientKeyExchange is the key exchange message of the client, as the server
// read it. It is read apart from package ctrlmsg: by hand.
type ClientKeyExchange struct {
	PreMaster, Random1, Random2           []byte
	Options, Username, Password, PeerInfo string
	LeadingZeros                          bool
}

// KeyExchange is the client's key exchange message, or nil before it arrived.
func (s *Server) KeyExchange() *ClientKeyExchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kx
}

// parseClientKX reads the client's message the way the plan describes it: 4 zero
// bytes, 1 byte 2, 48 + 32 + 32 random bytes, then four strings, each with a
// 16-bit length that counts its NUL. It returns what is wrong with the message,
// in words, or "" when nothing is.
func parseClientKX(b []byte) (*ClientKeyExchange, string) {
	if len(b) < 5+48+32+32 {
		return nil, "the message is too short: " + strconv.Itoa(len(b)) + " bytes"
	}
	m := &ClientKeyExchange{LeadingZeros: binary.BigEndian.Uint32(b) == 0}
	if b[4] != 2 {
		return nil, "the key method is " + strconv.Itoa(int(b[4]))
	}
	m.PreMaster, m.Random1, m.Random2 = bytes.Clone(b[5:5+48]), bytes.Clone(b[53:85]), bytes.Clone(b[85:117])
	rest := b[117:]
	var strs [4]string
	for i := range strs {
		if len(rest) < 2 {
			return nil, "string " + strconv.Itoa(i) + " has no length"
		}
		n := int(binary.BigEndian.Uint16(rest))
		rest = rest[2:]
		if n < 1 || len(rest) < n || rest[n-1] != 0 {
			return nil, "string " + strconv.Itoa(i) + " is not " + strconv.Itoa(n) + " bytes that end in a NUL"
		}
		strs[i], rest = string(rest[:n-1]), rest[n:]
	}
	if len(rest) != 0 {
		return nil, strconv.Itoa(len(rest)) + " bytes follow the strings"
	}
	m.Options, m.Username, m.Password, m.PeerInfo = strs[0], strs[1], strs[2], strs[3]
	return m, ""
}

// serverKX writes a well-formed server key exchange message by hand.
func serverKX(options, peerInfo string) []byte {
	b := []byte{0, 0, 0, 0, 2}
	b = append(b, make([]byte, 64)...)
	for _, s := range []string{options, "", "", peerInfo} {
		b = binary.BigEndian.AppendUint16(b, uint16(min(len(s)+1, math.MaxUint16)))
		b = append(b, s...)
		b = append(b, 0)
	}
	return b
}

// serverChunk is how many bytes of TLS the server puts in a packet: far below
// what a packet can hold, so the server needs no figures of the client's.
const serverChunk = 900

// bridgeRead takes what TLS writes and hands it to the loop, a chunk at a time.
func (s *Server) bridgeRead() {
	defer s.wg.Done()
	buf := make([]byte, serverChunk)
	for {
		n, err := s.bridge.Read(buf)
		if err != nil {
			return
		}
		select {
		case s.tlsOut <- append([]byte(nil), buf[:n]...):
		case <-s.done:
			return
		}
	}
}

// bridgeWrite gives what arrived in order to TLS.
func (s *Server) bridgeWrite() {
	defer s.wg.Done()
	for {
		select {
		case p := <-s.tlsIn:
			if _, err := s.bridge.Write(p); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}

// CloseTLS ends the TLS server inside the server at once, so that the server
// goes on reading and acknowledging packets and says nothing more. It is for the
// tests of a server that stops in the middle of a handshake.
func (s *Server) CloseTLS() error {
	if s.tlsEnd == nil {
		return nil
	}
	if err := s.tlsEnd.Close(); err != nil {
		return err
	}
	return s.bridge.Close()
}

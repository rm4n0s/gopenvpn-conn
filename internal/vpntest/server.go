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
	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
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
	// DataCipher is the data cipher the server uses on the data channel; the
	// usual push reply names AES-256-GCM, which is the default. A test that pushes
	// another cipher says so here.
	DataCipher string
	// DataV1 makes the server's data packets DATA_V1 (no peer id), for a test whose
	// push reply has no peer-id; the default is DATA_V2 with peer id 0.
	DataV1 bool
	// Epoch makes the server's data channel use the epoch format; the push reply
	// must then have protocol-flags aead-epoch. EpochUsageLimit replaces the usage
	// limit of the server's keys, so that its sender moves through epochs with a few
	// packets.
	Epoch           bool
	EpochUsageLimit uint64
	// StaticKey is the static key that protects the control channel of the first
	// session (the key of tls-auth or tls-crypt, Kc of tls-crypt-v2), when
	// DynamicTLSCrypt is set: the key of the renegotiations is the exporter's key
	// XORed with it. Nil means none.
	StaticKey *keys.StaticKey
	// DynamicTLSCrypt makes the server protect the control packets of the
	// renegotiations (key ids above 0) with dynamic tls-crypt, made from the TLS
	// session of the first key; the push reply must have protocol-flags dyn-tls-crypt.
	DynamicTLSCrypt bool
	// RejectRenegotiations is how many renegotiations that the client starts the
	// server ignores (it reads them and answers nothing), so that they fail.
	RejectRenegotiations int
	// SwitchDelay is how long after a new key is made the server starts to send with
	// it; the default is 1 second. The client opens packets of the new key at once,
	// but only after its own key exchange is done, which the server cannot see.
	SwitchDelay time.Duration
	// EchoData makes the server send every IP packet that it receives back.
	EchoData bool
	// OnData, when set, is called with every IP packet that the server opens (not
	// with pings and exit messages), in the order of arrival, from the goroutine that
	// reads the link; it must not wait for the server. A test that joins two clients
	// sends each packet to the other server with it.
	OnData func(packet []byte)
	// Fault is how the server misbehaves.
	Fault Fault
	// RetransmitTimeout is the first wait before it sends a packet again;
	// 2 seconds when zero.
	RetransmitTimeout time.Duration
}

// serverKS is the control channel of one key id of the server: the same pieces as the
// session's key state, and a TLS server over it.
type serverKS struct {
	id        uint8
	sender    *reliable.Sender
	receiver  reliable.Receiver
	peerReset bool     // the client's reset has come
	backlog   [][]byte // what TLS wrote, not yet in packets
	muted     bool     // the server ignores the packets of this key state

	tlsEnd, bridge net.Conn
	tlsIn          chan []byte
	data           *serverData // guarded by Server.mu
	established    time.Time   // guarded by Server.mu
	closed         bool        // guarded by Server.mu
}

// chunk is what the TLS server of a key state wrote.
type chunk struct {
	ks   *serverKS
	data []byte
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
	closed   bool

	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup

	// The TLS side: crypto/tls runs on the tlsEnd of each key state, and the other end
	// of that pipe is carried to and from the packets by two goroutines.
	chunks       chan chunk
	cmds         chan func() // run by the loop goroutine
	tlsDone      chan struct{}
	kxDone       chan struct{}
	kxs          []*ClientKeyExchange // the key exchange messages, in order: the first is key id 0's
	pushRequests int
	control      *tls.Conn   // the TLS session of the newest key, once its key exchange is done
	order        []*serverKS // the keys that carry data, oldest first
	history      []uint8     // the key ids of every key that was made, in order
	dataIn       [][]byte    // the IP packets the server opened, in order
	dataDropped  int         // the data packets it could not open
	pings        int         // the keepalive pings it received
	occExits     int         // the exit messages of the data channel it received
	exits        int         // the EXIT messages of the control channel it received
	tlsErr       error
	tlsState     tls.ConnectionState
	largest      int // the largest packet that came from the client, as it was on the link
	dyn          ctrlwrap.Wrapper

	// Owned by the loop goroutine.
	keysByID   [8]*serverKS
	nextID     uint8
	rejected   int
	remote     wire.SessionID
	haveRemote bool
	sendMu     sync.Mutex // Inject writes from the test's goroutine
}

// NewServer starts a server on link, which it takes over, and stops it when the
// test ends.
func NewServer(tb testing.TB, link net.Conn, opts ServerOptions) *Server {
	tb.Helper()
	if opts.RetransmitTimeout <= 0 {
		opts.RetransmitTimeout = 2 * time.Second
	}
	if opts.SwitchDelay == 0 {
		opts.SwitchDelay = time.Second
	}
	if opts.Wrapper == nil {
		opts.Wrapper = ctrlwrap.NewPlain()
	}
	s := &Server{
		tb: tb, opts: opts, link: link, sid: wire.RandomSessionID(), nextID: 1,
		done:   make(chan struct{}),
		chunks: make(chan chunk),
		cmds:   make(chan func(), 16),
	}
	s.tlsDone = make(chan struct{})
	s.kxDone = make(chan struct{})
	ks := s.newKS(0)
	in := make(chan []byte, 128) // deep enough that two ends writing a pipe do not wait for each other
	s.wg.Add(2)
	go s.read(in)
	go s.loop(in, ks)
	tb.Cleanup(s.Close)
	return s
}

// newKS makes the control channel of a key id, with its TLS server when the server has
// TLS, and starts the goroutines of that. It returns nil after Close. The first
// packet of a key id above 0 is the server's own soft reset.
func (s *Server) newKS(id uint8) *serverKS {
	ks := &serverKS{id: id, sender: reliable.NewSender(s.opts.RetransmitTimeout)}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	if s.opts.TLS != nil {
		ks.tlsEnd, ks.bridge = net.Pipe()
		ks.tlsIn = make(chan []byte, 1024)
		s.wg.Add(3)
	}
	s.mu.Unlock()
	if id > 0 {
		if _, err := ks.sender.Queue(wire.SoftResetV1, nil); err != nil {
			s.tb.Errorf("vpntest server: %v", err)
		}
		s.nextID = id%7 + 1
	}
	s.setKS(id, ks)
	if s.opts.TLS != nil {
		go s.runTLS(ks)
		go s.bridgeRead(ks)
		go s.bridgeWrite(ks)
	}
	return ks
}

// wrapperFor is the protection of the control packets of a key id: the configured one
// for key id 0 and, with dynamic tls-crypt, the key made from the first TLS session
// for the others.
func (s *Server) wrapperFor(id uint8) ctrlwrap.Wrapper {
	if id > 0 {
		s.mu.Lock()
		w := s.dyn
		s.mu.Unlock()
		if w != nil {
			return w
		}
	}
	return s.opts.Wrapper
}

// Close stops the server and closes the link.
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.done)
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		if err := s.link.Close(); err != nil {
			s.tb.Errorf("vpntest server: closing the link: %v", err)
		}
		s.closeTLSSides()
	})
	s.wg.Wait()
}

// closeTLSSides closes the pipe of every TLS server; closing it ends the TLS goroutines.
// The pipe has no state worth reporting.
func (s *Server) closeTLSSides() {
	s.mu.Lock()
	var all []*serverKS
	for _, ks := range s.allKS() {
		if !ks.closed {
			ks.closed = true
			all = append(all, ks)
		}
	}
	s.mu.Unlock()
	for _, ks := range all {
		if ks.tlsEnd == nil {
			continue
		}
		if err := ks.tlsEnd.Close(); err != nil {
			s.tb.Errorf("vpntest server: closing the TLS side: %v", err)
		}
		if err := ks.bridge.Close(); err != nil {
			s.tb.Errorf("vpntest server: closing the bridge: %v", err)
		}
	}
}

// allKS is every key state that was made and not thrown away. The caller holds s.mu.
func (s *Server) allKS() []*serverKS {
	var all []*serverKS
	seen := map[*serverKS]bool{}
	for _, ks := range s.keysByID {
		if ks != nil && !seen[ks] {
			seen[ks] = true
			all = append(all, ks)
		}
	}
	return all
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

func (s *Server) loop(in <-chan []byte, first *serverKS) {
	defer s.wg.Done()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		s.flush()
		var next time.Time
		found := false
		for _, ks := range s.liveKS() {
			if at, ok := ks.sender.NextDeadline(); ok && (!found || at.Before(next)) {
				next, found = at, true
			}
		}
		if found {
			timer.Reset(max(0, time.Until(next)))
		} else {
			timer.Stop()
		}
		select {
		case <-s.done:
			return
		case raw := <-in:
			s.handle(raw)
		case c := <-s.chunks:
			c.ks.backlog = append(c.ks.backlog, c.data)
		case f := <-s.cmds:
			f()
		case <-timer.C:
		}
	}
}

// liveKS is the key states that were made and are not thrown away.
func (s *Server) liveKS() []*serverKS {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allKS()
}

// getKS and setKS are the table of key states, which s.mu guards.
func (s *Server) getKS(id uint8) *serverKS {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keysByID[id]
}

func (s *Server) setKS(id uint8, ks *serverKS) {
	s.mu.Lock()
	s.keysByID[id] = ks
	s.mu.Unlock()
}

// Renegotiate makes the server start a renegotiation, as OpenVPN's server does when its
// --reneg-sec has passed: a soft reset with the next key id. It returns when the soft
// reset is queued. After Close it does nothing.
func (s *Server) Renegotiate() {
	done := make(chan struct{})
	f := func() {
		defer close(done)
		id := s.nextID
		if s.getKS(id) != nil {
			s.tb.Errorf("vpntest server: key id %d is in use", id)
			return
		}
		s.dropOldKey()
		s.newKS(id)
	}
	select {
	case s.cmds <- f:
	case <-s.done:
		return
	}
	select {
	case <-done:
	case <-s.done:
	}
}

// dropOldKey throws away the oldest of two keys that carry data, as OpenVPN frees its
// lame duck when it starts a new key. The loop goroutine calls it.
func (s *Server) dropOldKey() {
	s.mu.Lock()
	var gone *serverKS
	if len(s.order) >= 2 {
		gone, s.order = s.order[0], s.order[1:]
		gone.data, gone.closed = nil, true
	}
	s.mu.Unlock()
	if gone == nil {
		return
	}
	s.setKS(gone.id, nil)
	if gone.tlsEnd != nil {
		if err := gone.tlsEnd.Close(); err != nil {
			s.tb.Errorf("vpntest server: closing the TLS side: %v", err)
		}
		if err := gone.bridge.Close(); err != nil {
			s.tb.Errorf("vpntest server: closing the bridge: %v", err)
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
	if op.IsData() {
		s.handleData(raw)
		return
	}
	switch {
	case (op == wire.HardResetClientV2 || op == wire.HardResetClientV3) && keyID == 0:
	case op == wire.SoftResetV1 && keyID != 0:
	case op == wire.ControlV1 || op == wire.ControlWKCV1 || op == wire.AckV1:
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
	body, err := s.wrapperFor(keyID).Unwrap(packet)
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
	ks := s.getKS(keyID)
	if ks == nil {
		if op != wire.SoftResetV1 {
			s.drop()
			return
		}
		if s.rejected < s.opts.RejectRenegotiations {
			s.rejected++
			ks = s.newMutedKS(keyID)
		} else {
			s.dropOldKey()
			ks = s.newKS(keyID)
		}
		if ks == nil {
			return
		}
	}
	s.mu.Lock()
	s.received = append(s.received, c)
	s.largest = max(s.largest, len(raw))
	s.mu.Unlock()
	if s.opts.Fault == Silent || ks.muted {
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
		ks.sender.Ack(id)
	}
	if op == wire.AckV1 {
		return
	}
	payloads, ack := ks.receiver.Receive(c.PacketID, c.Payload)
	if !ack {
		s.drop()
		return
	}
	isReset := op == wire.HardResetClientV2 || op == wire.HardResetClientV3 || op == wire.SoftResetV1
	if isReset && !ks.peerReset {
		ks.peerReset = true
		if len(payloads) > 0 {
			payloads = payloads[1:] // the reset has no TLS bytes
		}
	}
	if s.opts.TLS != nil {
		for _, p := range payloads {
			select {
			case ks.tlsIn <- p:
			default:
				s.tb.Errorf("vpntest server: more than %d payloads wait for TLS", cap(ks.tlsIn))
			}
		}
	}
	if first {
		var payload []byte
		if op == wire.HardResetClientV3 && s.opts.AskForWKc {
			payload = wire.AppendEarlyNegotiation(nil, true)
		}
		if _, err := ks.sender.Queue(wire.HardResetServerV2, payload); err != nil {
			s.drop()
		}
	}
}

// newMutedKS makes a key state that the server ignores: the client's renegotiation on
// it never gets an answer.
func (s *Server) newMutedKS(id uint8) *serverKS {
	ks := &serverKS{id: id, sender: reliable.NewSender(s.opts.RetransmitTimeout), muted: true}
	s.setKS(id, ks)
	s.nextID = id%7 + 1
	return ks
}

func (s *Server) flush() {
	for _, ks := range s.liveKS() {
		if ks.muted {
			continue
		}
		for len(ks.backlog) > 0 && s.haveRemote && ks.sender.CanSend() {
			if _, err := ks.sender.Queue(wire.ControlV1, ks.backlog[0]); err != nil {
				s.tb.Errorf("vpntest server: %v", err)
			}
			ks.backlog = ks.backlog[1:]
		}
		for _, o := range ks.sender.Due(time.Now()) {
			c := wire.Control{Opcode: o.Opcode, KeyID: ks.id, SessionID: s.sid, PacketID: o.ID, Payload: o.Payload}
			s.addAcks(ks, &c)
			s.writeOrReport(&c)
		}
		if ks.receiver.HasPendingAcks() {
			c := wire.Control{Opcode: wire.AckV1, KeyID: ks.id, SessionID: s.sid}
			s.addAcks(ks, &c)
			s.writeOrReport(&c)
		}
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

func (s *Server) addAcks(ks *serverKS, c *wire.Control) {
	if !s.haveRemote {
		return
	}
	acks := ks.receiver.Acks(wire.MaxAcks)
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
	packet, err := s.wrapperFor(c.KeyID).Wrap(nil, wire.FirstByte(c.Opcode, c.KeyID), c.SessionID, body)
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

// runTLS runs crypto/tls as the server over the control channel of a key state.
func (s *Server) runTLS(ks *serverKS) {
	defer s.wg.Done()
	conn := tls.Server(ks.tlsEnd, s.opts.TLS)
	err := conn.Handshake()
	select {
	case <-s.done:
		return
	default:
	}
	if ks.id == 0 {
		s.tlsErr = err
		if err == nil {
			s.tlsState = conn.ConnectionState()
		}
		close(s.tlsDone)
	}
	if err == nil {
		s.keyExchange(ks, conn)
	}
}

// keyExchange reads the client's key exchange message, which is one TLS record,
// keeps it, and answers.
func (s *Server) keyExchange(ks *serverKS, conn *tls.Conn) {
	kxDone := false
	finish := func() {
		if !kxDone && ks.id == 0 {
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
	s.kxs = append(s.kxs, kx)
	s.mu.Unlock()
	reply := s.opts.KeyExchangeReply
	if reply == nil {
		reply = serverKX("V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server", "IV_VER=vpntest\n")
	}
	if ks.id > 0 {
		// The data keys exist before the client can learn that the exchange is done.
		s.setupData(conn, ks)
	}
	if len(reply) > 0 {
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
	finish()
	if ks.id > 0 {
		s.mu.Lock()
		s.control = conn
		s.mu.Unlock()
		s.serveRenegotiated(conn, make([]byte, 1<<15))
		return
	}
	if s.opts.CloseAfterKeyExchange {
		if err := conn.Close(); err != nil {
			s.tb.Logf("vpntest server: closing the TLS session: %v", err)
		}
		return
	}
	if len(reply) == 0 {
		return // a server that says nothing at all
	}
	s.serveControl(ks, conn, make([]byte, 1<<15))
}

// DefaultPushReply is what the server pushes when the test does not say.
const DefaultPushReply = "PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.255.255.0,route-gateway 10.8.0.1," +
	"cipher AES-256-GCM,ping 10,ping-restart 60,peer-id 0,tun-mtu 1500,key-derivation tls-ekm"

// PushRequests is how many PUSH_REQUEST messages the server has read.
func (s *Server) PushRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pushRequests
}

// serveControl sends the push messages when it is time, and counts the requests
// that come, until the TLS session ends.
func (s *Server) serveControl(ks *serverKS, conn *tls.Conn, buf []byte) {
	s.setupData(conn, ks)
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
		if string(buf[:n]) == "EXIT\x00" {
			s.mu.Lock()
			s.exits++
			s.mu.Unlock()
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

// serveRenegotiated reads the control messages that come in the TLS session of a
// renegotiated key: only EXIT is counted. There is no push after the first key.
func (s *Server) serveRenegotiated(conn *tls.Conn, buf []byte) {
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) == "EXIT\x00" {
			s.mu.Lock()
			s.exits++
			s.mu.Unlock()
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
	if len(s.kxs) == 0 {
		return nil
	}
	return s.kxs[0]
}

// parseClientKX reads the client's message the way the plan describes it: 4 zero
// bytes, 1 byte 2, 48 + 32 + 32 random bytes, then four strings, each with a
// 16-bit length that counts its NUL (the user name and the password may have the
// length 0: none given). It returns what is wrong with the message,
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
		if n == 0 && (i == 1 || i == 2) {
			continue // no user name, no password: OpenVPN's client writes a length of 0
		}
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
func (s *Server) bridgeRead(ks *serverKS) {
	defer s.wg.Done()
	buf := make([]byte, serverChunk)
	for {
		n, err := ks.bridge.Read(buf)
		if err != nil {
			return
		}
		select {
		case s.chunks <- chunk{ks: ks, data: append([]byte(nil), buf[:n]...)}:
		case <-s.done:
			return
		}
	}
}

// bridgeWrite gives what arrived in order to TLS.
func (s *Server) bridgeWrite(ks *serverKS) {
	defer s.wg.Done()
	for {
		select {
		case p := <-ks.tlsIn:
			if _, err := ks.bridge.Write(p); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}

// CloseTLS ends the TLS server of key id 0 inside the server at once, so that the
// server goes on reading and acknowledging packets and says nothing more. It is for
// the tests of a server that stops in the middle of a handshake.
func (s *Server) CloseTLS() error {
	ks := s.getKS(0)
	if ks == nil || ks.tlsEnd == nil {
		return nil
	}
	if err := ks.tlsEnd.Close(); err != nil {
		return err
	}
	return ks.bridge.Close()
}

// KeyExchanges is every key exchange message of the client in the order of arrival:
// the first is the one of the handshake, the others are the renegotiations.
func (s *Server) KeyExchanges() []*ClientKeyExchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*ClientKeyExchange(nil), s.kxs...)
}

// Renegotiations is how many renegotiations the server has finished the key exchange
// of.
func (s *Server) Renegotiations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return max(0, len(s.kxs)-1)
}

// KeyHistory is the key id of every key that the server made, in order: 0, then the
// renegotiations.
func (s *Server) KeyHistory() []uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint8(nil), s.history...)
}

// KeyIDs is the key ids of the keys that carry data, oldest first.
func (s *Server) KeyIDs() []uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]uint8, len(s.order))
	for i, ks := range s.order {
		ids[i] = ks.id
	}
	return ids
}

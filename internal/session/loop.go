// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl.c and ssl_pkt.c (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package session

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// readLoop reads packets from the link and gives them to the loop, each in a
// slice of its own. It returns when the link fails or the session has ended.
func (s *Session) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, maxPacket)
	failures := 0 // read errors of a datagram link in a row, none of which was a packet
	var br *bufio.Reader
	if s.opts.Stream {
		br = bufio.NewReader(s.opts.Link)
	}
	for {
		var n int
		var err error
		if s.opts.Stream {
			var header [2]byte
			if _, err = io.ReadFull(br, header[:]); err == nil {
				n = int(binary.BigEndian.Uint16(header[:]))
				_, err = io.ReadFull(br, buf[:n])
				if err == io.EOF {
					err = io.ErrUnexpectedEOF // the length was read: the frame is cut
				}
			}
		} else {
			n, err = s.opts.Link.Read(buf)
		}
		if err != nil {
			if !s.opts.Stream && s.transientRead(err, &failures) {
				continue
			}
			select {
			case <-s.done: // the link was closed by the session: not a failure
			default:
				s.readErr <- errors.NewErr(TagLinkFailed, err).SetMetadata("op", "read")
			}
			return
		}
		failures = 0
		select {
		case s.in <- append([]byte(nil), buf[:n]...):
		case <-s.done:
			return
		}
	}
}

// maxReadFailures is how many read errors in a row a datagram link may give, with
// no packet between them, before the session ends.
const maxReadFailures = 64

// transientRead reports whether a read error of a datagram link is one to go on
// after: a connected UDP socket returns the ICMP "port unreachable" of an earlier
// packet as an error of the next read (ECONNREFUSED on Linux and macOS, a reset on
// Windows), which says nothing of the packets that follow, and OpenVPN ignores it
// and lets the keepalive decide. So any error does not end the session, except
// that the link is closed or ended, or that it fails over and over with no packet
// in between (a socket that is broken for good).
//
// OpenVPN: socket.c link_socket_read_udp_posix (a failed read is logged and the
// loop goes on).
func (s *Session) transientRead(err error, failures *int) bool {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
	}
	*failures++
	if *failures > maxReadFailures {
		return false
	}
	s.log.Debug("ignored a read error of the datagram link", "err", err)
	return true
}

// loop owns the state: it handles the packets that the reader gives it, sends
// what is due, and runs the timers. It closes the link when it returns.
func (s *Session) loop() {
	defer s.wg.Done()
	defer s.closeLink()

	handshake := time.NewTimer(s.opts.HandshakeTimeout)
	defer handshake.Stop()
	deadline := s.began.Add(s.opts.HandshakeTimeout)
	retransmit := time.NewTimer(time.Hour)
	retransmit.Stop()
	defer retransmit.Stop()
	keepalive := time.NewTimer(time.Hour)
	keepalive.Stop()
	defer keepalive.Stop()

	if _, err := s.sender.Queue(s.resetOp, nil); err != nil {
		s.fail(err)
		return
	}
	complete := false
	tlsReady := s.tlsReady // nil once it has fired, and in ResetOnly mode
	if s.opts.ResetOnly {
		tlsReady = nil
	}
	for {
		// What crypto/tls has written is taken once the server's reset is in,
		// and only when the bytes of the last write are all in packets.
		var outbound <-chan []byte
		if !s.opts.ResetOnly && s.serverResetSeen && len(s.pending) == 0 {
			outbound = s.out
		}
		select {
		case msg := <-outbound:
			s.pending = msg
		default:
		}
		if err := s.flush(); err != nil {
			s.fail(err)
			return
		}
		if len(s.pending) > 0 {
			outbound = nil // the bytes that are waiting go first: take no more
		}
		if !s.drainedClosed && s.exitSent.Load() && len(s.pending) == 0 && s.sender.Len() == 0 {
			s.drainedClosed = true // EXIT, and all that came before it, is acknowledged
			close(s.drained)
		}
		if !complete {
			switch {
			case s.opts.ResetOnly:
				complete = s.serverResetSeen && s.thirdSent && s.sender.Len() == 0
			default:
				complete = tlsReady == nil
			}
			if complete {
				handshake.Stop()
				if !s.opts.ResetOnly {
					s.startKeepalive()
				}
				close(s.ready)
			}
		}
		if at, ok := s.sender.NextDeadline(); ok {
			retransmit.Reset(max(0, time.Until(at)))
		} else {
			retransmit.Stop()
		}
		if wait, ok := s.keepaliveWait(); ok {
			keepalive.Reset(wait)
		} else {
			keepalive.Stop()
		}
		select {
		case <-s.done:
			return
		case pkt := <-s.in:
			s.handle(pkt)
		case msg := <-outbound:
			s.pending = msg
		case <-tlsReady:
			tlsReady = nil
		case <-s.extend:
			s.mu.Lock()
			at := s.extendAt
			s.mu.Unlock()
			if !complete && at.After(deadline) {
				deadline = at
				handshake.Reset(time.Until(at))
			}
		case err := <-s.readErr:
			s.fail(err)
			return
		case <-handshake.C:
			s.fail(errors.New(TagHandshakeTimeout, "the handshake did not finish in time",
				"timeout", s.opts.HandshakeTimeout.String()))
			return
		case <-retransmit.C:
		case <-s.wake:
		case <-keepalive.C:
			if !s.keepaliveTick() {
				return
			}
		}
	}
}

// closeLink closes the link, once the loop is done with it.
func (s *Session) closeLink() {
	if err := s.opts.Link.Close(); err != nil {
		s.mu.Lock()
		s.closeErr = errors.NewErr(tagLinkCloseFailed, err)
		s.mu.Unlock()
	}
}

// flush sends the packets that are due, with the acknowledgements that wait
// on them, and an ACK_V1 when acknowledgements still wait.
func (s *Session) flush() error {
	if err := s.fillSender(); err != nil {
		return err
	}
	for _, o := range s.sender.Due(time.Now()) {
		c := wire.Control{Opcode: o.Opcode, SessionID: s.sid, PacketID: o.ID, Payload: o.Payload}
		s.addAcks(&c)
		if err := s.send(&c); err != nil {
			return err
		}
	}
	if s.receiver.HasPendingAcks() {
		c := wire.Control{Opcode: wire.AckV1, SessionID: s.sid}
		s.addAcks(&c)
		if err := s.send(&c); err != nil {
			return err
		}
	}
	return nil
}

// fillSender cuts what crypto/tls wrote into control packets, as many as the
// send window has room for. The first packet after the reset is a
// CONTROL_WKC_V1, with less room, when the server asked for the wrapped key.
//
// OpenVPN: ssl.c write_outgoing_tls_ciphertext.
func (s *Session) fillSender() error {
	for len(s.pending) > 0 && s.sender.CanSend() {
		op, room := wire.ControlV1, s.budget
		if s.wkcAsked && !s.wkcSent {
			op, room = wire.ControlWKCV1, max(minPayload, room-s.wkcLen)
			s.wkcSent = true
		}
		n := min(room, len(s.pending))
		if _, err := s.sender.Queue(op, s.pending[:n:n]); err != nil {
			return err
		}
		s.pending = s.pending[n:]
	}
	return nil
}

// addAcks puts the acknowledgements that fit into a packet on it.
func (s *Session) addAcks(c *wire.Control) {
	if !s.haveRemote {
		return
	}
	if acks := s.receiver.Acks(wire.MaxAcks); len(acks) > 0 {
		c.Acks = acks
		c.RemoteSessionID = s.remote
	}
}

// send protects a control packet and writes it to the link.
func (s *Session) send(c *wire.Control) error {
	var err error
	if s.body, err = wire.AppendControlBody(s.body[:0], c); err != nil {
		return err
	}
	if s.packet, err = s.opts.Wrapper.Wrap(s.packet[:0], wire.FirstByte(c.Opcode, c.KeyID), c.SessionID, s.body); err != nil {
		return err
	}
	out := s.packet
	if s.opts.Stream {
		if out, err = wire.AppendFrame(nil, s.packet); err != nil {
			return err
		}
	}
	if _, err := s.writeLink(out, time.Time{}); err != nil {
		return errors.NewErr(TagLinkFailed, err).SetMetadata("op", "write")
	}
	s.touchSent()
	if s.serverResetSeen && len(c.Acks) > 0 {
		s.thirdSent = true
	}
	return nil
}

// handle takes one packet from the link. Anyone can send a packet, so one that
// does not belong is dropped, and nothing in it is used before it is shown to
// be from the server: the protection first, then the session ids.
func (s *Session) handle(raw []byte) {
	if len(raw) > 0 {
		if op, _ := wire.SplitFirstByte(raw[0]); op.IsData() {
			s.handleData(raw)
			return
		}
	}
	if len(raw) < 1+wire.SessionIDSize {
		s.drop("too short", nil)
		return
	}
	op, keyID := wire.SplitFirstByte(raw[0])
	if !op.IsControl() || keyID != 0 {
		s.drop("not a control packet of key 0", nil)
		return
	}
	switch op {
	case wire.HardResetServerV2, wire.ControlV1, wire.AckV1:
	default:
		s.drop("an opcode that only a client sends", nil)
		return
	}
	body, err := s.opts.Wrapper.Unwrap(raw)
	if err != nil {
		s.drop("the protection does not check", err)
		return
	}
	c, err := wire.ParseControlBody(op, body)
	if err != nil {
		s.drop("does not parse", err)
		return
	}
	copy(c.SessionID[:], raw[1:1+wire.SessionIDSize])
	c.KeyID = keyID

	if s.haveRemote {
		if c.SessionID != s.remote {
			s.drop("from another session", nil)
			return
		}
	} else if op != wire.HardResetServerV2 {
		s.drop("not a reset, and no session yet", nil)
		return
	}
	if len(c.Acks) > 0 && c.RemoteSessionID != s.sid {
		s.drop("acknowledges another session", nil)
		return
	}
	resend := false
	if op == wire.HardResetServerV2 {
		if c.PacketID != 0 {
			s.drop("a reset with an id that is not 0", nil)
			return
		}
		if !s.serverResetSeen && s.resetOp == wire.HardResetClientV3 {
			if resend, err = wire.ParseEarlyNegotiation(c.Payload); err != nil {
				s.drop("the payload of the reset does not parse", err)
				return
			}
		}
	}

	// From here the packet is the server's, and counts as something received.
	s.lastRecv = time.Now()
	if !s.haveRemote {
		s.remote, s.haveRemote = c.SessionID, true
	}
	for _, id := range c.Acks {
		s.sender.Ack(id)
	}
	if op == wire.AckV1 {
		return
	}
	if !s.opts.ResetOnly && s.adapter.queued() >= inboundLimit {
		// Not acknowledged, so the server sends it again when TLS has caught
		// up. Its acknowledgements were taken above.
		s.drop("the TLS side has not read what is waiting", nil)
		return
	}
	payloads, ack := s.receiver.Receive(c.PacketID, c.Payload)
	if !ack {
		s.drop("not accepted by the reliability layer", nil)
		return
	}
	if op == wire.HardResetServerV2 && !s.serverResetSeen {
		s.serverResetSeen = true
		s.wkcAsked = resend
		if len(payloads) > 0 {
			payloads = payloads[1:] // the payload of the reset is the TLVs, not TLS
		}
		if resend && s.opts.ResetOnly && !s.wkcQueued {
			// The server asks for the wrapped key again, and there is no TLS
			// to send it with: an empty packet carries it, and the acknowledgement.
			s.wkcQueued = true
			if _, err := s.sender.Queue(wire.ControlWKCV1, nil); err != nil {
				s.fail(err)
				return
			}
		}
	}
	for _, p := range payloads {
		if s.opts.ResetOnly {
			s.drop("TLS bytes, and no TLS in this mode", nil)
			continue
		}
		s.adapter.push(p)
	}
}

// tlsMain runs the TLS handshake over the control channel. It is a goroutine
// of the session: it ends when the handshake does, and when the session ends
// (the conn that crypto/tls reads and writes then fails).
func (s *Session) tlsMain() {
	defer s.wg.Done()
	conn := tls.Client(s.adapter, s.tlsCfg)
	if err := conn.Handshake(); err != nil {
		s.fail(errors.NewErr(TagTLSHandshakeFailed, err))
		return
	}
	kx, err := s.keyExchange(conn)
	if err != nil {
		s.fail(err)
		return
	}
	s.tlsConn, s.serverKX = conn, kx
	s.controlLoop(conn)
}

// controlLoop reads the control messages that the server sends in TLS, for as
// long as the session lives. The handshake is complete when the PUSH_REPLY is:
// until then PUSH_REQUEST is sent every 5 seconds. Messages that are not yet
// understood are ignored and logged by name only.
//
// OpenVPN: push.c send_push_request, incoming_push_message.
func (s *Session) controlLoop(conn *tls.Conn) {
	s.wg.Add(1)
	go s.pushRequests(conn)
	var pushed ctrlmsg.Pushed
	ready := false
	buf := make([]byte, 1<<15)
	var stream []byte // bytes read that do not make a whole message yet
	for {
		n, err := conn.Read(buf)
		if err != nil {
			select {
			case <-s.done: // the session ended: this is how the read stops
			default:
				s.fail(errors.NewErr(TagControlChannelFailed, err).SetMetadata("op", "read"))
			}
			return
		}
		stream = append(stream, buf[:n]...)
		// A message ends with a NUL and has none inside. OpenVPN's servers send
		// each in one TLS record, but a record may be cut by another sender, and
		// two messages may share one, so the NUL is what ends a message.
		for {
			end := bytes.IndexByte(stream, 0)
			if end < 0 {
				break
			}
			record := stream[:end+1]
			stream = stream[end+1:]
			if failed := s.control(record, &pushed, &ready); failed {
				return
			}
		}
		if len(stream) > maxControlMessage {
			s.fail(errors.New(tagControlMessageTooLong, "a control message is too long", "max", maxControlMessage))
			return
		}
		if len(stream) == 0 {
			stream = nil
		}
	}
}

// control handles one control message. It reports true when the session has
// failed and the loop is to stop.
func (s *Session) control(record []byte, pushed *ctrlmsg.Pushed, ready *bool) (failed bool) {
	text := string(record[:len(record)-1]) // the text, without its NUL
	switch {
	case ctrlmsg.IsAuthFailed(text):
		f := ctrlmsg.ParseAuthFailed(text)
		s.fail(errors.New(TagAuthFailed, "the server refused the credentials",
			"reason", f.Reason, "session", f.Session, "temporary", f.Temporary,
			"backoff", int(f.Backoff/time.Second), "advance", f.Advance))
		return true
	case ctrlmsg.IsAuthPending(text):
		s.extendHandshake(ctrlmsg.ParseAuthPending(text))
		return false
	case isExit(text):
		s.serverExited()
		return true
	}
	if sig, ok := ctrlmsg.ParseSignal(text); ok {
		if sig.Restart {
			s.fail(errors.New(TagServerRestart, "the server asked the client to connect again", "reason", sig.Reason, "flags", sig.Flags))
		} else {
			s.fail(errors.New(TagServerHalt, "the server told the client to stop", "reason", sig.Reason))
		}
		return true
	}
	if !ctrlmsg.IsPushReply(text) || *ready {
		s.log.Debug("ignored a control message", "name", ctrlmsg.Name(text))
		return false
	}
	reply, err := ctrlmsg.ParsePushReply(text)
	if err != nil {
		s.fail(err)
		return true
	}
	if err := pushed.Add(reply, s.opts.Ciphers); err != nil {
		s.fail(err)
		return true
	}
	if reply.More {
		return false
	}
	if err := pushed.Finish(); err != nil {
		s.fail(err)
		return true
	}
	for _, name := range pushed.Unknown {
		s.log.Warn("the server pushed an option that is not known", "option", name)
	}
	state := s.tlsConn.ConnectionState()
	if err := s.setupData(pushed, &state); err != nil {
		s.fail(err)
		return true
	}
	s.pushed, *ready = pushed, true
	close(s.pushDone)
	close(s.tlsReady)
	return false
}

// extendHandshake makes the end of the handshake later, as AUTH_PENDING asks: the
// server needs more time (a second factor, a web login). The time counts from the
// start of the handshake and is at most the longer of HandshakeTimeout and
// maxAuthPending; a message with no time keeps HandshakeTimeout. The context of
// the handshake, and Close, still end it at any time.
//
// OpenVPN: push.c receive_auth_pending.
func (s *Session) extendHandshake(asked time.Duration) {
	if asked <= 0 {
		asked = s.opts.HandshakeTimeout
	}
	asked = min(asked, max(s.opts.HandshakeTimeout, maxAuthPending))
	at := s.began.Add(asked)
	s.mu.Lock()
	if at.After(s.extendAt) { // the latest end wins, whatever the order of the messages
		s.extendAt = at
	}
	s.mu.Unlock()
	select { // one wake-up is enough: the loop reads extendAt when it runs
	case s.extend <- struct{}{}:
	default:
	}
}

// pushRequests sends PUSH_REQUEST at once and then every 5 seconds, until the
// reply is complete or the session ends.
func (s *Session) pushRequests(conn *tls.Conn) {
	defer s.wg.Done()
	request := ctrlmsg.AppendMessage(nil, ctrlmsg.PushRequest)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-s.pushDone:
			return
		case <-s.done:
			return
		case <-timer.C:
		}
		if _, err := conn.Write(request); err != nil {
			select {
			case <-s.done:
			default:
				s.fail(errors.NewErr(TagControlChannelFailed, err).SetMetadata("op", "write"))
			}
			return
		}
		timer.Reset(pushRequestInterval)
	}
}

// keyExchange sends the client's key exchange message in one TLS record and
// reads the server's, which is one record too. The data keys do not come from
// it (SPEC §8.3), so what it gives the library is the server's strings.
//
// OpenVPN: ssl.c key_method_2_write, key_method_2_read.
func (s *Session) keyExchange(conn *tls.Conn) (*ctrlmsg.ServerKeyExchange, error) {
	var username, password string
	if s.opts.Credentials != nil {
		var err error
		if username, password, err = s.opts.Credentials(s.ctx); err != nil {
			return nil, errors.NewErr(TagCredentialsFailed, err)
		}
	}
	msg, err := ctrlmsg.AppendClientKeyExchange(nil, ctrlmsg.NewClientKeyExchange(s.opts.Options, username, password, s.opts.PeerInfo))
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(msg)
	clear(msg) // the password is in it
	if err != nil {
		return nil, errors.NewErr(TagKeyExchangeFailed, err).SetMetadata("op", "write")
	}
	buf := make([]byte, 1<<15)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, errors.NewErr(TagKeyExchangeFailed, err).SetMetadata("op", "read")
	}
	return ctrlmsg.ParseServerKeyExchange(buf[:n])
}

// drop counts a packet that is not used, and says why at the debug level.
func (s *Session) drop(reason string, err error) {
	s.dropped.Add(1)
	if err != nil {
		s.log.Debug("dropped a packet", "reason", reason, "err", err)
		return
	}
	s.log.Debug("dropped a packet", "reason", reason)
}

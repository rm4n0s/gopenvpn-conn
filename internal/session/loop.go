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
// slice of its own. It returns when the link fails, with the error of that, or
// when the session has ended, with nil.
func (s *Session) readLoop() error {
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
				return nil
			default:
				return errors.NewErr(TagLinkFailed, err).SetMetadata("op", "read")
			}
		}
		failures = 0
		pb := s.packetFor(buf[:n])
		select {
		case s.in <- pb:
		case <-s.done:
			s.pool.put(pb)
			return nil
		}
	}
}

// packetFor copies a packet that was read into a buffer of its own. A packet of the
// data channel gets one from the pool, which the loop gives back when it has opened
// the packet; a control packet is kept by the reliability layer and gets a new one.
func (s *Session) packetFor(p []byte) *packetBuf {
	if len(p) > 0 {
		if op, _ := wire.SplitFirstByte(p[0]); op.IsData() {
			pb := s.pool.get(len(p))
			copy(pb.b, p)
			return pb
		}
	}
	return &packetBuf{b: append([]byte(nil), p...)}
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
// what is due, and runs the timers. It returns the error that ends the session, or
// nil when the session has ended without it (another goroutine's failure, or
// Close); its goroutine stores the error and closes the link (runLoop).
func (s *Session) loop() error {
	handshake := time.NewTimer(s.opts.HandshakeTimeout)
	defer handshake.Stop()
	deadline := s.began.Add(s.opts.HandshakeTimeout)
	retransmit := time.NewTimer(time.Hour)
	retransmit.Stop()
	defer retransmit.Stop()
	keepalive := time.NewTimer(time.Hour)
	keepalive.Stop()
	defer keepalive.Stop()
	reneg := time.NewTimer(time.Hour)
	reneg.Stop()
	defer reneg.Stop()
	// The server must answer within ServerPollTimeout; once it has, only the time of
	// the handshake is left to bound the rest (the TLS handshake, a slow login).
	//
	// OpenVPN: forward.c check_server_poll_timeout.
	var poll <-chan time.Time
	if d := s.opts.ServerPollTimeout; d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		poll = t.C
	}

	if _, err := s.ks0.sender.Queue(s.ks0.resetOp, nil); err != nil {
		return err
	}
	complete := false
	tlsReady := s.tlsReady // nil once it has fired, and in ResetOnly mode
	if s.opts.ResetOnly {
		tlsReady = nil
	}
	for {
		if complete && !s.opts.ResetOnly {
			if err := s.renegTick(); err != nil {
				return err
			}
		}
		if err := s.flush(); err != nil {
			return err
		}
		if !s.drainedClosed && s.exitSent.Load() && s.settled() {
			s.drainedClosed = true // EXIT, and all that came before it, is acknowledged
			close(s.drained)
		}
		if !complete {
			switch {
			case s.opts.ResetOnly:
				complete = s.ks0.peerReset && s.ks0.thirdSent && s.ks0.sender.Len() == 0
			default:
				complete = tlsReady == nil
			}
			if complete {
				handshake.Stop()
				if !s.opts.ResetOnly {
					s.startKeepalive()
					s.startRenegotiation()
				}
				close(s.ready)
			}
		}
		if at, ok := s.nextRetransmit(); ok {
			retransmit.Reset(max(0, time.Until(at)))
		} else {
			retransmit.Stop()
		}
		if wait, ok := s.keepaliveWait(); ok {
			keepalive.Reset(wait)
		} else {
			keepalive.Stop()
		}
		if at, ok := s.renegWait(); ok && complete && !s.opts.ResetOnly {
			reneg.Reset(max(0, time.Until(at)))
		} else {
			reneg.Stop()
		}
		select {
		case <-s.done:
			return nil
		case pb := <-s.in:
			err := s.handle(pb.b)
			s.pool.put(pb)
			if err != nil {
				return err
			}
		case m := <-s.out:
			s.take(m)
		case ev := <-s.events:
			if err := s.onKeyEvent(ev); err != nil {
				return err
			}
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
			return err
		case <-poll:
			poll = nil
			if !s.haveRemote {
				return errors.New(TagServerPollTimeout, "the server did not answer in time",
					"timeout", s.opts.ServerPollTimeout.String())
			}
		case <-handshake.C:
			return errors.New(TagHandshakeTimeout, "the handshake did not finish in time",
				"timeout", s.opts.HandshakeTimeout.String())
		case <-retransmit.C:
		case <-reneg.C:
		case <-s.wake:
		case <-keepalive.C:
			if err := s.keepaliveTick(); err != nil {
				return err
			}
		}
	}
}

// closeLink closes the link, once the loop is done with it. After Close (not after a
// failure) the writer of the link first sends what the loop gave it, for at most
// exitWait: the write deadline that is set here ends a write that the link does not
// take. It returns the error of closing the link, which Close returns.
func (s *Session) closeLink() error {
	close(s.loopDone)
	if s.closing.Load() {
		if err := s.opts.Link.SetWriteDeadline(time.Now().Add(exitWait)); err == nil {
			timer := time.NewTimer(2 * exitWait)
			select {
			case <-s.ctlDone:
			case <-timer.C:
			}
			timer.Stop()
		}
	}
	if err := s.opts.Link.Close(); err != nil {
		return errors.NewErr(tagLinkCloseFailed, err)
	}
	return nil
}

// take keeps what crypto/tls wrote to the conn of a key state, until it is in packets.
// A key state that is gone gets nothing.
func (s *Session) take(m outMsg) {
	if m.ks.closing.Load() || s.keys[m.ks.id] != m.ks {
		return
	}
	m.ks.pending, m.ks.holding = m.data, true
}

// settled reports whether everything that the control channels have to send is sent
// and acknowledged.
func (s *Session) settled() bool {
	for _, ks := range s.keys {
		if ks != nil && (len(ks.pending) > 0 || ks.sender.Len() > 0) {
			return false
		}
	}
	return true
}

// nextRetransmit is the earliest time that a control packet of any key state is to be
// sent again.
func (s *Session) nextRetransmit() (time.Time, bool) {
	var first time.Time
	found := false
	for _, ks := range s.keys {
		if ks == nil {
			continue
		}
		if at, ok := ks.sender.NextDeadline(); ok && (!found || at.Before(first)) {
			first, found = at, true
		}
	}
	return first, found
}

// flush sends the packets that are due for each key state, with the acknowledgements
// that wait on them, and an ACK_V1 when acknowledgements still wait.
func (s *Session) flush() error {
	for _, ks := range s.keys {
		if ks == nil {
			continue
		}
		if err := s.flushKey(ks); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) flushKey(ks *keyState) error {
	if err := s.fillSender(ks); err != nil {
		return err
	}
	ks.giveBack()
	for _, o := range ks.sender.Due(time.Now()) {
		c := wire.Control{Opcode: o.Opcode, KeyID: ks.id, SessionID: s.sid, PacketID: o.ID, Payload: o.Payload}
		s.addAcks(ks, &c)
		if err := s.send(ks, &c); err != nil {
			return err
		}
	}
	if ks.receiver.HasPendingAcks() {
		c := wire.Control{Opcode: wire.AckV1, KeyID: ks.id, SessionID: s.sid}
		s.addAcks(ks, &c)
		if err := s.send(ks, &c); err != nil {
			return err
		}
	}
	return nil
}

// fillSender cuts what crypto/tls wrote into control packets, as many as the
// send window has room for, once the peer's reset is in. The first packet after the
// reset of key id 0 is a CONTROL_WKC_V1, with less room, when the server asked for
// the wrapped key.
//
// OpenVPN: ssl.c write_outgoing_tls_ciphertext.
func (s *Session) fillSender(ks *keyState) error {
	if !ks.peerReset {
		return nil
	}
	for len(ks.pending) > 0 && ks.sender.CanSend() {
		op, room := wire.ControlV1, ks.budget
		if ks.wkcAsked && !ks.wkcSent {
			op, room = wire.ControlWKCV1, max(minPayload, room-s.wkcLen)
			ks.wkcSent = true
		}
		n := min(room, len(ks.pending))
		if _, err := ks.sender.Queue(op, ks.pending[:n:n]); err != nil {
			return err
		}
		ks.pending = ks.pending[n:]
	}
	return nil
}

// addAcks puts the acknowledgements that fit into a packet on it.
func (s *Session) addAcks(ks *keyState, c *wire.Control) {
	if !s.haveRemote {
		return
	}
	if acks := ks.receiver.Acks(wire.MaxAcks); len(acks) > 0 {
		c.Acks = acks
		c.RemoteSessionID = s.remote
	}
}

// send protects a control packet and gives it to the writer of the link.
func (s *Session) send(ks *keyState, c *wire.Control) error {
	var err error
	if s.body, err = wire.AppendControlBody(s.body[:0], c); err != nil {
		return err
	}
	if s.packet, err = ks.wrap.Wrap(s.packet[:0], wire.FirstByte(c.Opcode, c.KeyID), c.SessionID, s.body); err != nil {
		return err
	}
	// The writer of the link sends it: the loop does not wait for the link.
	var out []byte
	if s.opts.Stream {
		if out, err = wire.AppendFrame(nil, s.packet); err != nil {
			return err
		}
	} else {
		out = append(out, s.packet...)
	}
	s.queueForLink(out)
	if ks.peerReset && len(c.Acks) > 0 {
		ks.thirdSent = true
	}
	return nil
}

// handle takes one packet from the link. Anyone can send a packet, so one that
// does not belong is dropped, and nothing in it is used before it is shown to
// be from the server: the protection first, then the session ids. It returns an
// error only when the session ends with it.
func (s *Session) handle(raw []byte) error {
	if len(raw) > 0 {
		if op, _ := wire.SplitFirstByte(raw[0]); op.IsData() {
			return s.handleData(raw)
		}
	}
	if len(raw) < 1+wire.SessionIDSize {
		s.drop("too short", nil)
		return nil
	}
	op, keyID := wire.SplitFirstByte(raw[0])
	if !op.IsControl() {
		s.drop("not a control packet", nil)
		return nil
	}
	switch {
	case op == wire.HardResetServerV2 && keyID == 0:
	case op == wire.SoftResetV1 && keyID != 0:
	case op == wire.ControlV1 || op == wire.AckV1:
	default:
		s.drop("an opcode that only a client sends, or a reset of the wrong key id", nil)
		return nil
	}
	ks := s.keys[keyID]
	if ks == nil && op != wire.SoftResetV1 {
		s.drop("a control packet of a key id that has no key state", nil)
		return nil
	}
	wrap := s.wrapperFor(keyID)
	body, err := wrap.Unwrap(raw)
	if err != nil {
		s.drop("the protection does not check", err)
		return nil
	}
	c, err := wire.ParseControlBody(op, body)
	if err != nil {
		s.drop("does not parse", err)
		return nil
	}
	copy(c.SessionID[:], raw[1:1+wire.SessionIDSize])
	c.KeyID = keyID

	if s.haveRemote {
		if c.SessionID != s.remote {
			s.drop("from another session", nil)
			return nil
		}
	} else if op != wire.HardResetServerV2 {
		s.drop("not a reset, and no session yet", nil)
		return nil
	}
	if len(c.Acks) > 0 && c.RemoteSessionID != s.sid {
		s.drop("acknowledges another session", nil)
		return nil
	}
	isReset := op == wire.HardResetServerV2 || op == wire.SoftResetV1
	if isReset && c.PacketID != 0 {
		s.drop("a reset with an id that is not 0", nil)
		return nil
	}
	if ks == nil {
		// The server asks for a renegotiation: a soft reset of a key id that is free,
		// once the key in use is complete. It is authentic here, so it is answered.
		if ks, err = s.acceptSoftReset(keyID); err != nil {
			return err
		}
		if ks == nil {
			s.drop("a soft reset that is not accepted now", nil)
			return nil
		}
	}
	resend := false
	if op == wire.HardResetServerV2 && !ks.peerReset && s.resetOp == wire.HardResetClientV3 {
		if resend, err = wire.ParseEarlyNegotiation(c.Payload); err != nil {
			s.drop("the payload of the reset does not parse", err)
			return nil
		}
	}

	// From here the packet is the server's, and counts as something received.
	s.lastRecv = time.Now()
	if !s.haveRemote {
		s.remote, s.haveRemote = c.SessionID, true
		s.sawServer.Store(true)
	}
	for _, id := range c.Acks {
		ks.sender.Ack(id)
	}
	if op == wire.AckV1 {
		return nil
	}
	if !s.opts.ResetOnly && ks.adapter.queued() >= inboundLimit {
		// Not acknowledged, so the server sends it again when TLS has caught
		// up. Its acknowledgements were taken above.
		s.drop("the TLS side has not read what is waiting", nil)
		return nil
	}
	payloads, ack := ks.receiver.Receive(c.PacketID, c.Payload)
	if !ack {
		s.drop("not accepted by the reliability layer", nil)
		return nil
	}
	if isReset && !ks.peerReset {
		ks.peerReset = true
		ks.wkcAsked = resend
		if len(payloads) > 0 {
			payloads = payloads[1:] // the payload of the reset is the TLVs, not TLS
		}
		if resend && s.opts.ResetOnly && !ks.wkcQueued {
			// The server asks for the wrapped key again, and there is no TLS
			// to send it with: an empty packet carries it, and the acknowledgement.
			ks.wkcQueued = true
			if _, err := ks.sender.Queue(wire.ControlWKCV1, nil); err != nil {
				return err
			}
		}
	}
	for _, p := range payloads {
		if s.opts.ResetOnly {
			s.drop("TLS bytes, and no TLS in this mode", nil)
			continue
		}
		ks.adapter.push(p)
	}
	return nil
}

// tlsMain runs the TLS handshake over the control channel of a key state, and then
// reads its control messages. It is the work of a goroutine of the session
// (startTLS): it ends when the session does, and when its key state is thrown away
// (the conn that crypto/tls reads and writes then fails). It returns the error that
// ended it, or nil; *made is set once the key exchange is done. A failure of key id 0
// ends the session; a failure of a renegotiation is told to the loop, which ends the
// session with it (tlsEnded).
func (s *Session) tlsMain(ks *keyState, made *bool) error {
	conn := tls.Client(ks.adapter, s.tlsCfg)
	if err := conn.Handshake(); err != nil {
		return errors.NewErr(TagTLSHandshakeFailed, err)
	}
	kx, err := s.keyExchange(ks, conn)
	if err != nil {
		return err
	}
	*made = true
	if ks.id == 0 {
		s.tlsConn, s.serverKX = conn, kx
		ks.tlsConn = conn
		s.ctlTLS.Store(conn)
	} else {
		select {
		case s.events <- keyEvent{ks: ks, conn: conn, state: conn.ConnectionState()}:
		case <-s.done:
			return nil
		}
	}
	return s.controlLoop(ks, conn)
}

// controlLoop reads the control messages that the server sends in TLS, for as
// long as the session lives. The handshake is complete when the PUSH_REPLY is:
// until then PUSH_REQUEST is sent every 5 seconds. Messages that are not yet
// understood are ignored and logged by name only. It returns the error that ends
// the session, or nil when the session or the key state ended first.
//
// OpenVPN: push.c send_push_request, incoming_push_message.
func (s *Session) controlLoop(ks *keyState, conn *tls.Conn) error {
	var pushed ctrlmsg.Pushed
	ready := ks.id != 0 // the push is of the first key only
	if !ready {
		s.wg.Add(1)
		go s.runPush()
	}
	buf := make([]byte, 1<<15)
	var stream []byte // bytes read that do not make a whole message yet
	for {
		n, err := conn.Read(buf)
		if err != nil {
			select {
			case <-s.done: // the session ended: this is how the read stops
			default:
				switch {
				case ks.closing.Load(): // the key was thrown away: this is how the read stops
				case s.ctlTLS.Load() == conn:
					return errors.NewErr(TagControlChannelFailed, err).SetMetadata("op", "read")
				default:
					s.log.Debug("the control channel of an old key ended", "key_id", ks.id, "err", err)
				}
			}
			return nil
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
			if err := s.control(record, &pushed, &ready); err != nil {
				return err
			}
		}
		if len(stream) > maxControlMessage {
			return errors.New(tagControlMessageTooLong, "a control message is too long", "max", maxControlMessage)
		}
		if len(stream) == 0 {
			stream = nil
		}
	}
}

// control handles one control message. It returns the error that ends the session
// (io.EOF for the server's EXIT once the handshake is complete), or nil.
func (s *Session) control(record []byte, pushed *ctrlmsg.Pushed, ready *bool) error {
	text := string(record[:len(record)-1]) // the text, without its NUL
	switch {
	case ctrlmsg.IsAuthFailed(text):
		f := ctrlmsg.ParseAuthFailed(text)
		return errors.New(TagAuthFailed, "the server refused the credentials",
			"reason", f.Reason, "session", f.Session, "temporary", f.Temporary,
			"backoff", int(f.Backoff/time.Second), "advance", f.Advance)
	case ctrlmsg.IsAuthPending(text):
		s.extendHandshake(ctrlmsg.ParseAuthPending(text))
		return nil
	case isExit(text):
		return s.serverExited()
	}
	if sig, ok := ctrlmsg.ParseSignal(text); ok {
		if sig.Restart {
			return errors.New(TagServerRestart, "the server asked the client to connect again", "reason", sig.Reason, "flags", sig.Flags)
		}
		return errors.New(TagServerHalt, "the server told the client to stop", "reason", sig.Reason)
	}
	if ctrlmsg.IsPushReply(text) && *ready {
		s.pushUpdate(text)
		return nil
	}
	if !ctrlmsg.IsPushReply(text) {
		s.log.Debug("ignored a control message", "name", ctrlmsg.Name(text))
		return nil
	}
	reply, err := ctrlmsg.ParsePushReply(text)
	if err != nil {
		return err
	}
	if s.opts.PullFilter != nil {
		if err := reply.Filter(s.opts.PullFilter); err != nil {
			return err
		}
	}
	if err := pushed.Add(reply, s.opts.Ciphers); err != nil {
		return err
	}
	if reply.More {
		return nil
	}
	if err := pushed.Finish(); err != nil {
		return err
	}
	for _, name := range pushed.Unknown {
		s.log.Warn("the server pushed an option that is not known", "option", name)
	}
	for _, o := range pushed.Skipped {
		s.log.Warn("the server pushed an option that cannot be read; it is left out", "option", o.Option, "problem", o.Problem)
	}
	state := s.tlsConn.ConnectionState()
	if err := s.setupData(pushed, &state); err != nil {
		return err
	}
	s.keepToken(pushed.AuthToken, pushed.AuthTokenUser)
	s.pushed, *ready = pushed, true
	close(s.pushDone)
	close(s.tlsReady)
	return nil
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

// pushRequests sends PUSH_REQUEST at once and then every 5 seconds over the TLS
// session of key id 0, until the reply is complete or the session ends. It returns
// the error of a write that failed, which ends the session.
func (s *Session) pushRequests() error {
	conn := s.tlsConn // set by the TLS goroutine of key id 0 before it starts this one
	request := ctrlmsg.AppendMessage(nil, ctrlmsg.PushRequest)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-s.pushDone:
			return nil
		case <-s.done:
			return nil
		case <-timer.C:
		}
		if _, err := conn.Write(request); err != nil {
			select {
			case <-s.done:
				return nil
			default:
				return errors.NewErr(TagControlChannelFailed, err).SetMetadata("op", "write")
			}
		}
		timer.Reset(pushRequestInterval)
	}
}

// keyExchange sends the client's key exchange message in one TLS record and
// reads the server's, which is one record too. The data keys do not come from
// it (SPEC §8.3), so what it gives the library is the server's strings.
//
// OpenVPN: ssl.c key_method_2_write, key_method_2_read.
func (s *Session) keyExchange(ks *keyState, conn *tls.Conn) (*ctrlmsg.ServerKeyExchange, error) {
	var username, password string
	again := false // the credentials are asked for again: auth-nocache, and no auth token
	if ks.id != 0 {
		username, password, again = s.renegotiationCredentials()
	}
	if (ks.id == 0 || again) && s.opts.Credentials != nil {
		var err error
		if username, password, err = s.opts.Credentials(s.ctx); err != nil {
			return nil, errors.NewErr(TagCredentialsFailed, err)
		}
		if ks.id == 0 {
			s.user = username // the name is kept: an auth token goes with it
			if !s.opts.AuthNoCache {
				s.pass = password
			}
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

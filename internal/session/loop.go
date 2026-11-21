// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl.c and ssl_pkt.c (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package session

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
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
			select {
			case <-s.done: // the link was closed by the session: not a failure
			default:
				s.readErr <- errors.NewErr(TagLinkFailed, err).SetMetadata("op", "read")
			}
			return
		}
		select {
		case s.in <- append([]byte(nil), buf[:n]...):
		case <-s.done:
			return
		}
	}
}

// loop owns the state: it handles the packets that the reader gives it, sends
// what is due, and runs the timers. It closes the link when it returns.
func (s *Session) loop() {
	defer s.wg.Done()
	defer s.closeLink()

	handshake := time.NewTimer(s.opts.HandshakeTimeout)
	defer handshake.Stop()
	retransmit := time.NewTimer(time.Hour)
	retransmit.Stop()
	defer retransmit.Stop()

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
		if !complete {
			switch {
			case s.opts.ResetOnly:
				complete = s.serverResetSeen && s.thirdSent && s.sender.Len() == 0
			default:
				complete = tlsReady == nil
			}
			if complete {
				handshake.Stop()
				close(s.ready)
			}
		}
		if at, ok := s.sender.NextDeadline(); ok {
			retransmit.Reset(max(0, time.Until(at)))
		} else {
			retransmit.Stop()
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
		case err := <-s.readErr:
			s.fail(err)
			return
		case <-handshake.C:
			s.fail(errors.New(TagHandshakeTimeout, "the handshake did not finish in time",
				"timeout", s.opts.HandshakeTimeout.String()))
			return
		case <-retransmit.C:
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
	if _, err := s.opts.Link.Write(out); err != nil {
		return errors.NewErr(TagLinkFailed, err).SetMetadata("op", "write")
	}
	if s.serverResetSeen && len(c.Acks) > 0 {
		s.thirdSent = true
	}
	return nil
}

// handle takes one packet from the link. Anyone can send a packet, so one that
// does not belong is dropped, and nothing in it is used before it is shown to
// be from the server: the protection first, then the session ids.
func (s *Session) handle(raw []byte) {
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

	// From here the packet is the server's.
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
	close(s.tlsReady)
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

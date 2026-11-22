// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl.c (generate_key_expansion_tls_export, init_key_contexts) and forward.c (process_incoming_link_part2, process_outgoing_tun) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
	"github.com/rm4n0s/gopenvpn-conn/internal/datachan"
	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
)

// recvQueue is how many decrypted packets wait for Read. A packet that comes when
// the queue is full is dropped, as a full buffer of a UDP socket drops it: the
// loop never waits for a reader, because it also runs the control channel.
const recvQueue = 512

// defaultMTU is the tunnel MTU when neither the server nor the options have one.
const defaultMTU = 1500

// pingString is the 16 bytes that OpenVPN sends as a keepalive on the data
// channel: a packet with this payload is not an IP packet.
//
// OpenVPN: ping.c ping_string.
var pingString = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

// exporter is what gives the key material: a tls.ConnectionState. The tests
// give one that fails.
type exporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// dataKey is the data channel of one key id.
type dataKey struct {
	id   uint8
	ch   datachan.Channel
	rbuf []byte // the loop's buffer for what it opens
}

// keyTable is the data keys that are valid: the one that Write seals with and the
// ones that the loop opens with, by key id. It is never changed after it is
// published; the loop makes a new one when a key comes or goes.
type keyTable struct {
	send *dataKey
	byID [datachan.MaxKeyID + 1]*dataKey
}

// dataPath is the data side of the session: the table of keys, what makes a new
// key, and the size of the largest packet.
type dataPath struct {
	mtu    int
	table  atomic.Pointer[keyTable]
	cipher datachan.Cipher
	header datachan.Header // the peer id; the key id is set for each key
	epoch  bool            // the format with epochs

	sem  chan struct{} // the right to write: Seal and wbuf, for many goroutines that may give up
	wbuf []byte
}

// setupData makes the data channel of key id 0 from the TLS session that is complete
// and the options that the server pushed: the keys from the TLS exporter, the cipher
// the server chose, the header with the peer id, and the format (32-bit packet ids,
// or epochs when protocol-flags has aead-epoch). It is called when the push reply is
// complete, before the handshake is.
//
// OpenVPN: ssl.c generate_key_expansion_tls_export, init_key_contexts.
func (s *Session) setupData(p *ctrlmsg.Pushed, x exporter) error {
	if p.KeyDerivation != "tls-ekm" && !slices.Contains(p.ProtocolFlags, "tls-ekm") {
		return errors.New(TagKeyDerivationUnsupported, "the server did not ask for the keys of the TLS exporter (key-derivation tls-ekm), which is the only way this library makes them",
			"key_derivation", p.KeyDerivation)
	}
	cipher, ok := datachan.LookupCipher(p.Cipher)
	if !ok {
		return errors.New(ctrlmsg.TagCipherNegotiationFailed, "the server did not push a data cipher this library has", "cipher", p.Cipher)
	}
	s.ccExit = hasFlag(p.ProtocolFlags, "cc-exit")
	d := &dataPath{
		mtu:    cmpOr(p.MTU, s.opts.MTU, defaultMTU),
		cipher: cipher,
		header: datachan.Header{HasPeerID: p.HasPeerID, PeerID: p.PeerID},
		epoch:  hasFlag(p.ProtocolFlags, "aead-epoch"),
		sem:    make(chan struct{}, 1),
	}
	k, err := s.makeKey(d, 0, x)
	if err != nil {
		return err
	}
	t := &keyTable{send: k}
	t.byID[0] = k
	d.table.Store(t)
	if hasFlag(p.ProtocolFlags, "dyn-tls-crypt") {
		if err := s.setupDynamic(x); err != nil {
			return err
		}
	}
	s.data.Store(d)
	return nil
}

// makeKey makes the data channel of a key id from the TLS session that made the key.
// This library is the TLS client: it sends with the client-to-server keys. The epoch
// format has a channel of its own; it exists only for DATA_V2.
func (s *Session) makeKey(d *dataPath, id uint8, x exporter) (*dataKey, error) {
	material, err := x.ExportKeyingMaterial(keys.ExportLabel, nil, keys.DataKeysSize)
	if err != nil {
		return nil, errors.NewErr(TagKeyExportFailed, err)
	}
	dk, err := keys.SplitDataKeys(material)
	clear(material)
	if err != nil {
		return nil, err
	}
	defer dk.Clear()
	header := d.header
	header.KeyID = id
	var ch datachan.Channel
	if d.epoch {
		ch, err = datachan.NewEpochChannel(d.cipher, &dk.ClientToServer, &dk.ServerToClient, header, datachan.EpochOptions{UsageLimit: s.opts.EpochUsageLimit})
	} else {
		ch, err = datachan.NewChannel(d.cipher, &dk.ClientToServer, &dk.ServerToClient, header, datachan.ReceiverOptions{UsageLimit: s.opts.UsageLimit})
	}
	if err != nil {
		return nil, err
	}
	return &dataKey{id: id, ch: ch}, nil
}

// cmpOr is the first of its arguments that is not zero.
func cmpOr(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

// handleData opens a packet of the data channel and queues the IP packet for
// Read. Anyone can send a packet to the client, so one that does not open, that is a
// replay, or that comes before the keys are there is dropped and counted; it never
// ends the session (SPEC §15 rule 7).
//
// OpenVPN: forward.c process_incoming_link_part2.
func (s *Session) handleData(raw []byte) {
	d := s.data.Load()
	if d == nil {
		s.drop("a data packet before the keys are made", nil)
		return
	}
	k := d.table.Load().byID[raw[0]&0x07]
	if k == nil {
		s.drop("a data packet of a key id that has no key", nil)
		return
	}
	plain, err := k.ch.Open(k.rbuf[:0], raw, time.Now())
	if err != nil {
		s.drop("a data packet that is refused", err)
		return
	}
	k.rbuf = plain[:0]
	if k.ch.NeedsRenegotiation() {
		s.requestRenegotiation(k.id)
	}
	s.lastRecv = time.Now() // authentic: a ping counts, though Read does not get it
	if bytes.Equal(plain, pingString) {
		s.log.Debug("a keepalive ping arrived")
		return
	}
	if isOCCExit(plain) {
		s.serverExited()
		return
	}
	pb := s.pool.get(len(plain))
	copy(pb.b, plain)
	select {
	case s.recv <- pb:
	default:
		s.pool.put(pb)
		s.drop("the packets for Read are not read", nil)
	}
}

// awaitReady waits for the handshake when it has not run, as the first Read or Write
// of a tls.Conn does, and returns the error of the session if it failed.
func (s *Session) awaitReady() error {
	select {
	case <-s.ready:
		return nil
	default:
	}
	return s.Handshake(context.Background())
}

// Read takes the next IP packet that the server sent, waiting for it. A buffer
// that is too small gets the start of the packet. It runs the handshake first when
// it has not run (the read deadline does not bound that: HandshakeTimeout does).
// When the session has ended it returns the error that ended it (net.ErrClosed
// after Close, io.EOF after the server's EXIT); when the read deadline passes,
// os.ErrDeadlineExceeded, even if a packet is waiting.
func (s *Session) Read(b []byte) (int, error) {
	if err := s.awaitReady(); err != nil {
		return 0, err
	}
	for {
		select {
		case <-s.done:
			return 0, s.result()
		default:
		}
		t, changed := s.rdl.get()
		if !t.IsZero() && !time.Now().Before(t) {
			return 0, errDeadline
		}
		timer, expired := timerFor(t)
		select {
		case pb := <-s.recv:
			stopTimer(timer)
			n := copy(b, pb.b)
			s.pool.put(pb)
			return n, nil
		case <-s.done:
			stopTimer(timer)
			return 0, s.result()
		case <-expired:
			return 0, errDeadline
		case <-changed:
			stopTimer(timer)
		}
	}
}

// Write sends one IP packet to the server. It runs the handshake first when it has
// not run. A packet larger than the MTU, or an empty one, is refused. When the
// session has ended it returns the error that ended it. When the write deadline
// passes, before the packet is out or while the link will not take it, it returns
// os.ErrDeadlineExceeded and the session goes on; the exception is a stream link
// that took a part of the frame, which cannot go on and ends the session. The packet
// ids of the key are used up only after a very long time; if they ever are, the
// session ends rather than repeat a nonce (SPEC §10).
//
// OpenVPN: forward.c process_outgoing_tun.
func (s *Session) Write(b []byte) (int, error) {
	if err := s.awaitReady(); err != nil {
		return 0, err
	}
	select {
	case <-s.done:
		return 0, s.result()
	default:
	}
	d := s.data.Load()
	if len(b) == 0 {
		return 0, errors.New(tagEmptyPacket, "an IP packet has at least one byte")
	}
	if len(b) > d.mtu {
		return 0, errors.New(TagPacketTooLarge, "the packet is larger than the MTU of the tunnel", "len", len(b), "mtu", d.mtu)
	}
	if err := s.lockWrite(d, true); err != nil {
		return 0, err
	}
	defer d.unlockWrite()
	if err := s.writeLocked(d, b, true); err != nil {
		if err == errDeadline {
			return 0, err
		}
		return 0, s.result()
	}
	return len(b), nil
}

// lockWrite takes the right to write data. It gives up when the session ends (the
// error that ended it) or, for a user's write, when the write deadline passes.
func (s *Session) lockWrite(d *dataPath, user bool) error {
	for {
		var t time.Time
		var changed <-chan struct{}
		if user {
			t, changed = s.wdl.get()
			if !t.IsZero() && !time.Now().Before(t) {
				return errDeadline
			}
		}
		timer, expired := timerFor(t)
		select {
		case d.sem <- struct{}{}:
			stopTimer(timer)
			return nil
		case <-s.done:
			stopTimer(timer)
			return s.result()
		case <-expired:
			return errDeadline
		case <-changed:
			stopTimer(timer)
		}
	}
}

func (d *dataPath) unlockWrite() { <-d.sem }

// writeLocked seals one IP packet (or the ping) and writes it to the link. The
// caller holds the right to write. A failure of the link, or the end of the packet
// ids, ends the session: it is made here and stored, and the returned error is that
// one. With user set the write deadline of the connection applies, and a deadline
// that passes gives errDeadline.
func (s *Session) writeLocked(d *dataPath, b []byte, user bool) error {
	d.wbuf = d.wbuf[:0]
	if s.opts.Stream {
		d.wbuf = append(d.wbuf, 0, 0) // the length of the frame goes here
	}
	k := d.table.Load().send
	packet, err := k.ch.Seal(d.wbuf, b)
	if err != nil {
		s.fail(err)
		return err
	}
	d.wbuf = packet
	if s.opts.Stream {
		binary.BigEndian.PutUint16(packet, uint16(min(len(packet)-2, 1<<16-1)))
	}
	var wd time.Time
	if user {
		wd, _ = s.wdl.get()
	}
	n, err := s.writeLink(packet, wd)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) && (!s.opts.Stream || n == 0) {
			return errDeadline // nothing of the packet is out: the session goes on
		}
		e := errors.NewErr(TagLinkFailed, err).SetMetadata("op", "write")
		s.fail(e)
		return e
	}
	s.touchSent()
	if k.ch.NeedsRenegotiation() {
		s.requestRenegotiation(k.id)
	}
	return nil
}

// writeLink writes one packet (or frame) to the link, with the deadline wd if it
// is not zero. The loop writes control packets to the same link, so the two take
// turns (linkSem), and the deadline never reaches a control write.
func (s *Session) writeLink(p []byte, wd time.Time) (int, error) {
	// A channel and not a mutex: a writer that waits for the other is then blocked in
	// a way that the fake clock of the tests sees, so that time goes on to the deadline
	// of the writer that holds the link.
	s.linkSem <- struct{}{}
	defer func() { <-s.linkSem }()
	if wd.IsZero() {
		return s.opts.Link.Write(p)
	}
	if err := s.opts.Link.SetWriteDeadline(wd); err != nil {
		return 0, err
	}
	n, err := s.opts.Link.Write(p)
	if rerr := s.opts.Link.SetWriteDeadline(time.Time{}); rerr != nil && err == nil {
		err = rerr
	}
	return n, err
}

const (
	// TagKeyDerivationUnsupported: the server did not push key-derivation
	// tls-ekm (or protocol-flags tls-ekm), so it expects the old derivation of the
	// data keys, which this library does not have (SPEC §8.3). Metadata:
	// "key_derivation".
	TagKeyDerivationUnsupported = "KeyDerivationUnsupported"
	// TagKeyExportFailed: the TLS session could not export the key material (a
	// TLS 1.2 session without the extended master secret). The cause is the
	// crypto/tls error.
	TagKeyExportFailed = "KeyExportFailed"
	// TagPacketTooLarge: Write got a packet larger than the MTU of the tunnel.
	// Metadata: "len" and "mtu".
	TagPacketTooLarge = "PacketTooLarge"

	tagEmptyPacket = "EmptyPacket"
)

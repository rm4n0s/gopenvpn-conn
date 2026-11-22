// SPDX-License-Identifier: GPL-2.0-only

// Based on OpenVPN 2.7.9, src/openvpn/crypto_epoch.c and src/openvpn/crypto.c
// (openvpn_encrypt_aead, openvpn_decrypt_aead, crypto_check_replay; Copyright
// (C) 2002-2026 OpenVPN Inc, 2024-2026 Arne Schwabe); rewritten in Go and changed
// for gopenvpn-conn, 2026-11-22.

package datachan

import (
	"crypto/cipher"
	"encoding/binary"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/replay"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

const (
	// DefaultFutureKeys is how many keys of the epochs after the current one a
	// receiver keeps, so that it can open the packets of a sender that moved on while
	// packets were lost. The draft and OpenVPN 2.7.9 say 4 (earlier versions kept 16).
	//
	// OpenVPN: ssl.c init_epoch_keys.
	DefaultFutureKeys = 4

	// RenegotiateEpoch is the send epoch from which a new key is due: the epochs
	// are 16 bits and must not run out.
	//
	// OpenVPN: ssl.c should_trigger_renegotiation.
	RenegotiateEpoch uint16 = 0xF000

	// maxCounter is the highest counter inside one epoch: it has 48 bits.
	maxCounter uint64 = 1<<48 - 1

	epochIDSize     = 8
	epochHeaderSize = 1 + peerIDSize + epochIDSize
	epochMinPacket  = epochHeaderSize + 1 + TagSize

	// aeadLimit is the usage limit of the AES-GCM key of an epoch: the packets
	// plus the 16-byte blocks that it protected, 2^36 - 1 (the draft's safety
	// margin of 2^-57). CHACHA20-POLY1305 has none.
	//
	// OpenVPN: crypto.c cipher_get_aead_limits.
	aeadLimit uint64 = 1<<36 - 1

	blockSize = 16
)

// Channel is the data channel of one key id, as the session uses it: Seal for
// Write, Open for the loop that reads the link. NewChannel makes one for the
// 32-bit packet id format and NewEpochChannel one for the epoch format.
type Channel interface {
	// Seal appends the packet that carries payload to dst.
	Seal(dst, payload []byte) ([]byte, error)
	// Open authenticates and decrypts a packet that arrived at now, appends the
	// payload to dst and returns the result.
	Open(dst, packet []byte, now time.Time) ([]byte, error)
	// NeedsRenegotiation reports whether a new key is due.
	NeedsRenegotiation() bool
	// Dropped counts the packets that Open refused, by reason.
	Dropped() Drops
}

// sealOpener is a Sender and a Receiver of the 32-bit format as one Channel.
type sealOpener struct {
	*Sender
	*Receiver
}

// NeedsRenegotiation is true when either direction of the key wants a new one.
func (p sealOpener) NeedsRenegotiation() bool {
	return p.Sender.NeedsRenegotiation() || p.Receiver.NeedsRenegotiation()
}

// NewChannel makes the Channel of the 32-bit packet id format from the keys of
// the two directions.
func NewChannel(c Cipher, send, receive *keys.DirectionKey, h Header, o ReceiverOptions) (Channel, error) {
	s, err := NewSender(c, send, h)
	if err != nil {
		return nil, err
	}
	if o.UsageLimit != 0 {
		s.limit = o.UsageLimit
	}
	r, err := NewReceiver(c, receive, h, o)
	if err != nil {
		return nil, err
	}
	return sealOpener{s, r}, nil
}

// EpochOptions tune an EpochChannel. The zero value is OpenVPN's default.
type EpochOptions struct {
	// Strict, Window and MaxAge are the replay protection of each epoch, as in
	// ReceiverOptions.
	Strict bool
	Window int
	MaxAge time.Duration
	// FutureKeys is how many future epoch keys the receiver keeps; DefaultFutureKeys
	// when zero.
	FutureKeys int
	// UsageLimit replaces the usage limit of the cipher. Only the tests set it, to
	// make a channel move through its epochs with a few packets.
	UsageLimit uint64
}

// epochState is a key of one epoch ready to use: the AEAD and the implicit IV.
type epochState struct {
	epoch uint16
	aead  cipher.AEAD
	iv    [nonceSize]byte
}

func newEpochState(c Cipher, e keys.EpochKey) (epochState, error) {
	key, iv, err := e.DataKey(c.keySize, nonceSize)
	if err != nil {
		return epochState{}, err
	}
	defer clear(key)
	aead, err := c.aead(key)
	if err != nil {
		return epochState{}, err
	}
	st := epochState{epoch: e.Epoch, aead: aead}
	copy(st.iv[:], iv)
	clear(iv)
	return st, nil
}

// recvSlot is a key that the receiver can open packets with, and the replay
// state of its epoch once the epoch is current or retiring.
type recvSlot struct {
	epochState
	window  *replay.Window // nil until the slot is current
	highest uint64         // strict order: the highest counter accepted
	blocks  uint64         // plaintext blocks opened with this key
}

// EpochChannel is the data channel of the epoch format (SPEC §10) for one key
// id: each direction has its own chain of epoch keys, a sender moves to the next
// epoch when the usage limit of its key is near, and a receiver keeps the current
// key, the one before and a few of the future ones. Seal calls must not overlap
// each other, and neither must Open calls; one Seal and one Open may run at the
// same time.
//
// Draft: "AEAD encrypted data channel packet with extended packet id and epoch
// keys", "OpenVPN epoch data channel keys".
type EpochChannel struct {
	cipher  Cipher
	header  Header
	limit   uint64
	strict  bool
	winSize int
	maxAge  time.Duration
	future  int

	sendMu sync.Mutex // the sender's state: Open moves it to a newer epoch
	send   struct {
		key     keys.EpochKey // E_n of the send epoch
		state   epochState
		counter uint64 // the counter of the last packet; 0 before the first
		blocks  uint64 // the 16-byte blocks that this key has protected
		nonce   [nonceSize]byte
	}

	recv struct { // owned by the goroutine that calls Open
		current  recvSlot
		retiring recvSlot   // epoch 0: none
		ahead    []recvSlot // the keys of the epochs after current, in order
		top      keys.EpochKey
		nonce    [nonceSize]byte
	}
	// The receiver's state that the sender reads.
	recvEpoch    atomic.Uint32
	recvLimitHit atomic.Bool

	drops dropCounters
}

// NewEpochChannel makes an EpochChannel from the keys of the two directions that
// the TLS exporter gave: the first 32 bytes of each cipher key are the secret of
// the epoch 1. The epoch format exists only for DATA_V2 (SPEC §10), so the header
// must have a peer id.
func NewEpochChannel(c Cipher, send, receive *keys.DirectionKey, h Header, o EpochOptions) (*EpochChannel, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	if !h.HasPeerID {
		return nil, errors.New(tagEpochNeedsPeerID, "the epoch format is only defined for DATA_V2, which needs a peer id")
	}
	if c.aead == nil {
		return nil, errors.New(tagBadCipher, "the cipher is not one of LookupCipher's")
	}
	ch := &EpochChannel{
		cipher: c, header: h, limit: o.UsageLimit, strict: o.Strict, winSize: o.Window, maxAge: o.MaxAge, future: o.FutureKeys,
	}
	if ch.limit == 0 && c.name != "CHACHA20-POLY1305" {
		ch.limit = aeadLimit
	}
	if ch.future <= 0 {
		ch.future = DefaultFutureKeys
	}
	if ch.winSize <= 0 {
		ch.winSize = defaultWindow
	}
	if ch.maxAge <= 0 {
		ch.maxAge = defaultMaxAge
	}

	e1 := keys.FirstEpochKey(send)
	st, err := newEpochState(c, e1)
	if err != nil {
		return nil, err
	}
	ch.send.key, ch.send.state = e1, st

	r1 := keys.FirstEpochKey(receive)
	cur, err := newEpochState(c, r1)
	if err != nil {
		return nil, err
	}
	ch.recv.current = recvSlot{epochState: cur, window: ch.newWindow()}
	ch.recv.top = r1
	if err := ch.fillAhead(); err != nil {
		return nil, err
	}
	ch.recvEpoch.Store(uint32(cur.epoch))
	return ch, nil
}

func (c *EpochChannel) newWindow() *replay.Window {
	if c.strict {
		return nil
	}
	return replay.NewWindow(c.winSize, c.maxAge)
}

// fillAhead derives the keys that are missing until the receiver has FutureKeys
// of them after the current epoch.
func (c *EpochChannel) fillAhead() error {
	for len(c.recv.ahead) < c.future {
		next, err := c.recv.top.Next()
		if err != nil {
			return err
		}
		st, err := newEpochState(c.cipher, next)
		if err != nil {
			return err
		}
		c.recv.top = next
		c.recv.ahead = append(c.recv.ahead, recvSlot{epochState: st})
	}
	return nil
}

// SendEpoch is the epoch that Seal uses now.
func (c *EpochChannel) SendEpoch() uint16 {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.send.state.epoch
}

// ReceiveEpoch is the current epoch of the receiver.
func (c *EpochChannel) ReceiveEpoch() uint16 { return uint16(c.recvEpoch.Load() & 0xffff) }

// NeedsRenegotiation reports whether the send epoch is so high that the epochs
// would run out: a new TLS session is due (OpenVPN asks at 0xF000).
func (c *EpochChannel) NeedsRenegotiation() bool { return c.SendEpoch() >= RenegotiateEpoch }

// Dropped counts the packets that Open refused, by reason.
func (c *EpochChannel) Dropped() Drops { return c.drops.snapshot() }

// iterateSend moves the sender to the next epoch. The caller holds sendMu.
func (c *EpochChannel) iterateSend() error {
	next, err := c.send.key.Next()
	if err != nil {
		return err
	}
	return c.setSend(next)
}

// setSend makes e the key of the sender, with a counter that starts again: the
// nonce of a new key cannot repeat one of the old. The caller holds sendMu.
func (c *EpochChannel) setSend(e keys.EpochKey) error {
	st, err := newEpochState(c.cipher, e)
	if err != nil {
		return err
	}
	c.send.key.Clear()
	c.send.key, c.send.state = e, st
	c.send.counter, c.send.blocks = 0, 0
	return nil
}

// moveSendTo makes the send epoch at least epoch, by iterating the key. The
// caller holds sendMu.
func (c *EpochChannel) moveSendTo(epoch uint16) error {
	if c.send.key.Epoch >= epoch {
		return nil
	}
	e := c.send.key
	for e.Epoch < epoch {
		var err error
		if e, err = e.Next(); err != nil {
			return err
		}
	}
	return c.setSend(e)
}

// checkIterate moves the sender to the next epoch when its key has done its share:
// the usage limit of the cipher, the limit of the receive key (which pushes the
// peer to a new epoch too), or the end of the 48-bit counter. The caller holds
// sendMu.
//
// OpenVPN: crypto_epoch.c epoch_check_send_iterate. Deviation: it also moves on
// when the peer's packets fail verification too often; here a forged packet is
// only counted (SPEC §20 V10).
func (c *EpochChannel) checkIterate() error {
	if c.send.state.epoch == keys.MaxEpoch {
		return nil
	}
	if c.limit > 0 {
		switch {
		case c.send.blocks+c.send.counter > c.limit:
			return c.iterateSend()
		case uint32(c.send.state.epoch) == c.recvEpoch.Load() && c.recvLimitHit.Load():
			return c.iterateSend()
		}
	}
	if c.send.counter == maxCounter {
		return c.iterateSend()
	}
	return nil
}

// Seal appends the packet that carries payload to dst: the first byte, the peer
// id, the 64-bit packet id (the epoch and its counter), the encrypted payload and
// the tag. With room in dst it allocates nothing. When the counter of the last
// epoch is used up it returns an error and the session must end.
//
// OpenVPN: crypto.c openvpn_encrypt_aead (the epoch branches).
func (c *EpochChannel) Seal(dst, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return dst, errors.New(tagEmptyPayload, "a data packet needs at least one byte of payload")
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if err := c.checkIterate(); err != nil {
		return dst, err
	}
	if c.send.counter == maxCounter {
		return dst, errors.New(tagPacketIDExhausted, "every packet id of the last epoch has been used")
	}
	c.send.counter++
	st := &c.send.state

	start := len(dst)
	dst = slices.Grow(dst, epochMinPacket+len(payload))
	dst = append(dst, byte(wire.DataV2)<<3|c.header.KeyID)
	var peer [4]byte
	binary.BigEndian.PutUint32(peer[:], c.header.PeerID)
	dst = append(dst, peer[1:]...) // the low 24 bits
	dst = binary.BigEndian.AppendUint64(dst, uint64(st.epoch)<<48|c.send.counter)
	ad := dst[start:]

	// The nonce is the packet id, then 4 zero bytes, XORed with the implicit IV.
	n := &c.send.nonce
	*n = [nonceSize]byte{}
	copy(n[:epochIDSize], ad[1+peerIDSize:])
	for i := range n {
		n[i] ^= st.iv[i]
	}
	dst = st.aead.Seal(dst, n[:], payload, ad)
	c.send.blocks += (uint64(len(payload)&0x7fffffff) + epochIDSize + blockSize - 1) / blockSize // OpenVPN counts the packet id too
	return dst, nil
}

// lookup finds the key for an epoch: the current one, the retiring one, or one of
// the future keys. The last epochs, whose future keys would run past 0xffff, have
// no future keys at all.
//
// OpenVPN: crypto_epoch.c epoch_lookup_decrypt_key.
func (c *EpochChannel) lookup(epoch uint16) (slot *recvSlot, ahead int) {
	r := &c.recv
	switch {
	case epoch == 0:
		return nil, -1
	case epoch == r.current.epoch:
		return &r.current, -1
	case r.retiring.epoch != 0 && epoch == r.retiring.epoch:
		return &r.retiring, -1
	case epoch > r.current.epoch && int(epoch) <= int(r.current.epoch)+c.future:
		if int(epoch) > keys.MaxEpoch-c.future-1 {
			return nil, -1
		}
		i := int(epoch-r.current.epoch) - 1
		return &r.ahead[i], i
	}
	return nil, -1
}

// Open authenticates and decrypts a packet, appends its payload to dst and
// returns the result. A packet of an epoch after the current one that
// authenticates makes that epoch current, and the sender follows it if it is
// behind: the draft says a receiver SHOULD. A packet that is not good is dropped:
// the error says why, and no such error ends a session (SPEC §15 rule 7). packet
// is not changed.
//
// OpenVPN: crypto.c openvpn_decrypt_aead, crypto_check_replay and
// crypto_epoch.c epoch_replace_update_recv_key.
func (c *EpochChannel) Open(dst, packet []byte, now time.Time) ([]byte, error) {
	h := c.header
	if len(packet) < epochMinPacket {
		c.drops.short.Add(1)
		return dst, errors.New(tagPacketTooShort, "the packet has no room for its header, its tag and a byte of payload", "len", len(packet), "min", epochMinPacket)
	}
	if wire.Opcode(packet[0]>>3) != wire.DataV2 {
		c.drops.format.Add(1)
		return dst, errors.New(tagWrongFormat, "the packet is not of the format of this key", "opcode", packet[0]>>3, "want", int(wire.DataV2))
	}
	if packet[0]&0x07 != h.KeyID {
		c.drops.keyID.Add(1)
		return dst, errors.New(tagWrongKeyID, "the packet is of another key id", "key_id", packet[0]&0x07, "want", h.KeyID)
	}
	id := binary.BigEndian.Uint64(packet[1+peerIDSize:])
	epoch, counter := uint16(id>>48&0xffff), id&maxCounter
	slot, ahead := c.lookup(epoch)
	if slot == nil {
		c.drops.epoch.Add(1)
		return dst, errors.New(tagUnknownEpoch, "the epoch of the packet is not one that has a key", "epoch", epoch, "current", c.recv.current.epoch)
	}
	// A key that is current or retiring has replay state: a cheap refusal that
	// changes nothing. A future key has none yet.
	if ahead < 0 && !c.fresh(slot, counter, now) {
		c.drops.replay.Add(1)
		return dst, errors.New(tagReplayed, "the packet id was seen, is too old or is out of order", "epoch", epoch, "counter", counter)
	}

	n := &c.recv.nonce
	*n = [nonceSize]byte{}
	copy(n[:epochIDSize], packet[1+peerIDSize:epochHeaderSize])
	for i := range n {
		n[i] ^= slot.iv[i]
	}
	out, err := slot.aead.Open(dst, n[:], packet[epochHeaderSize:], packet[:epochHeaderSize])
	if err != nil {
		c.drops.auth.Add(1)
		return dst, errors.NewErr(tagAuthFailed, err)
	}

	if ahead >= 0 {
		if err := c.promote(ahead); err != nil {
			return dst, err
		}
		slot = &c.recv.current
	}
	if !c.fresh(slot, counter, now) { // after the move, for a key that is new this is true
		c.drops.replay.Add(1)
		return dst, errors.New(tagReplayed, "the packet id was seen, is too old or is out of order", "epoch", epoch, "counter", counter)
	}
	c.accept(slot, counter, now)
	slot.blocks += (uint64((len(out)-len(dst))&0x7fffffff) + blockSize - 1) / blockSize
	if slot == &c.recv.current {
		c.recvLimitHit.Store(c.limit > 0 && slot.blocks+slot.highest > c.limit)
	}
	return out, nil
}

// fresh says whether a counter may be taken in the epoch of the slot. It changes
// nothing.
func (c *EpochChannel) fresh(s *recvSlot, counter uint64, now time.Time) bool {
	if c.strict {
		return counter != 0 && (s.highest == 0 || counter == s.highest+1)
	}
	return s.window.Check(counter, now)
}

// accept records the counter of a packet that authenticated.
func (c *EpochChannel) accept(s *recvSlot, counter uint64, now time.Time) {
	if c.strict {
		s.highest = counter
		return
	}
	s.window.Accept(counter, now)
	s.highest = max(s.highest, counter)
}

// promote makes the future key at index i the current one: the old current key
// becomes the retiring one (keeping its replay state), the keys before i are gone,
// the sender moves to the new epoch if it is behind, and new future keys are
// derived to have FutureKeys of them again.
//
// OpenVPN: crypto_epoch.c epoch_replace_update_recv_key.
func (c *EpochChannel) promote(i int) error {
	r := &c.recv
	epoch := r.ahead[i].epoch
	c.sendMu.Lock()
	err := c.moveSendTo(epoch)
	c.sendMu.Unlock()
	if err != nil {
		return err
	}
	next := r.ahead[i]
	next.window = c.newWindow()
	r.retiring = r.current
	r.current = next
	r.ahead = append(r.ahead[:0:0], r.ahead[i+1:]...)
	if err := c.fillAhead(); err != nil {
		return err
	}
	c.recvEpoch.Store(uint32(epoch))
	c.recvLimitHit.Store(false)
	return nil
}

const (
	tagEpochNeedsPeerID = "DataEpochNeedsPeerID"
	tagUnknownEpoch     = "DataPacketUnknownEpoch"
)

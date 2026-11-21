// SPDX-License-Identifier: GPL-2.0-only

// Based on OpenVPN 2.7.9, src/openvpn/crypto.c (openvpn_encrypt_aead,
// openvpn_decrypt_aead; Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and
// changed for gopenvpn-conn, 2026-11-22.

package datachan

import (
	"crypto/cipher"
	"encoding/binary"
	"math"
	"slices"
	"sync/atomic"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/replay"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

const (
	// RenegotiateAt is the packet id from which a sender asks for a new key: the
	// ids that are left (about 16 million) are time enough for the renegotiation.
	//
	// OpenVPN: packet_id.h PACKET_ID_WRAP_TRIGGER.
	RenegotiateAt uint32 = 0xFF000000

	// MaxPeerID is the largest peer id of a DATA_V2 packet: it has 24 bits.
	MaxPeerID = 1<<24 - 1
	// MaxKeyID is the largest key id: it has 3 bits.
	MaxKeyID = 7

	packetIDSize = 4
	peerIDSize   = 3

	// Defaults of the replay window of a datagram link.
	//
	// OpenVPN: packet_id.h DEFAULT_SEQ_BACKTRACK, DEFAULT_TIME_BACKTRACK.
	defaultWindow = 64
	defaultMaxAge = 15 * time.Second
)

// Header says how the packets of one key look: DATA_V2 when the server pushed
// a peer id, DATA_V1 when it did not.
type Header struct {
	// KeyID is the key id (0 to 7) of the packets, in their first byte.
	KeyID uint8
	// HasPeerID selects DATA_V2, whose header has PeerID.
	HasPeerID bool
	// PeerID is the 24-bit peer id that the server pushed, for DATA_V2.
	PeerID uint32
}

func (h Header) validate() error {
	if h.KeyID > MaxKeyID {
		return errors.New(tagBadHeader, "the key id has more than 3 bits", "key_id", h.KeyID)
	}
	if h.HasPeerID && h.PeerID > MaxPeerID {
		return errors.New(tagBadHeader, "the peer id has more than 24 bits", "peer_id", h.PeerID)
	}
	return nil
}

// opcode is the opcode of the packets of the header.
func (h Header) opcode() wire.Opcode {
	if h.HasPeerID {
		return wire.DataV2
	}
	return wire.DataV1
}

// headerSize is the length of the packet up to the packet id's end: the first
// byte, the peer id of DATA_V2, and the packet id.
func (h Header) headerSize() int {
	if h.HasPeerID {
		return 1 + peerIDSize + packetIDSize
	}
	return 1 + packetIDSize
}

// minPacket is the shortest packet that can be valid: the header, the tag and
// one byte of payload.
func (h Header) minPacket() int { return h.headerSize() + TagSize + 1 }

// aead makes the AEAD of a direction, and its implicit IV.
func newDirection(c Cipher, k *keys.DirectionKey) (aead cipher.AEAD, iv [implicitIVSize]byte, err error) {
	if c.aead == nil {
		return nil, iv, errors.New(tagBadCipher, "the cipher is not one of LookupCipher's")
	}
	a, err := c.aead(k.Cipher[:c.keySize])
	if err != nil {
		return nil, iv, err
	}
	copy(iv[:], k.HMAC[:implicitIVSize])
	return a, iv, nil
}

// Sender seals the packets of one key. The packet ids start at 1 and grow by
// one; none is used twice (SPEC §10). It is not safe for concurrent use.
type Sender struct {
	aead   cipher.AEAD
	iv     [implicitIVSize]byte
	header Header
	next   uint32 // the id of the next packet
	done   bool   // every id was used
	nonce  [nonceSize]byte
}

// NewSender makes a Sender that seals with the cipher and the key of one
// direction.
func NewSender(c Cipher, k *keys.DirectionKey, h Header) (*Sender, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	aead, iv, err := newDirection(c, k)
	if err != nil {
		return nil, err
	}
	return &Sender{aead: aead, iv: iv, header: h, next: 1}, nil
}

// NeedsRenegotiation reports whether so many packets were sent that a new key
// is due (RenegotiateAt). The sender goes on until the ids end.
func (s *Sender) NeedsRenegotiation() bool { return s.done || s.next >= RenegotiateAt }

// SetNextID makes id the id of the next packet. It is for the tests of the end of
// the ids, which no real session reaches in a test's time; nothing else calls it.
func (s *Sender) SetNextID(id uint32) { s.next, s.done = id, false }

// Seal appends the packet that carries payload to dst and returns the result:
// the first byte, the peer id (DATA_V2), the packet id, the tag and the
// encrypted payload. With room in dst it allocates nothing. It never reuses a
// packet id: when the last one has been used it returns an error, and the
// session must end.
//
// OpenVPN: crypto.c openvpn_encrypt_aead. Draft: "AEAD encrypted data channel
// packet" (the tag is before the ciphertext; Go's AEAD puts it after, so the
// ciphertext is sealed in its final place and the tag is moved).
func (s *Sender) Seal(dst, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return dst, errors.New(tagEmptyPayload, "a data packet needs at least one byte of payload")
	}
	if s.done {
		return dst, errors.New(tagPacketIDExhausted, "every packet id of this key has been used")
	}
	id := s.next
	if id == math.MaxUint32 {
		s.done = true
	} else {
		s.next++
	}

	start := len(dst)
	dst = slices.Grow(dst, s.header.minPacket()+len(payload))
	dst = append(dst, byte(s.header.opcode())<<3|s.header.KeyID)
	if s.header.HasPeerID {
		var peer [4]byte
		binary.BigEndian.PutUint32(peer[:], s.header.PeerID)
		dst = append(dst, peer[1:]...) // the low 24 bits
	}
	dst = binary.BigEndian.AppendUint32(dst, id)
	headerEnd := len(dst)
	// The additional data: the whole header of DATA_V2, the packet id of DATA_V1.
	adStart := start
	if !s.header.HasPeerID {
		adStart = headerEnd - packetIDSize
	}
	ad := dst[adStart:headerEnd]

	s.nonce = nonceOf(id, s.iv)
	// The tag's place is left empty: Seal appends the ciphertext after it, and the
	// tag, which it appends last, is moved there.
	dst = dst[:headerEnd+TagSize]
	dst = s.aead.Seal(dst, s.nonce[:], payload, ad)
	end := len(dst) - TagSize
	copy(dst[headerEnd:headerEnd+TagSize], dst[end:])
	return dst[:end], nil
}

// nonceOf is the nonce of a packet: its id, then the implicit IV.
func nonceOf(id uint32, iv [implicitIVSize]byte) (n [nonceSize]byte) {
	binary.BigEndian.PutUint32(n[:], id)
	copy(n[packetIDSize:], iv[:])
	return n
}

// Drops counts the packets that a Receiver refused, by the reason.
type Drops struct {
	// Epoch is packets of an epoch that is not known: 0, or too far from the
	// current one (the epoch format only).
	Epoch uint64
	// Short is packets too short to hold a header, a tag and a byte of payload.
	Short uint64
	// Format is packets that are not of the format of the receiver (the opcode).
	Format uint64
	// KeyID is packets of another key id.
	KeyID uint64
	// Replay is packets that the replay protection refused: a repeated id, one that
	// is too old, or, with strict order, one that is not the next.
	Replay uint64
	// Auth is packets that did not authenticate.
	Auth uint64
}

// Receiver opens the packets of one key and drops what is not good. A packet
// is authenticated before its packet id is accepted, so a forged packet changes
// nothing. It is not safe for concurrent use, except Dropped.
type Receiver struct {
	aead    cipher.AEAD
	iv      [implicitIVSize]byte
	header  Header
	window  *replay.Window // nil with strict order
	strict  bool
	highest uint32 // strict order: the highest id accepted, 0 before the first
	nonce   [nonceSize]byte
	scratch []byte // the ciphertext and the tag, in the order Go's AEAD wants them

	drops dropCounters
}

// dropCounters are the counters of Drops, safe to read from any goroutine.
type dropCounters struct {
	short, format, keyID, replay, auth, epoch atomic.Uint64
}

func (d *dropCounters) snapshot() Drops {
	return Drops{
		Short: d.short.Load(), Format: d.format.Load(), KeyID: d.keyID.Load(),
		Replay: d.replay.Load(), Auth: d.auth.Load(), Epoch: d.epoch.Load(),
	}
}

// ReceiverOptions tune the replay protection. The zero value is OpenVPN's
// default for a datagram link: a window of 64 packets and 15 seconds.
type ReceiverOptions struct {
	// Strict makes the receiver accept only packets in order, each id one more than
	// the last (the first may be any id above 0), as OpenVPN does with a stream
	// link, where packets cannot be lost or reordered.
	Strict bool
	// Window is the size of the window of a datagram link, in packets; 0 is 64.
	Window int
	// MaxAge is how late a packet may arrive after one with a higher id; 0 is 15
	// seconds.
	MaxAge time.Duration
}

// NewReceiver makes a Receiver for the packets that arrive with the key of one
// direction. Only the key id of the header is checked on arrival; the peer id is
// part of the authenticated data and is not compared.
func NewReceiver(c Cipher, k *keys.DirectionKey, h Header, opts ReceiverOptions) (*Receiver, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	aead, iv, err := newDirection(c, k)
	if err != nil {
		return nil, err
	}
	r := &Receiver{aead: aead, iv: iv, header: h, strict: opts.Strict}
	if !opts.Strict {
		size, age := opts.Window, opts.MaxAge
		if size <= 0 {
			size = defaultWindow
		}
		if age <= 0 {
			age = defaultMaxAge
		}
		r.window = replay.NewWindow(size, age)
	}
	return r, nil
}

// Dropped is how many packets were refused so far, by reason. It may be called
// from any goroutine.
func (r *Receiver) Dropped() Drops { return r.drops.snapshot() }

// Open authenticates and decrypts a packet, appends its payload to dst and
// returns the result. now is the time of its arrival, for the age rule of the
// replay window. A packet that is not good is dropped: the error says why, and the
// caller goes on with the next packet; no such error is a reason to end a session
// (SPEC §15 rule 7). packet is not changed.
//
// OpenVPN: crypto.c openvpn_decrypt_aead and crypto_check_replay.
func (r *Receiver) Open(dst, packet []byte, now time.Time) ([]byte, error) {
	h := r.header
	if len(packet) < h.minPacket() {
		r.drops.short.Add(1)
		return dst, errors.New(tagPacketTooShort, "the packet has no room for its header, its tag and a byte of payload", "len", len(packet), "min", h.minPacket())
	}
	if wire.Opcode(packet[0]>>3) != h.opcode() {
		r.drops.format.Add(1)
		return dst, errors.New(tagWrongFormat, "the packet is not of the format of this key", "opcode", packet[0]>>3, "want", int(h.opcode()))
	}
	if packet[0]&0x07 != h.KeyID {
		r.drops.keyID.Add(1)
		return dst, errors.New(tagWrongKeyID, "the packet is of another key id", "key_id", packet[0]&0x07, "want", h.KeyID)
	}
	headerEnd := h.headerSize()
	id := binary.BigEndian.Uint32(packet[headerEnd-packetIDSize:])
	if !r.fresh(id, now) {
		r.drops.replay.Add(1)
		return dst, errors.New(tagReplayed, "the packet id was seen, is too old or is out of order", "id", id)
	}

	adStart := 0
	if !h.HasPeerID {
		adStart = headerEnd - packetIDSize
	}
	tag := packet[headerEnd : headerEnd+TagSize]
	r.scratch = append(append(r.scratch[:0], packet[headerEnd+TagSize:]...), tag...)
	r.nonce = nonceOf(id, r.iv)
	out, err := r.aead.Open(dst, r.nonce[:], r.scratch, packet[adStart:headerEnd])
	if err != nil {
		r.drops.auth.Add(1)
		return dst, errors.NewErr(tagAuthFailed, err)
	}
	r.accept(id, now)
	return out, nil
}

// fresh says whether a packet id may be taken. It changes nothing.
func (r *Receiver) fresh(id uint32, now time.Time) bool {
	if r.strict {
		return id != 0 && (r.highest == 0 || id == r.highest+1)
	}
	return r.window.Check(uint64(id), now)
}

// accept records the id of a packet that authenticated.
func (r *Receiver) accept(id uint32, now time.Time) {
	if r.strict {
		r.highest = id
		return
	}
	r.window.Accept(uint64(id), now)
}

const (
	tagBadHeader         = "DataHeaderInvalid"
	tagBadCipher         = "DataCipherInvalid"
	tagEmptyPayload      = "DataPayloadEmpty"
	tagPacketTooShort    = "DataPacketTooShort"
	tagWrongFormat       = "DataPacketWrongFormat"
	tagWrongKeyID        = "DataPacketWrongKeyID"
	tagReplayed          = "DataPacketReplayed"
	tagAuthFailed        = "DataPacketAuthFailed"
	tagPacketIDExhausted = "DataPacketIDExhausted"
)

// TagPacketIDExhausted is the tag of the error of Seal when every packet id of
// the key has been used. A caller that keeps sending after NeedsRenegotiation
// reaches it; the session ends with it rather than repeat a nonce.
const TagPacketIDExhausted = tagPacketIDExhausted

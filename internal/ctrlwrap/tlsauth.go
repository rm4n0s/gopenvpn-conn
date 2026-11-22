// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"sync"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/replay"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

const (
	// replayWindowSize and replayMaxAge are the replay protection of the
	// control channel: OpenVPN's defaults, 64 counters and 15 seconds.
	replayWindowSize = 64
	replayMaxAge     = 15 * time.Second

	// replayIDSize is the packet id (4 bytes) and the time (4 bytes) that every
	// protected packet carries.
	replayIDSize = 8
)

// tlsAuth is tls-auth: the packet is authenticated with an HMAC and not
// encrypted.
type tlsAuth struct {
	static   keys.StaticKey // the key as it was given, for dynamic tls-crypt
	hmacSize int
	now      func() time.Time

	sendMu  sync.Mutex
	sender  *replay.Sender
	sendMAC hash.Hash

	recvMu  sync.Mutex
	window  *replay.Window
	recvMAC hash.Hash
}

// NewTLSAuth returns the Wrapper of tls-auth, "HMAC authentication of control
// channel packets" in the draft.
//
// A packet is: the first byte, the session id of the sender, an HMAC of the
// size of the hash, a replay packet id (4 bytes, then 4 bytes of time), and the
// body. The HMAC covers, in this order, the replay packet id, the first byte,
// the session id and the body: not the order on the wire. Its key is the first
// bytes of an HMAC key of the static key, as many as the hash gives; dir says
// which of the two keys sends and which receives (a client has keys.Inverse).
// newHash is the digest: SHA-1 unless the profile says --auth.
//
// now is the clock (nil is time.Now). It stamps the packets and runs the age
// rule of the replay window. NewTLSAuth panics when key or newHash is nil.
func NewTLSAuth(key *keys.StaticKey, dir keys.Direction, newHash func() hash.Hash, now func() time.Time) (Wrapper, error) {
	if key == nil || newHash == nil {
		panic("ctrlwrap: NewTLSAuth needs a key and a hash")
	}
	if now == nil {
		now = time.Now
	}
	send, receive, err := key.Parts(dir)
	if err != nil {
		return nil, err
	}
	size := newHash().Size()
	if size > keys.PartSize {
		return nil, errors.New(tagHashTooLarge, "the hash is larger than the HMAC key of a static key", "size", size, "max", keys.PartSize)
	}
	return &tlsAuth{
		static:   *key,
		hmacSize: size,
		now:      now,
		sender:   replay.NewSender(0),
		sendMAC:  hmac.New(newHash, send.HMAC[:size]),
		window:   replay.NewWindow(replayWindowSize, replayMaxAge),
		recvMAC:  hmac.New(newHash, receive.HMAC[:size]),
	}, nil
}

func (w *tlsAuth) Overhead() int { return w.hmacSize + replayIDSize }

func (w *tlsAuth) Wrap(dst []byte, first byte, sid wire.SessionID, body []byte) ([]byte, error) {
	w.sendMu.Lock()
	defer w.sendMu.Unlock()

	id, sent, err := w.sender.Next(w.now())
	if err != nil {
		return dst, err
	}
	var replayID [replayIDSize]byte
	binary.BigEndian.PutUint32(replayID[:4], id)
	binary.BigEndian.PutUint32(replayID[4:], sent)

	mac := w.sendMAC
	mac.Reset()
	mac.Write(replayID[:])
	mac.Write([]byte{first})
	mac.Write(sid[:])
	mac.Write(body)

	dst = append(dst, first)
	dst = append(dst, sid[:]...)
	dst = mac.Sum(dst)
	dst = append(dst, replayID[:]...)
	return append(dst, body...), nil
}

func (w *tlsAuth) Unwrap(packet []byte) ([]byte, error) {
	idStart := headerSize + w.hmacSize
	bodyStart := idStart + replayIDSize
	if len(packet) < bodyStart {
		return nil, errors.New(tagTLSAuthTooShort, "the packet is shorter than its header", "want", bodyStart, "got", len(packet))
	}
	first, sid := packet[0], packet[1:headerSize]
	gotMAC, replayID, body := packet[headerSize:idStart], packet[idStart:bodyStart], packet[bodyStart:]

	id := binary.BigEndian.Uint32(replayID[:4])
	sent := binary.BigEndian.Uint32(replayID[4:])
	if id == 0 {
		return nil, errors.New(tagTLSAuthPacketIDZero, "the packet id is 0: ids start at 1")
	}
	counter := uint64(sent)<<32 | uint64(id)

	w.recvMu.Lock()
	defer w.recvMu.Unlock()
	now := w.now()
	// The replay check comes first because it is cheap; nothing is recorded
	// until the HMAC has been checked.
	if !w.window.Check(counter, now) {
		return nil, errors.New(tagTLSAuthReplay, "the packet is a replay or too old", "id", id, "time", sent)
	}
	mac := w.recvMAC
	mac.Reset()
	mac.Write(replayID)
	mac.Write([]byte{first})
	mac.Write(sid)
	mac.Write(body)
	var sum [64]byte // the largest hash that a static key can serve
	if !hmac.Equal(gotMAC, mac.Sum(sum[:0])) {
		return nil, errors.New(tagTLSAuthHMACMismatch, "the HMAC of the packet is wrong")
	}
	w.window.Accept(counter, now)
	return body, nil
}

const (
	tagHashTooLarge        = "HashTooLarge"
	tagTLSAuthTooShort     = "TLSAuthTooShort"
	tagTLSAuthPacketIDZero = "TLSAuthPacketIDZero"
	tagTLSAuthReplay       = "TLSAuthReplay"
	tagTLSAuthHMACMismatch = "TLSAuthHMACMismatch"
)

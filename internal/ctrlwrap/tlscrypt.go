// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
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
	// cryptKeySize is the size of the AES-256 key and of the HMAC-SHA256 key:
	// the first 32 bytes of the cipher key and of the HMAC key of a static key.
	cryptKeySize = 32

	// cryptTagSize is the size of the authentication tag, an HMAC-SHA256.
	cryptTagSize = sha256.Size

	// cryptHeaderSize is what is authenticated and not encrypted: the first
	// byte, the session id and the replay packet id (4 bytes, then 4 bytes of
	// time).
	cryptHeaderSize = headerSize + replayIDSize
)

// tlsCrypt is tls-crypt: the body is encrypted with AES-256-CTR and the packet
// is authenticated with an HMAC-SHA256 that is also the IV.
type tlsCrypt struct {
	now func() time.Time

	sendMu    sync.Mutex
	sender    *replay.Sender
	sendMAC   hash.Hash
	sendBlock cipher.Block

	recvMu    sync.Mutex
	window    *replay.Window
	recvMAC   hash.Hash
	recvBlock cipher.Block
}

// NewTLSCrypt returns the Wrapper of a client with tls-crypt, "Encrypting
// control channel packets (tls-crypt)" in the draft. The key is the static key
// of the tls-crypt option; a client sends with its second key and receives
// with its first (keys.Inverse), whatever key-direction says: tls-crypt has no
// such choice.
//
// A packet is: the first byte, the session id of the sender, a replay packet
// id (4 bytes, then 4 bytes of time), a tag of 32 bytes, and the body
// encrypted. The tag is HMAC-SHA256 over the first byte, the session id, the
// replay packet id and the body (the plaintext). The IV is the first 16 bytes
// of the tag, and the cipher is AES-256-CTR: so no padding, and the same
// plaintext under the same replay id gives the same packet, never the same
// stream for two different plaintexts.
//
// now is the clock (nil is time.Now). NewTLSCrypt panics when key is nil.
func NewTLSCrypt(key *keys.StaticKey, now func() time.Time) (Wrapper, error) {
	return newTLSCrypt(key, keys.Inverse, 0, now)
}

// NewTLSCryptServer returns the Wrapper of the other end of tls-crypt: the one
// that sends with the first key of the static key and receives with the second
// (keys.Normal). A client never needs it; the server of a test does.
func NewTLSCryptServer(key *keys.StaticKey, now func() time.Time) (Wrapper, error) {
	return newTLSCrypt(key, keys.Normal, 0, now)
}

// newTLSCrypt makes the Wrapper for a direction. startID is the id before the
// first one that is sent: tls-crypt-v2 starts at 0x0f000000.
func newTLSCrypt(key *keys.StaticKey, dir keys.Direction, startID uint32, now func() time.Time) (*tlsCrypt, error) {
	if key == nil {
		panic("ctrlwrap: NewTLSCrypt needs a key")
	}
	if dir != keys.Normal && dir != keys.Inverse {
		return nil, errors.New(tagTLSCryptNeedsDirection, "tls-crypt sends with one key and receives with the other", "direction", dir.String())
	}
	if now == nil {
		now = time.Now
	}
	send, receive, err := key.Parts(dir)
	if err != nil {
		return nil, err
	}
	return &tlsCrypt{
		now:       now,
		sender:    replay.NewSender(startID),
		sendMAC:   hmac.New(sha256.New, send.HMAC[:cryptKeySize]),
		sendBlock: newAES256(send.Cipher[:cryptKeySize]),
		window:    replay.NewWindow(replayWindowSize, replayMaxAge),
		recvMAC:   hmac.New(sha256.New, receive.HMAC[:cryptKeySize]),
		recvBlock: newAES256(receive.Cipher[:cryptKeySize]),
	}, nil
}

// newAES256 makes the AES block cipher of a 32-byte key. aes.NewCipher fails
// only for a key of another length, and the length here is a constant: an
// error would be a mistake in this package, so it stops the program.
func newAES256(key []byte) cipher.Block {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("ctrlwrap: a 32-byte key is not an AES-256 key: " + err.Error())
	}
	return block
}

func (w *tlsCrypt) Overhead() int { return replayIDSize + cryptTagSize }

func (w *tlsCrypt) Wrap(dst []byte, first byte, sid wire.SessionID, body []byte) ([]byte, error) {
	w.sendMu.Lock()
	defer w.sendMu.Unlock()

	id, sent, err := w.sender.Next(w.now())
	if err != nil {
		return dst, err
	}
	var header [cryptHeaderSize]byte
	header[0] = first
	copy(header[1:headerSize], sid[:])
	binary.BigEndian.PutUint32(header[headerSize:], id)
	binary.BigEndian.PutUint32(header[headerSize+4:], sent)

	mac := w.sendMAC
	mac.Reset()
	mac.Write(header[:])
	mac.Write(body)
	var tag [cryptTagSize]byte
	mac.Sum(tag[:0])

	dst = append(dst, header[:]...)
	dst = append(dst, tag[:]...)
	start := len(dst)
	dst = append(dst, body...)
	cipher.NewCTR(w.sendBlock, tag[:aes.BlockSize]).XORKeyStream(dst[start:], body)
	return dst, nil
}

func (w *tlsCrypt) Unwrap(packet []byte) ([]byte, error) {
	bodyStart := cryptHeaderSize + cryptTagSize
	if len(packet) < bodyStart {
		return nil, errors.New(tagTLSCryptTooShort, "the packet is shorter than its header", "want", bodyStart, "got", len(packet))
	}
	header, gotTag, ciphertext := packet[:cryptHeaderSize], packet[cryptHeaderSize:bodyStart], packet[bodyStart:]

	id := binary.BigEndian.Uint32(header[headerSize:])
	sent := binary.BigEndian.Uint32(header[headerSize+4:])
	if id == 0 {
		return nil, errors.New(tagTLSCryptPacketIDZero, "the packet id is 0: ids start at 1")
	}
	counter := uint64(sent)<<32 | uint64(id)

	w.recvMu.Lock()
	defer w.recvMu.Unlock()
	now := w.now()
	// The replay check is cheap and comes first; nothing is recorded until the
	// tag has been checked.
	if !w.window.Check(counter, now) {
		return nil, errors.New(tagTLSCryptReplay, "the packet is a replay or too old", "id", id, "time", sent)
	}
	// The tag covers the plaintext, so the body is decrypted before the tag can
	// be checked; it is not used, and not returned, until it has been.
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(w.recvBlock, gotTag[:aes.BlockSize]).XORKeyStream(plaintext, ciphertext)
	mac := w.recvMAC
	mac.Reset()
	mac.Write(header)
	mac.Write(plaintext)
	var sum [cryptTagSize]byte
	if !hmac.Equal(gotTag, mac.Sum(sum[:0])) {
		return nil, errors.New(tagTLSCryptTagMismatch, "the tag of the packet is wrong")
	}
	w.window.Accept(counter, now)
	return plaintext, nil
}

const (
	tagTLSCryptNeedsDirection = "TLSCryptNeedsDirection"
	tagTLSCryptTooShort       = "TLSCryptTooShort"
	tagTLSCryptPacketIDZero   = "TLSCryptPacketIDZero"
	tagTLSCryptReplay         = "TLSCryptReplay"
	tagTLSCryptTagMismatch    = "TLSCryptTagMismatch"
)

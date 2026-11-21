// SPDX-License-Identifier: GPL-2.0-only

package keys

import (
	"io"
	"strings"

	"github.com/rm4n0s/errors"
)

const (
	// StaticKeySize is the size of an OpenVPN static key in bytes: two keys,
	// each with a 64-byte cipher key and a 64-byte HMAC key.
	StaticKeySize = 256

	// PartSize is the size of a cipher key and of an HMAC key in a static key.
	PartSize = 64

	staticKeyBegin = "-----BEGIN OpenVPN Static key V1-----"
	staticKeyEnd   = "-----END OpenVPN Static key V1-----"

	// maxStaticKeyFile bounds what ParseStaticKey reads: a key file is about
	// 650 bytes.
	maxStaticKeyFile = 64 << 10
)

// StaticKey is the 256 bytes of an OpenVPN static key file, the format of
// tls-auth and tls-crypt keys: four parts of 64 bytes, in this order: cipher
// key 0, HMAC key 0, cipher key 1, HMAC key 1.
//
// Draft: appendix "OpenVPN Static key file format" and section "OpenVPN Key".
type StaticKey [StaticKeySize]byte

// KeyPart is one of the two keys of a static key: a cipher key and an HMAC
// key. A hash uses the first bytes of the HMAC key, as many as its output.
type KeyPart struct {
	Cipher [PartSize]byte
	HMAC   [PartSize]byte
}

// Direction says which of the two keys of a static key a peer sends with and
// which it receives with: the key-direction option of OpenVPN.
type Direction int

const (
	// Bidirectional is no direction: both ways use key 0.
	Bidirectional Direction = iota
	// Normal is key-direction 0: send with key 0, receive with key 1. A
	// server has it.
	Normal
	// Inverse is key-direction 1: send with key 1, receive with key 0. A
	// client has it.
	Inverse
)

// String is the name of the direction.
func (d Direction) String() string {
	switch d {
	case Bidirectional:
		return "bidirectional"
	case Normal:
		return "normal"
	case Inverse:
		return "inverse"
	}
	return "unknown"
}

// Parts returns the key to send with and the key to receive with for a
// direction. The parts are copies.
func (k *StaticKey) Parts(dir Direction) (send, receive KeyPart, err error) {
	var sendIdx, recvIdx int
	switch dir {
	case Bidirectional:
		sendIdx, recvIdx = 0, 0
	case Normal:
		sendIdx, recvIdx = 0, 1
	case Inverse:
		sendIdx, recvIdx = 1, 0
	default:
		return KeyPart{}, KeyPart{}, errors.New(tagUnknownDirection, "not a key direction", "direction", int(dir))
	}
	return k.part(sendIdx), k.part(recvIdx), nil
}

// part returns key 0 or key 1.
func (k *StaticKey) part(i int) KeyPart {
	var p KeyPart
	base := i * 2 * PartSize
	copy(p.Cipher[:], k[base:base+PartSize])
	copy(p.HMAC[:], k[base+PartSize:base+2*PartSize])
	return p
}

// ParseStaticKey reads an OpenVPN static key file. Everything before the line
// -----BEGIN OpenVPN Static key V1----- and after the line
// -----END OpenVPN Static key V1----- is ignored. Between them are the 256
// bytes of the key as hexadecimal digits, with any number of digits on a line
// and with white space anywhere. A file of 128 bytes, which OpenVPN reads as a
// single key, is refused: SPEC §20 V5.
//
// Draft: appendix "OpenVPN Static key file format".
func ParseStaticKey(r io.Reader) (*StaticKey, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxStaticKeyFile+1))
	if err != nil {
		return nil, errors.NewErr(tagStaticKeyReadFailed, err)
	}
	if len(data) > maxStaticKeyFile {
		return nil, errors.New(tagStaticKeyTooLarge, "the key file is too large", "max", maxStaticKeyFile)
	}

	var key StaticKey
	digits := 0 // hexadecimal digits read so far
	inside, done := false, false
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !inside {
			inside = trimmed == staticKeyBegin
			continue
		}
		if trimmed == staticKeyEnd {
			done = true
			break
		}
		for j := 0; j < len(trimmed); j++ {
			c := trimmed[j]
			if c == ' ' || c == '\t' || c == '\r' {
				continue
			}
			v, ok := hexValue(c)
			if !ok {
				// The character is not named: it may be a piece of a key.
				return nil, errors.New(tagStaticKeyBadHex, "a character that is not a hexadecimal digit in the key", "line", i+1)
			}
			if digits < 2*StaticKeySize { // more digits are counted, for the error, and not kept
				if digits%2 == 0 {
					key[digits/2] = v << 4
				} else {
					key[digits/2] |= v
				}
			}
			digits++
		}
	}
	if !done {
		return nil, errors.New(tagStaticKeyNotFound, "no complete OpenVPN static key block (BEGIN line, key, END line)", "begin_found", inside)
	}
	if digits != 2*StaticKeySize {
		return nil, errors.New(tagStaticKeyBadLength, "a static key has 256 bytes", "hex_digits", digits, "want", 2*StaticKeySize)
	}
	return &key, nil
}

// hexValue is the value of a hexadecimal digit.
func hexValue(c byte) (v byte, ok bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

const (
	tagUnknownDirection    = "UnknownDirection"
	tagStaticKeyReadFailed = "StaticKeyReadFailed"
	tagStaticKeyTooLarge   = "StaticKeyTooLarge"
	tagStaticKeyBadHex     = "StaticKeyBadHex"
	tagStaticKeyNotFound   = "StaticKeyNotFound"
	tagStaticKeyBadLength  = "StaticKeyBadLength"
)

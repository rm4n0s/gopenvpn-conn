// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl.c (key_method_2_write, key_method_2_read, key_source2_randomize_write, key_source2_read, write_string, read_string) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package ctrlmsg

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math"

	"github.com/rm4n0s/errors"
)

// The sizes of the fields of the key exchange message.
const (
	// KeyMethod is the only method of the key exchange that is supported.
	KeyMethod = 2
	// PreMasterSize is the size of the random pre-master secret that a client sends.
	PreMasterSize = 48
	// RandomSize is the size of each of the two random strings that each side sends.
	RandomSize = 32
	// MaxOptionsLen is the longest options string, with its NUL: OpenVPN's
	// TLS_OPTIONS_LEN.
	MaxOptionsLen = 512
	// MaxCredentialLen is the longest user name or password, with its NUL:
	// OpenVPN's USER_PASS_LEN when it is built with PKCS#11, as the packages of the
	// systems are; a build without it has 128, and answers a longer one with
	// AUTH_FAILED ("Username or password is too long"). What bounds a credential
	// first is MaxKeyExchangeLen.
	//
	// OpenVPN: misc.h USER_PASS_LEN.
	MaxCredentialLen = 4096
	// MaxKeyExchangeLen is the longest key exchange message: OpenVPN reads the
	// cleartext of the control channel into a buffer of this size, so a server cuts a
	// longer message there, loses the peer info and reads the rest as a control
	// message. OpenVPN's client cannot write a longer one either.
	//
	// OpenVPN: common.h TLS_CHANNEL_BUF_SIZE, ssl.c key_state_init.
	MaxKeyExchangeLen = 2048
	// maxPeerInfoLen is the longest peer info that is read, with its NUL. The
	// server's peer info is not used yet and a control message is one TLS
	// record (16 KB at most), so the bound is far above what is sent.
	maxPeerInfoLen = 1 << 14
)

// ClientKeyExchange is the message that a client sends first in the TLS
// session. The three random fields are not used by this library (the data keys
// come from the TLS exporter), but they are sent, random, as the server expects.
//
// Draft: "Key exchange message" (key method 2).
type ClientKeyExchange struct {
	PreMaster [PreMasterSize]byte
	Random1   [RandomSize]byte
	Random2   [RandomSize]byte
	// Options is the options string (SPEC §20 V1: the server only compares it).
	Options string
	// Username and Password are empty when the client has no credentials.
	Username string
	Password string
	// PeerInfo is the text of the peer info, lines "NAME=value\n".
	PeerInfo string
}

// NewClientKeyExchange makes a message with random fields from crypto/rand.
func NewClientKeyExchange(options, username, password, peerInfo string) *ClientKeyExchange {
	m := &ClientKeyExchange{Options: options, Username: username, Password: password, PeerInfo: peerInfo}
	// crypto/rand.Read does not fail (it ends the program if the system has no
	// randomness), so there is no error to return.
	_, _ = rand.Read(m.PreMaster[:])
	_, _ = rand.Read(m.Random1[:])
	_, _ = rand.Read(m.Random2[:])
	return m
}

// AppendClientKeyExchange appends the message to dst: four zero bytes, the key
// method, the random fields, and the four strings. A string is a 16-bit length
// that counts the NUL at its end, the bytes and the NUL; with no user name and no
// password, those two are strings of length 0, with no NUL. A string that is too
// long, or has a NUL inside, is refused, and so is a message that is longer than
// MaxKeyExchangeLen: a user name or password is never part of the error.
func AppendClientKeyExchange(dst []byte, m *ClientKeyExchange) ([]byte, error) {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0, KeyMethod)
	dst = append(dst, m.PreMaster[:]...)
	dst = append(dst, m.Random1[:]...)
	dst = append(dst, m.Random2[:]...)
	fields := []struct {
		name  string
		value string
		max   int
	}{
		{"options", m.Options, MaxOptionsLen},
		{"username", m.Username, MaxCredentialLen},
		{"password", m.Password, MaxCredentialLen},
		{"peer info", m.PeerInfo, 0xffff},
	}
	noCredentials := m.Username == "" && m.Password == ""
	for _, f := range fields {
		if len(f.value)+1 > f.max {
			return nil, errors.New(tagStringTooLong, "a string of the key exchange message is too long",
				"field", f.name, "length", len(f.value)+1, "max", f.max)
		}
		if bytes.IndexByte([]byte(f.value), 0) >= 0 {
			return nil, errors.New(tagStringHasNUL, "a string of the key exchange message has a NUL inside", "field", f.name)
		}
		if noCredentials && (f.name == "username" || f.name == "password") {
			// OpenVPN: ssl.c key_method_2_write, write_empty_string: a client that has no
			// user name and password to give writes two strings of length 0, with no NUL.
			// A server that asks for them tells "none given" from "empty" by that.
			dst = append(dst, 0, 0)
			continue
		}
		dst = binary.BigEndian.AppendUint16(dst, uint16(min(len(f.value)+1, math.MaxUint16))) // checked above: at most 0xffff
		dst = append(dst, f.value...)
		dst = append(dst, 0)
	}
	if n := len(dst) - start; n > MaxKeyExchangeLen {
		clear(dst[start:]) // the password is in it
		return nil, errors.New(TagKeyExchangeTooLong, "the key exchange message is longer than a server reads: the peer info, the user name or the password is too long",
			"length", n, "max", MaxKeyExchangeLen)
	}
	return dst, nil
}

// ServerKeyExchange is the message that the server sends in answer: the same as
// the client's without the pre-master secret. Its strings are kept as sent; the
// user name and password are the server's, and empty.
type ServerKeyExchange struct {
	Random1  [RandomSize]byte
	Random2  [RandomSize]byte
	Options  string
	Username string
	Password string
	PeerInfo string
}

// ParseServerKeyExchange parses the server's message. The four leading bytes
// are not checked (OpenVPN does not), the key method (the low 4 bits of the
// next byte) must be 2, and every string must be as long as its length says,
// end in a NUL and have none inside. The options string must be present; any
// other string may have the length 0, which OpenVPN reads as "no string".
// Bytes after the peer info are an error.
func ParseServerKeyExchange(b []byte) (*ServerKeyExchange, error) {
	const header = 4 + 1 + 2*RandomSize
	if len(b) < header {
		return nil, errors.New(tagKeyExchangeTruncated, "the message is shorter than its fixed part", "want", header, "got", len(b))
	}
	if method := b[4] & 0x0f; method != KeyMethod {
		return nil, errors.New(tagBadKeyMethod, "the key method is not 2", "method", int(method))
	}
	m := &ServerKeyExchange{}
	copy(m.Random1[:], b[5:])
	copy(m.Random2[:], b[5+RandomSize:])
	rest := b[header:]

	var err error
	if m.Options, rest, err = readString(rest, MaxOptionsLen, false, "options"); err != nil {
		return nil, err
	}
	if m.Username, rest, err = readString(rest, MaxCredentialLen, true, "username"); err != nil {
		return nil, err
	}
	if m.Password, rest, err = readString(rest, MaxCredentialLen, true, "password"); err != nil {
		return nil, err
	}
	if m.PeerInfo, rest, err = readString(rest, maxPeerInfoLen, true, "peer info"); err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New(tagKeyExchangeTrailing, "bytes follow the peer info", "count", len(rest))
	}
	return m, nil
}

// readString reads one string of the message from the start of b, and returns
// it without its NUL, and what follows it.
func readString(b []byte, limit int, mayBeAbsent bool, field string) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, errors.New(tagKeyExchangeTruncated, "no length for a string", "field", field)
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if n == 0 {
		if !mayBeAbsent {
			return "", nil, errors.New(tagStringMissing, "a string that must be there has length 0", "field", field)
		}
		return "", b, nil
	}
	if n > limit {
		return "", nil, errors.New(tagStringTooLong, "a string of the key exchange message is too long", "field", field, "length", n, "max", limit)
	}
	if len(b) < n {
		return "", nil, errors.New(tagKeyExchangeTruncated, "a string is longer than the message", "field", field, "length", n, "left", len(b))
	}
	s, rest := b[:n], b[n:]
	if s[n-1] != 0 {
		return "", nil, errors.New(tagStringNotTerminated, "a string does not end in a NUL", "field", field)
	}
	if bytes.IndexByte(s[:n-1], 0) >= 0 {
		return "", nil, errors.New(tagStringHasNUL, "a string has a NUL inside", "field", field)
	}
	return string(s[:n-1]), rest, nil
}

const (
	tagStringTooLong        = "StringTooLong"
	tagStringHasNUL         = "StringHasNUL"
	tagStringMissing        = "StringMissing"
	tagStringNotTerminated  = "StringNotTerminated"
	tagKeyExchangeTruncated = "KeyExchangeTruncated"
	tagKeyExchangeTrailing  = "KeyExchangeTrailing"
	tagBadKeyMethod         = "BadKeyMethod"
)

// TagKeyExchangeTooLong is the tag of the error of a key exchange message that is
// longer than MaxKeyExchangeLen. Metadata: "length", "max".
const TagKeyExchangeTooLong = "KeyExchangeTooLong"

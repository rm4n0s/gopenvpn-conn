// SPDX-License-Identifier: GPL-2.0-only

package keys

import (
	"encoding/binary"
	"encoding/pem"
	"io"

	"github.com/rm4n0s/errors"
)

const (
	tlsCryptV2ClientKeyType = "OpenVPN tls-crypt-v2 client key"

	// MaxWKcSize is the largest wrapped client key that OpenVPN accepts.
	MaxWKcSize = 1024

	// minWKcSize is the least a wrapped client key can be: the 2 bytes of its
	// length. The rest of its format belongs to the server (it may differ from
	// OpenVPN's), but the length at its end is part of the protocol.
	minWKcSize = 2

	maxTLSCryptV2KeyFile = 64 << 10
)

// TLSCryptV2ClientKey is a tls-crypt-v2 client key: the key Kc that the client
// uses like a tls-crypt key, and the wrapped key WKc that it sends to the
// server so that the server can get Kc, which the client cannot read.
//
// Draft: "Client-specific encryption keys".
type TLSCryptV2ClientKey struct {
	// Kc is the 256 bytes of the client key, in the layout of a static key.
	Kc StaticKey
	// WKc is the wrapped client key, as the file has it. Its last 2 bytes are its
	// length, in network byte order.
	WKc []byte
}

// ParseTLSCryptV2ClientKey reads a tls-crypt-v2 client key file: a PEM block
// "OpenVPN tls-crypt-v2 client key" whose data is Kc (256 bytes) followed by
// WKc. Text outside the block is ignored. WKc is checked only for what the
// protocol fixes: it is at most 1024 bytes and its last 2 bytes are its length.
func ParseTLSCryptV2ClientKey(r io.Reader) (*TLSCryptV2ClientKey, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxTLSCryptV2KeyFile+1))
	if err != nil {
		return nil, errors.NewErr(tagTLSCryptV2KeyReadFailed, err)
	}
	if len(data) > maxTLSCryptV2KeyFile {
		return nil, errors.New(tagTLSCryptV2KeyTooLarge, "the key file is too large", "max", maxTLSCryptV2KeyFile)
	}
	var der []byte
	found := false
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == tlsCryptV2ClientKeyType {
			der, found = block.Bytes, true
			break
		}
	}
	if !found {
		return nil, errors.New(tagTLSCryptV2KeyNotFound, "no PEM block "+tlsCryptV2ClientKeyType)
	}
	if len(der) < StaticKeySize+minWKcSize {
		return nil, errors.New(tagTLSCryptV2KeyTooShort, "a client key is Kc of 256 bytes and a wrapped key", "got", len(der), "want_at_least", StaticKeySize+minWKcSize)
	}
	wkc := der[StaticKeySize:]
	if len(wkc) > MaxWKcSize {
		return nil, errors.New(tagTLSCryptV2BadWKc, "the wrapped client key is too large", "length", len(wkc), "max", MaxWKcSize)
	}
	if declared := int(binary.BigEndian.Uint16(wkc[len(wkc)-2:])); declared != len(wkc) {
		return nil, errors.New(tagTLSCryptV2BadWKc, "the length at the end of the wrapped client key is not its length", "length", len(wkc), "declared", declared)
	}
	key := &TLSCryptV2ClientKey{WKc: append([]byte(nil), wkc...)}
	copy(key.Kc[:], der[:StaticKeySize])
	return key, nil
}

const (
	tagTLSCryptV2KeyReadFailed = "TLSCryptV2KeyReadFailed"
	tagTLSCryptV2KeyTooLarge   = "TLSCryptV2KeyTooLarge"
	tagTLSCryptV2KeyNotFound   = "TLSCryptV2KeyNotFound"
	tagTLSCryptV2KeyTooShort   = "TLSCryptV2KeyTooShort"
	tagTLSCryptV2BadWKc        = "TLSCryptV2BadWKc"
)

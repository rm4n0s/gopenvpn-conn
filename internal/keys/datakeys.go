// SPDX-License-Identifier: GPL-2.0-only

package keys

import (
	"github.com/rm4n0s/errors"
)

const (
	// DataKeysSize is the length of the key material of the data channel: four
	// parts of 64 bytes.
	DataKeysSize = 256

	// ExportLabel is the label of the TLS exporter (RFC 5705, RFC 8446 §7.5) that
	// gives the key material of the data channel, 256 bytes long, with no context.
	//
	// Draft: "Data channel key generation".
	ExportLabel = "EXPORTER-OpenVPN-datakeys"

	partSize = 64
)

// DirectionKey is what protects the data in one direction: a cipher key and a
// second key. For the AEAD ciphers the second key is not a MAC key: its first
// bytes are the implicit part of every nonce. Only the first bytes of each are
// used (16, 24 or 32 of the cipher key, 8 of the other).
type DirectionKey struct {
	Cipher [partSize]byte
	HMAC   [partSize]byte
}

// DataKeys are the keys of the data channel of one key id, as OpenVPN names the
// directions: from the TLS client to the TLS server, and back. This library is
// always the TLS client, so it sends with ClientToServer and receives with
// ServerToClient.
//
// Draft: "OpenVPN Key".
type DataKeys struct {
	ClientToServer DirectionKey
	ServerToClient DirectionKey
}

// SplitDataKeys cuts the 256 bytes of key material in the order of the draft:
// cipher key and second key client to server, then the same server to client.
// The material is copied; the caller may clear its own copy.
func SplitDataKeys(material []byte) (*DataKeys, error) {
	if len(material) != DataKeysSize {
		return nil, errors.New(tagBadDataKeys, "the key material of the data channel has the wrong size", "got", len(material), "want", DataKeysSize)
	}
	var k DataKeys
	copy(k.ClientToServer.Cipher[:], material[0*partSize:1*partSize])
	copy(k.ClientToServer.HMAC[:], material[1*partSize:2*partSize])
	copy(k.ServerToClient.Cipher[:], material[2*partSize:3*partSize])
	copy(k.ServerToClient.HMAC[:], material[3*partSize:4*partSize])
	return &k, nil
}

// Clear overwrites the keys with zeros. It is called when the key slot that
// owns them ends (SPEC §15 rule 10).
func (k *DataKeys) Clear() {
	*k = DataKeys{}
}

const tagBadDataKeys = "BadDataKeys"

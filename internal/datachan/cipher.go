// SPDX-License-Identifier: GPL-2.0-only

package datachan

import (
	"crypto/aes"
	"crypto/cipher"
	"strings"

	"github.com/rm4n0s/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher is a data channel cipher: an AEAD with a 12-byte nonce and a 16-byte
// tag, as OpenVPN uses them. Get one with LookupCipher.
type Cipher struct {
	name    string
	keySize int
	aead    func(key []byte) (cipher.AEAD, error)
}

// ciphers are the data ciphers of this library, in the order that it offers
// them (SPEC §8.2); they are the AEAD ciphers of OpenVPN.
var ciphers = []Cipher{
	{"AES-256-GCM", 32, newGCM},
	{"AES-128-GCM", 16, newGCM},
	{"CHACHA20-POLY1305", chacha20poly1305.KeySize, newChaCha},
	{"AES-192-GCM", 24, newGCM},
}

// LookupCipher finds a cipher by its OpenVPN name (AES-128-GCM, AES-192-GCM,
// AES-256-GCM or CHACHA20-POLY1305; the case does not matter, as in OpenVPN).
func LookupCipher(name string) (Cipher, bool) {
	for _, c := range ciphers {
		if strings.EqualFold(c.name, name) {
			return c, true
		}
	}
	return Cipher{}, false
}

// Name is the name of the cipher, as OpenVPN writes it.
func (c Cipher) Name() string { return c.name }

// KeySize is the length of the key in bytes.
func (c Cipher) KeySize() int { return c.keySize }

const (
	// TagSize is the length of the authentication tag.
	TagSize = 16
	// nonceSize is the length of the nonce: the 4 bytes of the packet id and the
	// 8 bytes of the implicit IV.
	nonceSize = 12
	// implicitIVSize is how many bytes of the second key are the implicit IV.
	implicitIVSize = nonceSize - 4
)

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.NewErr(tagCipherInit, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.NewErr(tagCipherInit, err)
	}
	return aead, nil
}

func newChaCha(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, errors.NewErr(tagCipherInit, err)
	}
	return aead, nil
}

const tagCipherInit = "DataCipherInitFailed"

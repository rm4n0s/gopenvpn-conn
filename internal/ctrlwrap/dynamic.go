// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/tls_crypt.c (tls_session_generate_dynamic_tls_crypt_key, xor_key2) and ssl_pkt.h (tls_session_get_tls_wrap) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package ctrlwrap

import (
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
)

// DynamicLabel is the label of the TLS exporter that gives the key of dynamic
// tls-crypt: 256 bytes, laid out like a static key.
const DynamicLabel = "EXPORTER-OpenVPN-dynamic-tls-crypt"

// StaticKeyed is a Wrapper that knows the static key it was made from: what
// dynamic tls-crypt combines with the key of the TLS exporter.
type StaticKeyed interface {
	Wrapper
	// StaticKey is the key as it was given to the constructor: the static key of
	// tls-auth or tls-crypt, or the client key Kc of tls-crypt-v2. It is a secret.
	StaticKey() *keys.StaticKey
}

// StaticKey is the key of a tls-auth wrapper.
func (w *tlsAuth) StaticKey() *keys.StaticKey { k := w.static; return &k }

// StaticKey is the key of a tls-crypt wrapper (Kc for tls-crypt-v2).
func (w *tlsCrypt) StaticKey() *keys.StaticKey { k := w.static; return &k }

// NewDynamic makes the wrapper of the control packets of a renegotiated session
// (a key id above 0) from the 256 bytes that the TLS exporter gave, for the label
// DynamicLabel, in the first session. The bytes are laid out like a static key and
// XORed, byte by byte, with the static key that protects the first session when there
// is one (original is nil when it has none); the result is the key of a tls-crypt
// wrapper, whatever protected the first session: tls-auth turns into tls-crypt. A
// client sends with the key a tls-crypt client does, and the server of a test with
// the other (server set).
//
// OpenVPN: tls_crypt.c tls_session_generate_dynamic_tls_crypt_key, xor_key2.
func NewDynamic(exported []byte, original *keys.StaticKey, server bool, now func() time.Time) (Wrapper, error) {
	if len(exported) != keys.StaticKeySize {
		return nil, errors.New(tagDynamicKeySize, "the key material of dynamic tls-crypt is not 256 bytes", "len", len(exported))
	}
	var key keys.StaticKey
	copy(key[:], exported)
	if original != nil {
		for i := range key {
			key[i] ^= original[i]
		}
	}
	if server {
		return NewTLSCryptServer(&key, now)
	}
	return NewTLSCrypt(&key, now)
}

const tagDynamicKeySize = "DynamicTLSCryptKeySize"

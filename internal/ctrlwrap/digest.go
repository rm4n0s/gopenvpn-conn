// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, doc/man-sections/tls-options.rst (--auth, --tls-auth) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package ctrlwrap

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/rm4n0s/errors"
)

// HashFor returns the constructor of the digest that tls-auth authenticates
// packets with (OpenVPN's --auth). The digests that a server of OpenVPN 2.6 or
// later is used with here are SHA-1 (the default), SHA-256, SHA-384 and
// SHA-512; any other is refused.
//
// OpenVPN doc: tls-options.rst --tls-auth ("the --auth digest").
func HashFor(h crypto.Hash) (func() hash.Hash, error) {
	switch h {
	case crypto.SHA1:
		return sha1.New, nil
	case crypto.SHA256:
		return sha256.New, nil
	case crypto.SHA384:
		return sha512.New384, nil
	case crypto.SHA512:
		return sha512.New, nil
	}
	return nil, errors.New(tagUnsupportedDigest, "tls-auth does not support this digest", "digest", h.String())
}

const tagUnsupportedDigest = "UnsupportedDigest"

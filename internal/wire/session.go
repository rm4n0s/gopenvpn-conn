// SPDX-License-Identifier: GPL-2.0-only

package wire

import (
	"crypto/rand"
	"encoding/hex"
)

// SessionIDSize is the size of a session id in bytes.
const SessionIDSize = 8

// SessionID is the 8 random bytes that each side picks for a connection. A
// peer must not read anything into them.
//
// Draft: "Unauthenticated control channel packets", "Field: session_id".
type SessionID [SessionIDSize]byte

// RandomSessionID makes a session id from crypto/rand. It is never all zero,
// which OpenVPN treats as "not defined".
func RandomSessionID() SessionID {
	var id SessionID
	for id.IsZero() {
		// crypto/rand.Read does not return an error: when the system cannot
		// give random bytes the program stops.
		_, _ = rand.Read(id[:])
	}
	return id
}

// IsZero reports whether the id is all zero bytes.
func (id SessionID) IsZero() bool {
	return id == SessionID{}
}

// String is the id in hexadecimal.
func (id SessionID) String() string {
	return hex.EncodeToString(id[:])
}

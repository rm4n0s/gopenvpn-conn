// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// headerSize is the first byte and the session id: what is never wrapped.
const headerSize = 1 + wire.SessionIDSize

// Wrapper protects control channel packets.
//
// A Wrapper may be used by two goroutines at the same time when one sends
// (Wrap) and the other receives (Unwrap): each direction has its own state.
type Wrapper interface {
	// Wrap appends to dst the packet to put on the link: the first byte, the
	// session id of the sender, and body (the part from the acknowledgement
	// count on), protected. Every call makes a new replay counter, so a packet
	// that is sent again is wrapped again.
	Wrap(dst []byte, first byte, sid wire.SessionID, body []byte) ([]byte, error)

	// Unwrap checks a packet that came from the link, first byte and session
	// id included, and returns its body. The body may point into packet. An
	// error means that the packet is to be dropped.
	Unwrap(packet []byte) ([]byte, error)

	// Overhead is how many bytes Wrap adds to a packet.
	Overhead() int
}

// plain is the control channel with no protection.
type plain struct{}

// NewPlain returns the Wrapper of a control channel with no protection: the
// packet is the first byte, the session id and the body.
//
// Draft: "Unauthenticated control channel packets".
func NewPlain() Wrapper {
	return plain{}
}

func (plain) Wrap(dst []byte, first byte, sid wire.SessionID, body []byte) ([]byte, error) {
	dst = append(dst, first)
	dst = append(dst, sid[:]...)
	return append(dst, body...), nil
}

func (plain) Unwrap(packet []byte) ([]byte, error) {
	if len(packet) < headerSize {
		return nil, errors.New(tagPlainTooShort, "no first byte and session id", "want", headerSize, "got", len(packet))
	}
	return packet[headerSize:], nil
}

func (plain) Overhead() int { return 0 }

const tagPlainTooShort = "PlainTooShort"

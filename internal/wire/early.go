// SPDX-License-Identifier: GPL-2.0-only

package wire

import (
	"encoding/binary"

	"github.com/rm4n0s/errors"
)

const (
	// EarlyNegotiationStart is the counter that a tls-crypt-v2 client starts its
	// replay packet ids from, instead of 0: its packets then carry 0x0f000001,
	// 0x0f000002 and so on. The top byte 0x0f in the first packet tells the
	// server that the client supports early negotiation, which for now means
	// that it can send its wrapped key again on request.
	//
	// Draft: "[OPCODE ID 10] CONTROL_HARD_RESET_CLIENT_V3".
	EarlyNegotiationStart uint32 = 0x0f000000

	// The TLVs of the payload of CONTROL_HARD_RESET_SERVER_V2 (for a client that
	// announced early negotiation): a type and a length of 2 bytes each.
	earlyNegFlagsType     = 0x0001
	earlyNegFlagsLen      = 2
	earlyNegFlagResendWKC = 0x0001
)

// ParseEarlyNegotiation reads the payload of a CONTROL_HARD_RESET_SERVER_V2
// packet that answers a client that announced early negotiation: a list of TLVs,
// each a 16-bit type, a 16-bit length and the value. It reports whether the
// server asks the client to resend its wrapped key in the packet that
// acknowledges the reset (the flag of the TLV of type 1).
//
// A TLV of a type that is not known is skipped. A TLV that is cut short, or a
// flags TLV whose length is not 2, makes the whole payload an error. An empty
// payload is no flags.
//
// Draft: "Client-specific encryption keys" (the TLV flags, type 0x01, length 2).
func ParseEarlyNegotiation(payload []byte) (resendWKC bool, err error) {
	rest := payload
	for len(rest) > 0 {
		if len(rest) < 4 {
			return false, errors.New(tagEarlyNegTruncated, "a TLV has less than its 4 bytes of header", "left", len(rest))
		}
		typ := binary.BigEndian.Uint16(rest)
		n := int(binary.BigEndian.Uint16(rest[2:]))
		if len(rest)-4 < n {
			return false, errors.New(tagEarlyNegTruncated, "a TLV is longer than the payload", "type", typ, "length", n, "left", len(rest)-4)
		}
		value := rest[4 : 4+n]
		rest = rest[4+n:]
		if typ != earlyNegFlagsType {
			continue
		}
		if n != earlyNegFlagsLen {
			return false, errors.New(tagEarlyNegBadFlags, "the flags TLV is not 2 bytes long", "length", n)
		}
		if binary.BigEndian.Uint16(value)&earlyNegFlagResendWKC != 0 {
			resendWKC = true
		}
	}
	return resendWKC, nil
}

// AppendEarlyNegotiation appends the payload of a server's reset: one flags TLV
// that asks, or does not ask, for the wrapped key to be sent again.
func AppendEarlyNegotiation(dst []byte, resendWKC bool) []byte {
	var flags uint16
	if resendWKC {
		flags = earlyNegFlagResendWKC
	}
	dst = binary.BigEndian.AppendUint16(dst, earlyNegFlagsType)
	dst = binary.BigEndian.AppendUint16(dst, earlyNegFlagsLen)
	return binary.BigEndian.AppendUint16(dst, flags)
}

const (
	tagEarlyNegTruncated = "EarlyNegotiationTruncated"
	tagEarlyNegBadFlags  = "EarlyNegotiationBadFlags"
)

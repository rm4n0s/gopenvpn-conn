// SPDX-License-Identifier: GPL-2.0-only

package wire

import (
	"encoding/binary"

	"github.com/rm4n0s/errors"
)

// MaxAcks is the most acknowledgements that one control packet carries.
// OpenVPN refuses a packet with more.
//
// Draft: "Acknowledgements"; OpenVPN: reliable.h RELIABLE_ACK_SIZE.
const MaxAcks = 8

// Control is a control channel packet as it is before control channel
// protection is added (and after it is taken off): the first byte, the session
// id of the sender, and the body.
//
// Draft: "Unauthenticated control channel packets".
type Control struct {
	Opcode Opcode
	KeyID  uint8
	// SessionID is the session id of the sender.
	SessionID SessionID
	// Acks are the ids of the packets of the other side that were received,
	// at most MaxAcks. Each is 4 bytes on the wire.
	Acks []uint32
	// RemoteSessionID is the session id of the other side. It is on the wire
	// only when there are Acks, and is not checked here: a zero or unknown
	// value is for the session to refuse.
	RemoteSessionID SessionID
	// PacketID is the id of this packet. An ACK_V1 packet has none.
	PacketID uint32
	// Payload is what the packet carries. An ACK_V1 packet has none.
	Payload []byte
}

// ParseControlBody parses the part of a control packet that starts at the
// acknowledgement count: after the first byte and the session id, and after
// whatever control channel protection puts there. op is the opcode of the
// packet; the result has it as Opcode and nothing in KeyID and SessionID, which
// the caller knows. Payload points into body.
//
// Draft: "Control channel wire packet structure". The ack count is 1 byte; then
// that many packet ids of 4 bytes; then, only if the count is not 0, the
// session id of the peer; then, except in ACK_V1, the 4-byte packet id and the
// payload. An ACK_V1 with bytes after its acks is refused: OpenVPN never sends
// one.
func ParseControlBody(op Opcode, body []byte) (Control, error) {
	if !op.IsControl() {
		return Control{}, errors.New(tagUnknownOpcode, "not the opcode of a control packet", "opcode", uint8(op))
	}
	if len(body) < 1 {
		return Control{}, errors.New(tagPacketTooShort, "no acknowledgement count", "opcode", op.String(), "want", 1, "got", len(body))
	}
	n := int(body[0])
	if n > MaxAcks {
		return Control{}, errors.New(tagTooManyAcks, "more acknowledgements than a packet carries", "opcode", op.String(), "count", n, "max", MaxAcks)
	}
	need := 1 + 4*n
	if n > 0 {
		need += SessionIDSize
	}
	if len(body) < need {
		return Control{}, errors.New(tagPacketTooShort, "the acknowledgements are cut short", "opcode", op.String(), "acks", n, "want", need, "got", len(body))
	}
	c := Control{Opcode: op}
	if n > 0 {
		c.Acks = make([]uint32, n)
		for i := range c.Acks {
			c.Acks[i] = binary.BigEndian.Uint32(body[1+4*i:])
		}
		copy(c.RemoteSessionID[:], body[1+4*n:need])
	}
	rest := body[need:]
	if op == AckV1 {
		if len(rest) != 0 {
			return Control{}, errors.New(tagTrailingData, "an ACK_V1 packet has bytes after its acknowledgements", "extra", len(rest))
		}
		return c, nil
	}
	if len(rest) < 4 {
		return Control{}, errors.New(tagPacketTooShort, "no packet id", "opcode", op.String(), "want", need+4, "got", len(body))
	}
	c.PacketID = binary.BigEndian.Uint32(rest)
	c.Payload = rest[4:]
	return c, nil
}

// AppendControlBody appends the body of c, the part that ParseControlBody
// reads, to dst. An ACK_V1 has no packet id and no payload: those fields of c
// are not written. It fails when c has more than MaxAcks acknowledgements.
func AppendControlBody(dst []byte, c *Control) ([]byte, error) {
	n := len(c.Acks)
	if n > MaxAcks {
		return dst, errors.New(tagAckListTooLong, "more acknowledgements than a packet carries", "count", n, "max", MaxAcks)
	}
	dst = append(dst, byte(n))
	for _, id := range c.Acks {
		dst = binary.BigEndian.AppendUint32(dst, id)
	}
	if len(c.Acks) > 0 {
		dst = append(dst, c.RemoteSessionID[:]...)
	}
	if c.Opcode == AckV1 {
		return dst, nil
	}
	dst = binary.BigEndian.AppendUint32(dst, c.PacketID)
	return append(dst, c.Payload...), nil
}

// ParseControl parses a whole control packet that has no control channel
// protection: the first byte, the session id of the sender, and the body.
func ParseControl(packet []byte) (Control, error) {
	if len(packet) < 1+SessionIDSize {
		return Control{}, errors.New(tagPacketTooShort, "no first byte and session id", "want", 1+SessionIDSize, "got", len(packet))
	}
	op, keyID := SplitFirstByte(packet[0])
	c, err := ParseControlBody(op, packet[1+SessionIDSize:])
	if err != nil {
		return Control{}, err
	}
	c.KeyID = keyID
	copy(c.SessionID[:], packet[1:1+SessionIDSize])
	return c, nil
}

// AppendControl appends the whole control packet, with no control channel
// protection, to dst.
func AppendControl(dst []byte, c *Control) ([]byte, error) {
	dst = append(dst, FirstByte(c.Opcode, c.KeyID))
	dst = append(dst, c.SessionID[:]...)
	return AppendControlBody(dst, c)
}

const (
	tagPacketTooShort = "PacketTooShort"
	tagTooManyAcks    = "TooManyAcks"
	tagUnknownOpcode  = "UnknownOpcode"
	tagTrailingData   = "TrailingData"
	tagAckListTooLong = "AckListTooLong"
)

// SPDX-License-Identifier: GPL-2.0-only

package wire

import "strconv"

// Opcode is the type of a packet: the high 5 bits of its first byte.
//
// Draft: "Overview of OPCODEs". Opcodes 1 and 2 (the V1 hard resets) are
// obsolete, and 12 to 14 of the draft are not in any released server; none of
// them is valid here.
type Opcode uint8

// The opcodes of the protocol that this library speaks.
const (
	// SoftResetV1 starts a renegotiation: CONTROL_SOFT_RESET_V1.
	SoftResetV1 Opcode = 3
	// ControlV1 carries TLS bytes: CONTROL_V1.
	ControlV1 Opcode = 4
	// AckV1 acknowledges control packets and carries nothing else: ACK_V1.
	AckV1 Opcode = 5
	// DataV1 is a data packet without a peer id: DATA_V1.
	DataV1 Opcode = 6
	// HardResetClientV2 is the first packet of a client: CONTROL_HARD_RESET_CLIENT_V2.
	HardResetClientV2 Opcode = 7
	// HardResetServerV2 is the answer of a server: CONTROL_HARD_RESET_SERVER_V2.
	HardResetServerV2 Opcode = 8
	// DataV2 is a data packet with a 24-bit peer id: DATA_V2.
	DataV2 Opcode = 9
	// HardResetClientV3 is the first packet of a tls-crypt-v2 client: CONTROL_HARD_RESET_CLIENT_V3.
	HardResetClientV3 Opcode = 10
	// ControlWKCV1 is ControlV1 with the wrapped client key appended: CONTROL_WKC_V1.
	ControlWKCV1 Opcode = 11
)

// IsControl reports whether the opcode is of a packet of the control channel.
func (o Opcode) IsControl() bool {
	switch o {
	case SoftResetV1, ControlV1, AckV1, HardResetClientV2, HardResetServerV2, HardResetClientV3, ControlWKCV1:
		return true
	}
	return false
}

// IsData reports whether the opcode is of a packet of the data channel.
func (o Opcode) IsData() bool {
	return o == DataV1 || o == DataV2
}

// Valid reports whether the opcode is one of the opcodes above.
func (o Opcode) Valid() bool {
	return o.IsControl() || o.IsData()
}

// String is the name the draft gives the opcode, or OPCODE_n for an opcode
// that is not valid.
func (o Opcode) String() string {
	switch o {
	case SoftResetV1:
		return "CONTROL_SOFT_RESET_V1"
	case ControlV1:
		return "CONTROL_V1"
	case AckV1:
		return "ACK_V1"
	case DataV1:
		return "DATA_V1"
	case HardResetClientV2:
		return "CONTROL_HARD_RESET_CLIENT_V2"
	case HardResetServerV2:
		return "CONTROL_HARD_RESET_SERVER_V2"
	case DataV2:
		return "DATA_V2"
	case HardResetClientV3:
		return "CONTROL_HARD_RESET_CLIENT_V3"
	case ControlWKCV1:
		return "CONTROL_WKC_V1"
	}
	return "OPCODE_" + strconv.Itoa(int(o))
}

// MaxKeyID is the largest key id: it has 3 bits.
const MaxKeyID = 7

// SplitFirstByte takes the opcode and the key id out of the first byte of a
// packet. It does not check that the opcode is valid.
func SplitFirstByte(b byte) (op Opcode, keyID uint8) {
	return Opcode(b >> 3), b & MaxKeyID
}

// FirstByte makes the first byte of a packet. Only the low 3 bits of keyID and
// the low 5 bits of op are used.
func FirstByte(op Opcode, keyID uint8) byte {
	return byte(op)<<3 | keyID&MaxKeyID
}

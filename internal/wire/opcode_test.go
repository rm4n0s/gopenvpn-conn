// SPDX-License-Identifier: GPL-2.0-only

package wire

import (
	"strconv"
	"testing"
)

func TestOpcodes(t *testing.T) {
	tests := []struct {
		op      Opcode
		value   uint8
		name    string
		control bool
		data    bool
	}{
		{SoftResetV1, 3, "CONTROL_SOFT_RESET_V1", true, false},
		{ControlV1, 4, "CONTROL_V1", true, false},
		{AckV1, 5, "ACK_V1", true, false},
		{DataV1, 6, "DATA_V1", false, true},
		{HardResetClientV2, 7, "CONTROL_HARD_RESET_CLIENT_V2", true, false},
		{HardResetServerV2, 8, "CONTROL_HARD_RESET_SERVER_V2", true, false},
		{DataV2, 9, "DATA_V2", false, true},
		{HardResetClientV3, 10, "CONTROL_HARD_RESET_CLIENT_V3", true, false},
		{ControlWKCV1, 11, "CONTROL_WKC_V1", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint8(tt.op) != tt.value {
				t.Errorf("value = %d, want %d", tt.op, tt.value)
			}
			if tt.op.String() != tt.name {
				t.Errorf("String() = %q, want %q", tt.op.String(), tt.name)
			}
			if tt.op.IsControl() != tt.control || tt.op.IsData() != tt.data {
				t.Errorf("IsControl, IsData = %v, %v; want %v, %v", tt.op.IsControl(), tt.op.IsData(), tt.control, tt.data)
			}
			if !tt.op.Valid() {
				t.Error("not valid")
			}
		})
	}
}

func TestInvalidOpcodes(t *testing.T) {
	// 1 and 2 are obsolete, 0 is unused, 12 to 31 are not in any released server.
	invalid := []Opcode{0, 1, 2}
	for op := Opcode(12); op <= 31; op++ {
		invalid = append(invalid, op)
	}
	for _, op := range invalid {
		if op.Valid() || op.IsControl() || op.IsData() {
			t.Errorf("opcode %d is accepted", op)
		}
		if got, want := op.String(), "OPCODE_"+strconv.Itoa(int(op)); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

func TestFirstByte(t *testing.T) {
	// The first byte is opcode<<3 | key id.
	tests := []struct {
		op    Opcode
		keyID uint8
		want  byte
	}{
		{HardResetClientV2, 0, 0x38},
		{HardResetServerV2, 0, 0x40},
		{ControlV1, 2, 0x22},
		{AckV1, 1, 0x29},
		{DataV2, 7, 0x4f},
		{ControlWKCV1, 5, 0x5d},
	}
	for _, tt := range tests {
		if got := FirstByte(tt.op, tt.keyID); got != tt.want {
			t.Errorf("FirstByte(%v, %d) = %#x, want %#x", tt.op, tt.keyID, got, tt.want)
		}
		op, keyID := SplitFirstByte(tt.want)
		if op != tt.op || keyID != tt.keyID {
			t.Errorf("SplitFirstByte(%#x) = %v, %d; want %v, %d", tt.want, op, keyID, tt.op, tt.keyID)
		}
	}
}

func TestFirstByteRoundTrip(t *testing.T) {
	for op := 0; op < 32; op++ {
		for keyID := 0; keyID <= MaxKeyID; keyID++ {
			gotOp, gotKey := SplitFirstByte(FirstByte(Opcode(op), uint8(keyID)))
			if gotOp != Opcode(op) || gotKey != uint8(keyID) {
				t.Errorf("op %d key %d came back as %d, %d", op, keyID, gotOp, gotKey)
			}
		}
	}
}

func TestFirstByteMasksItsInputs(t *testing.T) {
	// A key id above 7 must not change the opcode.
	if got, want := FirstByte(ControlV1, 9), FirstByte(ControlV1, 1); got != want {
		t.Errorf("FirstByte(ControlV1, 9) = %#x, want %#x", got, want)
	}
}

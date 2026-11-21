// SPDX-License-Identifier: GPL-2.0-only

package wire

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/rm4n0s/errors"
)

var (
	clientSID = SessionID{1, 2, 3, 4, 5, 6, 7, 8}
	serverSID = SessionID{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
)

// unhex decodes a hexadecimal string, ignoring spaces.
func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(string(bytes.ReplaceAll([]byte(s), []byte(" "), nil)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// vectors are packets written by hand from the draft: each field is a group of
// the hexadecimal string, so that the encoder is not checked against itself.
var vectors = []struct {
	name   string
	packet string // the whole packet
	want   Control
}{
	{
		name:   "client hard reset: no acks, packet id 0, no payload",
		packet: "38" + " 0102030405060708" + " 00" + " 00000000",
		want:   Control{Opcode: HardResetClientV2, KeyID: 0, SessionID: clientSID, PacketID: 0, Payload: []byte{}},
	},
	{
		name:   "server hard reset: acks packet 0 of the client",
		packet: "40" + " a1a2a3a4a5a6a7a8" + " 01 00000000" + " 0102030405060708" + " 00000000",
		want: Control{Opcode: HardResetServerV2, SessionID: serverSID, Acks: []uint32{0},
			RemoteSessionID: clientSID, PacketID: 0, Payload: []byte{}},
	},
	{
		name:   "ack packet: key id 1, two acks, no packet id",
		packet: "29" + " 0102030405060708" + " 02 00000003 00000005" + " a1a2a3a4a5a6a7a8",
		want: Control{Opcode: AckV1, KeyID: 1, SessionID: clientSID, Acks: []uint32{3, 5},
			RemoteSessionID: serverSID},
	},
	{
		name:   "control packet: key id 2, packet id 7, payload",
		packet: "22" + " 0102030405060708" + " 00" + " 00000007" + " 6869",
		want:   Control{Opcode: ControlV1, KeyID: 2, SessionID: clientSID, PacketID: 7, Payload: []byte("hi")},
	},
	{
		name:   "soft reset: packet id above 2^31",
		packet: "1b" + " 0102030405060708" + " 00" + " fffffffe",
		want:   Control{Opcode: SoftResetV1, KeyID: 3, SessionID: clientSID, PacketID: 0xfffffffe, Payload: []byte{}},
	},
	{
		name:   "eight acks, the most there can be",
		packet: "22" + " 0102030405060708" + " 08 00000000 00000001 00000002 00000003 00000004 00000005 00000006 00000007" + " a1a2a3a4a5a6a7a8" + " 00000009",
		want: Control{Opcode: ControlV1, KeyID: 2, SessionID: clientSID, Acks: []uint32{0, 1, 2, 3, 4, 5, 6, 7},
			RemoteSessionID: serverSID, PacketID: 9, Payload: []byte{}},
	},
	{
		name:   "wrapped client key packet carries its payload",
		packet: "58" + " 0102030405060708" + " 00" + " 00000001" + " deadbeef",
		want:   Control{Opcode: ControlWKCV1, SessionID: clientSID, PacketID: 1, Payload: []byte{0xde, 0xad, 0xbe, 0xef}},
	},
}

func equalControl(a, b Control) bool {
	return a.Opcode == b.Opcode && a.KeyID == b.KeyID && a.SessionID == b.SessionID &&
		slices.Equal(a.Acks, b.Acks) && a.RemoteSessionID == b.RemoteSessionID &&
		a.PacketID == b.PacketID && bytes.Equal(a.Payload, b.Payload)
}

func TestParseControl(t *testing.T) {
	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseControl(unhex(t, tt.packet))
			if err != nil {
				t.Fatal(err)
			}
			if !equalControl(got, tt.want) {
				t.Errorf("parsed %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAppendControl(t *testing.T) {
	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			want := unhex(t, tt.packet)
			got, err := AppendControl(nil, &tt.want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("made %x, want %x", got, want)
			}
			// It appends: what was in dst stays.
			got, err = AppendControl([]byte("xy"), &tt.want)
			if err != nil || !bytes.Equal(got, append([]byte("xy"), want...)) {
				t.Errorf("did not append to dst: %x, %v", got, err)
			}
		})
	}
}

func TestControlBodyIsThePartAfterTheSessionID(t *testing.T) {
	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			packet := unhex(t, tt.packet)
			body := packet[1+SessionIDSize:]
			got, err := ParseControlBody(tt.want.Opcode, body)
			if err != nil {
				t.Fatal(err)
			}
			// The header fields are for the caller to fill in.
			want := tt.want
			want.KeyID, want.SessionID = 0, SessionID{}
			if !equalControl(got, want) {
				t.Errorf("parsed %+v, want %+v", got, want)
			}
			again, err := AppendControlBody(nil, &got)
			if err != nil || !bytes.Equal(again, body) {
				t.Errorf("made %x, want %x (%v)", again, body, err)
			}
		})
	}
}

func TestAckIgnoresPacketIDAndPayload(t *testing.T) {
	c := Control{Opcode: AckV1, SessionID: clientSID, Acks: []uint32{1}, RemoteSessionID: serverSID, PacketID: 99, Payload: []byte("ignored")}
	got, err := AppendControl(nil, &c)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "28 0102030405060708 01 00000001 a1a2a3a4a5a6a7a8"); !bytes.Equal(got, want) {
		t.Errorf("made %x, want %x", got, want)
	}
}

func TestParseControlPayloadPointsIntoTheInput(t *testing.T) {
	packet := unhex(t, "22 0102030405060708 00 00000007 6869")
	c, err := ParseControl(packet)
	if err != nil {
		t.Fatal(err)
	}
	packet[len(packet)-1] = 'X'
	if string(c.Payload) != "hX" {
		t.Errorf("Payload = %q: it is documented to point into the input", c.Payload)
	}
}

func TestParseControlFailures(t *testing.T) {
	tests := []struct {
		name   string
		packet string
		route  string
		meta   map[string]any
	}{
		{"empty packet", "", "ParseControl.PacketTooShort", map[string]any{"got": 0}},
		{"first byte only", "38", "ParseControl.PacketTooShort", nil},
		{"session id cut short", "38 01020304050607", "ParseControl.PacketTooShort", map[string]any{"want": 9, "got": 8}},
		{"no ack count", "38 0102030405060708", "ParseControl->ParseControlBody.PacketTooShort", map[string]any{"want": 1, "got": 0}},
		{"acks cut short", "22 0102030405060708 02 00000001", "ParseControl->ParseControlBody.PacketTooShort", map[string]any{"acks": 2}},
		{"session id of the peer missing", "22 0102030405060708 01 00000001", "ParseControl->ParseControlBody.PacketTooShort", nil},
		{"session id of the peer cut short", "22 0102030405060708 01 00000001 a1a2a3", "ParseControl->ParseControlBody.PacketTooShort", nil},
		{"no packet id", "22 0102030405060708 00", "ParseControl->ParseControlBody.PacketTooShort", nil},
		{"packet id cut short", "22 0102030405060708 00 000000", "ParseControl->ParseControlBody.PacketTooShort", nil},
		{"nine acks", "22 0102030405060708 09 0000000000000000", "ParseControl->ParseControlBody.TooManyAcks", map[string]any{"count": 9, "max": MaxAcks}},
		{"255 acks", "22 0102030405060708 ff", "ParseControl->ParseControlBody.TooManyAcks", map[string]any{"count": 255}},
		{"bytes after the acks of an ack packet", "28 0102030405060708 00 aa", "ParseControl->ParseControlBody.TrailingData", map[string]any{"extra": 1}},
		{"packet id on an ack packet", "28 0102030405060708 00 00000000", "ParseControl->ParseControlBody.TrailingData", map[string]any{"extra": 4}},
		{"obsolete hard reset v1 client", "08 0102030405060708 00 00000000", "ParseControl->ParseControlBody.UnknownOpcode", map[string]any{"opcode": uint8(1)}},
		{"obsolete hard reset v1 server", "10 0102030405060708 00 00000000", "ParseControl->ParseControlBody.UnknownOpcode", nil},
		{"opcode 0", "00 0102030405060708 00 00000000", "ParseControl->ParseControlBody.UnknownOpcode", nil},
		{"opcode 12", "60 0102030405060708 00 00000000", "ParseControl->ParseControlBody.UnknownOpcode", map[string]any{"opcode": uint8(12)}},
		{"opcode 31", "f8 0102030405060708 00 00000000", "ParseControl->ParseControlBody.UnknownOpcode", nil},
		{"a data packet is not a control packet", "30 0102030405060708 00 00000000", "ParseControl->ParseControlBody.UnknownOpcode", map[string]any{"opcode": uint8(6)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseControl(unhex(t, tt.packet))
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute(tt.route) {
				t.Errorf("unexpected failure path: %s, want %s", appErr.Route(), tt.route)
			}
			for k, v := range tt.meta {
				if appErr.Metadata[k] != v {
					t.Errorf("metadata %q = %v (%T), want %v (%T)", k, appErr.Metadata[k], appErr.Metadata[k], v, v)
				}
			}
		})
	}
}

func TestParseControlBodyRefusesOtherOpcodes(t *testing.T) {
	for _, op := range []Opcode{0, 1, 2, DataV1, DataV2, 12, 31} {
		_, err := ParseControlBody(op, []byte{0, 0, 0, 0, 0})
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("opcode %d: expected *errors.Error, got %T: %v", op, err, err)
		}
		if !appErr.HasRoute("ParseControlBody.UnknownOpcode") {
			t.Errorf("opcode %d: unexpected failure path: %s", op, appErr.Route())
		}
	}
}

func TestAppendControlFailures(t *testing.T) {
	c := Control{Opcode: ControlV1, SessionID: clientSID, Acks: make([]uint32, MaxAcks+1)}
	for name, fn := range map[string]func() ([]byte, error){
		"AppendControlBody": func() ([]byte, error) { return AppendControlBody(nil, &c) },
		"AppendControl":     func() ([]byte, error) { return AppendControl(nil, &c) },
	} {
		_, err := fn()
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("%s: expected *errors.Error, got %T: %v", name, err, err)
		}
		route := name + ".AckListTooLong"
		if name == "AppendControl" {
			route = "AppendControl->AppendControlBody.AckListTooLong"
		}
		if !appErr.HasRoute(route) {
			t.Errorf("%s: unexpected failure path: %s", name, appErr.Route())
		}
		if appErr.Metadata["count"] != MaxAcks+1 {
			t.Errorf("%s: metadata count = %v", name, appErr.Metadata["count"])
		}
	}
}

func TestControlRoundTrip(t *testing.T) {
	// Every control opcode, every number of acks, with and without a payload.
	for _, op := range []Opcode{SoftResetV1, ControlV1, AckV1, HardResetClientV2, HardResetServerV2, HardResetClientV3, ControlWKCV1} {
		for keyID := uint8(0); keyID <= MaxKeyID; keyID += 3 {
			for n := 0; n <= MaxAcks; n++ {
				for _, payload := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte{0xab}, 1200)} {
					c := Control{Opcode: op, KeyID: keyID, SessionID: clientSID, PacketID: uint32(n) * 1000003, Payload: payload}
					if op == AckV1 {
						c.PacketID, c.Payload = 0, nil
					}
					if n > 0 {
						c.RemoteSessionID = serverSID
						for i := 0; i < n; i++ {
							c.Acks = append(c.Acks, uint32(i*7+1))
						}
					}
					packet, err := AppendControl(nil, &c)
					if err != nil {
						t.Fatal(err)
					}
					got, err := ParseControl(packet)
					if err != nil {
						t.Fatalf("%v key %d acks %d: %v", op, keyID, n, err)
					}
					if !equalControl(got, c) {
						t.Fatalf("%v key %d acks %d: parsed %+v, want %+v", op, keyID, n, got, c)
					}
				}
			}
		}
	}
}

func FuzzParseControl(f *testing.F) {
	for _, tt := range vectors {
		f.Add(unhexString(tt.packet))
	}
	f.Add([]byte{})
	f.Add([]byte{0x38})
	f.Add([]byte{0x22, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Fuzz(func(t *testing.T, packet []byte) {
		c, err := ParseControl(packet)
		if err != nil {
			return
		}
		// What parses is exactly what was sent: it makes the same bytes again.
		again, err := AppendControl(nil, &c)
		if err != nil {
			t.Fatalf("a parsed packet cannot be written: %v", err)
		}
		if !bytes.Equal(again, packet) {
			t.Fatalf("parsed %x and wrote %x", packet, again)
		}
	})
}

func FuzzParseControlBody(f *testing.F) {
	f.Add(uint8(ControlV1), []byte{0, 0, 0, 0, 7, 'h', 'i'})
	f.Add(uint8(AckV1), []byte{1, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add(uint8(0), []byte{})
	f.Fuzz(func(t *testing.T, op uint8, body []byte) {
		c, err := ParseControlBody(Opcode(op&31), body)
		if err != nil {
			return
		}
		if len(c.Acks) > MaxAcks {
			t.Fatalf("%d acks parsed", len(c.Acks))
		}
		again, err := AppendControlBody(nil, &c)
		if err != nil {
			t.Fatalf("a parsed body cannot be written: %v", err)
		}
		if !bytes.Equal(again, body) {
			t.Fatalf("parsed %x and wrote %x", body, again)
		}
	})
}

// unhexString is unhex for seeds, where there is no *testing.T.
func unhexString(s string) []byte {
	b, err := hex.DecodeString(string(bytes.ReplaceAll([]byte(s), []byte(" "), nil)))
	if err != nil {
		panic(err)
	}
	return b
}

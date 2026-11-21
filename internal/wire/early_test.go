// SPDX-License-Identifier: GPL-2.0-only

package wire

import (
	"bytes"
	"testing"

	"github.com/rm4n0s/errors"
)

func TestParseEarlyNegotiation(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    bool
	}{
		{"no payload", "", false},
		{"resend the wrapped key", "0001 0002 0001", true},
		{"flags that ask for nothing", "0001 0002 0000", false},
		{"other flag bits are ignored", "0001 0002 0003", true},
		{"only other bits", "0001 0002 fffe", false},
		{"an unknown TLV is skipped", "0007 0003 aabbcc", false},
		{"an unknown TLV before the flags", "0007 0003 aabbcc 0001 0002 0001", true},
		{"an unknown TLV after the flags", "0001 0002 0001 0007 0000", true},
		{"an empty unknown TLV", "0009 0000", false},
		{"two flags TLVs: any of them asks", "0001 0002 0000 0001 0002 0001", true},
		{"type 0x8001 is not the flags TLV", "8001 0002 0001", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEarlyNegotiation(unhex(t, tt.payload))
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("resend = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseEarlyNegotiationFailures(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		route   string
		meta    map[string]any
	}{
		{"one byte", "00", "ParseEarlyNegotiation.EarlyNegotiationTruncated", map[string]any{"left": 1}},
		{"three bytes", "000100", "ParseEarlyNegotiation.EarlyNegotiationTruncated", map[string]any{"left": 3}},
		{"the value is cut short", "0001 0002 00", "ParseEarlyNegotiation.EarlyNegotiationTruncated", map[string]any{"type": uint16(1), "length": 2, "left": 1}},
		{"no value at all", "0001 0002", "ParseEarlyNegotiation.EarlyNegotiationTruncated", map[string]any{"left": 0}},
		{"an unknown TLV that is cut short", "0007 0005 aabb", "ParseEarlyNegotiation.EarlyNegotiationTruncated", map[string]any{"type": uint16(7), "length": 5}},
		{"a good TLV and then a cut one", "0001 0002 0001 0007 00", "ParseEarlyNegotiation.EarlyNegotiationTruncated", nil},
		{"flags of 1 byte", "0001 0001 01", "ParseEarlyNegotiation.EarlyNegotiationBadFlags", map[string]any{"length": 1}},
		{"flags of 3 bytes", "0001 0003 000001", "ParseEarlyNegotiation.EarlyNegotiationBadFlags", map[string]any{"length": 3}},
		{"flags of no bytes", "0001 0000", "ParseEarlyNegotiation.EarlyNegotiationBadFlags", map[string]any{"length": 0}},
		{"a bad flags TLV after a good one", "0001 0002 0001 0001 0004 00000001", "ParseEarlyNegotiation.EarlyNegotiationBadFlags", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEarlyNegotiation(unhex(t, tt.payload))
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
			if got {
				t.Error("a payload with an error reports a resend")
			}
		})
	}
}

func TestAppendEarlyNegotiation(t *testing.T) {
	if got, want := AppendEarlyNegotiation(nil, true), unhex(t, "0001 0002 0001"); !bytes.Equal(got, want) {
		t.Errorf("asking: %x, want %x", got, want)
	}
	if got, want := AppendEarlyNegotiation([]byte{0xee}, false), unhex(t, "ee 0001 0002 0000"); !bytes.Equal(got, want) {
		t.Errorf("not asking: %x, want %x", got, want)
	}
	for _, resend := range []bool{false, true} {
		got, err := ParseEarlyNegotiation(AppendEarlyNegotiation(nil, resend))
		if err != nil || got != resend {
			t.Errorf("round trip of %v: %v, %v", resend, got, err)
		}
	}
}

func TestEarlyNegotiationStart(t *testing.T) {
	// The top byte tells the server that the client supports early negotiation;
	// the first packet then carries 0x0f000001.
	if EarlyNegotiationStart != 0x0f000000 {
		t.Errorf("EarlyNegotiationStart = %#x, want 0x0f000000", EarlyNegotiationStart)
	}
	if EarlyNegotiationStart>>24 != 0x0f {
		t.Error("the top byte is not 0x0f")
	}
}

func FuzzParseEarlyNegotiation(f *testing.F) {
	f.Add([]byte{0, 1, 0, 2, 0, 1})
	f.Add([]byte{0, 7, 0, 3, 1, 2, 3})
	f.Add([]byte{})
	f.Add([]byte{0, 1, 0, 1, 1})
	f.Fuzz(func(t *testing.T, payload []byte) {
		resend, err := ParseEarlyNegotiation(payload)
		if err != nil && resend {
			t.Fatal("an error with a resend flag")
		}
		again, err2 := ParseEarlyNegotiation(payload)
		if again != resend || (err == nil) != (err2 == nil) {
			t.Fatal("the same payload gives two answers")
		}
	})
}

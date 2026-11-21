// SPDX-License-Identifier: GPL-2.0-only

package wire

import "testing"

func TestRandomSessionID(t *testing.T) {
	seen := map[SessionID]bool{}
	for i := 0; i < 1000; i++ {
		id := RandomSessionID()
		if id.IsZero() {
			t.Fatal("RandomSessionID returned the zero id")
		}
		if seen[id] {
			t.Fatalf("RandomSessionID repeated %v after %d ids", id, i)
		}
		seen[id] = true
	}
}

func TestSessionID(t *testing.T) {
	var zero SessionID
	if !zero.IsZero() {
		t.Error("the zero id is not zero")
	}
	id := SessionID{0x01, 0x02, 0x03, 0x04, 0xa5, 0xb6, 0xc7, 0xd8}
	if id.IsZero() {
		t.Error("a non-zero id is zero")
	}
	if got, want := id.String(), "01020304a5b6c7d8"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

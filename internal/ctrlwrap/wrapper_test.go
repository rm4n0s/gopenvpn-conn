// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"bytes"
	"testing"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

func TestPlain(t *testing.T) {
	w := NewPlain()
	first := wire.FirstByte(wire.ControlV1, 3)
	for _, body := range [][]byte{nil, {1}, bytes.Repeat([]byte{7}, 1200)} {
		packet, err := w.Wrap([]byte("dst"), first, testSID, body)
		if err != nil {
			t.Fatal(err)
		}
		want := append(append([]byte("dst"), first), testSID[:]...)
		want = append(want, body...)
		if !bytes.Equal(packet, want) {
			t.Errorf("Wrap = %x, want %x", packet, want)
		}
		got, err := w.Unwrap(packet[len("dst"):])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("Unwrap = %x, want %x", got, body)
		}
	}
	if w.Overhead() != 0 {
		t.Errorf("Overhead = %d, want 0", w.Overhead())
	}
}

func TestPlainTooShort(t *testing.T) {
	for n := 0; n < headerSize; n++ {
		_, err := NewPlain().Unwrap(make([]byte, n))
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("%d bytes: expected *errors.Error, got %T: %v", n, err, err)
		}
		if !appErr.HasRoute("plain.Unwrap.PlainTooShort") {
			t.Errorf("%d bytes: unexpected failure path: %s", n, appErr.Route())
		}
		if appErr.Metadata["got"] != n || appErr.Metadata["want"] != headerSize {
			t.Errorf("%d bytes: metadata = %v", n, appErr.Metadata)
		}
	}
	// A packet with just the header has an empty body.
	body, err := NewPlain().Unwrap(make([]byte, headerSize))
	if err != nil || len(body) != 0 {
		t.Errorf("header only: %x, %v", body, err)
	}
}

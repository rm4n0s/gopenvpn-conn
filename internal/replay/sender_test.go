// SPDX-License-Identifier: GPL-2.0-only

package replay

import (
	"math"
	"testing"
	"time"

	"github.com/rm4n0s/errors"
)

func TestSender(t *testing.T) {
	var s Sender // the zero value is ready
	id, tm, err := s.Next(base)
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 || tm != baseUnix {
		t.Errorf("first = (%d, %d), want (1, %d)", id, tm, baseUnix)
	}
	// The time is the time of the first packet, whatever the clock does after.
	for want := uint32(2); want <= 5; want++ {
		id, tm, err = s.Next(base.Add(time.Duration(want) * time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if id != want || tm != baseUnix {
			t.Errorf("next = (%d, %d), want (%d, %d)", id, tm, want, baseUnix)
		}
	}
}

func TestSenderStart(t *testing.T) {
	// tls-crypt-v2 starts at 0x0f000000, so its first packet is 0x0f000001.
	s := NewSender(0x0f000000)
	for want := uint32(0x0f000001); want <= 0x0f000003; want++ {
		id, _, err := s.Next(base)
		if err != nil {
			t.Fatal(err)
		}
		if id != want {
			t.Errorf("id = %#x, want %#x", id, want)
		}
	}
}

func TestSenderIDsRunOut(t *testing.T) {
	s := NewSender(math.MaxUint32 - 2)
	for _, want := range []uint32{math.MaxUint32 - 1, math.MaxUint32} {
		id, _, err := s.Next(base)
		if err != nil || id != want {
			t.Fatalf("id = %d, %v; want %d", id, err, want)
		}
	}
	// The ids are used up and the clock has not moved: no packet.
	_, _, err := s.Next(base)
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("Next.PacketIDExhausted") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if appErr.Metadata["time"] != uint32(baseUnix) {
		t.Errorf("metadata = %v", appErr.Metadata)
	}
	// The clock moved on: counting starts again with the new time.
	const laterUnix = baseUnix + 2
	later := time.Unix(laterUnix, 0)
	id, tm, err := s.Next(later)
	if err != nil || id != 1 || tm != laterUnix {
		t.Fatalf("after the clock moved: (%d, %d, %v), want (1, %d, nil)", id, tm, err, laterUnix)
	}
	id, tm, err = s.Next(base) // and the new time stays
	if err != nil || id != 2 || tm != laterUnix {
		t.Fatalf("next: (%d, %d, %v), want (2, %d, nil)", id, tm, err, laterUnix)
	}
}

func TestSenderClockOutOfRange(t *testing.T) {
	for name, at := range map[string]time.Time{
		"before 1970":   time.Unix(-5, 0),
		"after 2106":    time.Unix(math.MaxUint32+1, 0),
		"far in future": time.Unix(1<<40, 0),
	} {
		t.Run(name, func(t *testing.T) {
			var s Sender
			_, _, err := s.Next(at)
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute("Next.ClockOutOfRange") {
				t.Errorf("unexpected failure path: %s", appErr.Route())
			}
			if appErr.Metadata["unix"] != at.Unix() {
				t.Errorf("metadata = %v", appErr.Metadata)
			}
		})
	}
	// The edges are fine.
	for _, sec := range []int64{0, math.MaxUint32} {
		var s Sender
		if _, _, err := s.Next(time.Unix(sec, 0)); err != nil {
			t.Errorf("Next at %d: %v", sec, err)
		}
	}
}

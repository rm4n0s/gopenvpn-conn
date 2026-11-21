// SPDX-License-Identifier: GPL-2.0-only

package reliable

import (
	"fmt"
	"math"
	"slices"
	"testing"
)

func p(id uint32) []byte { return []byte(fmt.Sprintf("p%d", id)) }

func payloads(deliver [][]byte) []string {
	var r []string
	for _, d := range deliver {
		r = append(r, string(d))
	}
	return r
}

func TestReceiverSequences(t *testing.T) {
	type step struct {
		id      uint32
		deliver []string
		ack     bool
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{"in order", []step{
			{0, []string{"p0"}, true}, {1, []string{"p1"}, true}, {2, []string{"p2"}, true},
		}},
		{"a copy is acknowledged and not delivered again", []step{
			{0, []string{"p0"}, true}, {0, nil, true}, {1, []string{"p1"}, true}, {0, nil, true}, {1, nil, true},
		}},
		{"early packets wait for the missing one", []step{
			{2, nil, true}, {1, nil, true}, {3, nil, true},
			{0, []string{"p0", "p1", "p2", "p3"}, true},
			{4, []string{"p4"}, true},
		}},
		{"a copy of an early packet is acknowledged, delivered once", []step{
			{1, nil, true}, {1, nil, true}, {0, []string{"p0", "p1"}, true},
		}},
		{"the last id of the window is kept, the next is dropped", []step{
			{ReceiveWindow - 1, nil, true},
			{ReceiveWindow, nil, false},
			{ReceiveWindow + 100, nil, false},
			{0, []string{"p0"}, true},
			// 0 was delivered: next is 1, so id 12 is now inside the window.
			{ReceiveWindow, nil, true},
		}},
		{"a gap that is filled in the middle", []step{
			{0, []string{"p0"}, true}, {3, nil, true}, {1, []string{"p1"}, true}, {2, []string{"p2", "p3"}, true},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r Receiver
			for i, s := range tt.steps {
				deliver, ack := r.Receive(s.id, p(s.id))
				if got := payloads(deliver); !slices.Equal(got, s.deliver) || ack != s.ack {
					t.Fatalf("step %d: Receive(%d) = %v, %v; want %v, %v", i, s.id, got, ack, s.deliver, s.ack)
				}
				// Drop the acknowledgements so that the list never fills here.
				r.Acks(MaxAcks)
			}
		})
	}
}

func TestReceiverEmptyPayloadsAreDelivered(t *testing.T) {
	var r Receiver
	deliver, ack := r.Receive(0, nil)
	if len(deliver) != 1 || len(deliver[0]) != 0 || !ack {
		t.Fatalf("Receive(0, nil) = %v, %v", deliver, ack)
	}
	if deliver, _ = r.Receive(1, []byte{}); len(deliver) != 1 {
		t.Fatalf("an empty payload is not delivered: %v", deliver)
	}
}

func TestReceiverIDsWrap(t *testing.T) {
	var r Receiver
	r.next = math.MaxUint32 - 1
	if d, ack := r.Receive(0, p(0)); d != nil || !ack {
		t.Fatalf("early id across the wrap: %v, %v", d, ack)
	}
	r.Acks(MaxAcks)
	if d, ack := r.Receive(math.MaxUint32, p(math.MaxUint32)); d != nil || !ack {
		t.Fatalf("early id before the wrap: %v, %v", d, ack)
	}
	r.Acks(MaxAcks)
	d, ack := r.Receive(math.MaxUint32-1, p(math.MaxUint32-1))
	if len(d) != 3 || !ack {
		t.Fatalf("the missing packet freed %d payloads, want 3", len(d))
	}
	if d, ack = r.Receive(1, p(1)); len(d) != 1 || !ack {
		t.Errorf("after the wrap: %v, %v", d, ack)
	}
}

func TestReceiverAcks(t *testing.T) {
	var r Receiver
	if r.HasPendingAcks() || r.Acks(MaxAcks) != nil {
		t.Fatal("a new receiver has acknowledgements")
	}
	r.Receive(0, p(0))
	r.Receive(1, p(1))
	r.Receive(2, p(2))
	if !r.HasPendingAcks() {
		t.Fatal("HasPendingAcks is false")
	}
	if got := r.Acks(MaxAcks); !slices.Equal(got, []uint32{0, 1, 2}) {
		t.Fatalf("Acks = %v, want [0 1 2]", got)
	}
	if r.HasPendingAcks() {
		t.Error("the acknowledgements are still pending after they were sent")
	}
	// Sent ids are repeated while there is room, newest first.
	r.Receive(3, p(3))
	if got := r.Acks(MaxAcks); !slices.Equal(got, []uint32{3, 0, 1, 2}) {
		t.Fatalf("Acks = %v, want [3 0 1 2]", got)
	}
	// With nothing new, the same ones again.
	if got := r.Acks(MaxAcks); !slices.Equal(got, []uint32{3, 0, 1, 2}) {
		t.Fatalf("Acks with nothing pending = %v", got)
	}
	// A room of two: the new one first, one repeated.
	r.Receive(4, p(4))
	if got := r.Acks(2); !slices.Equal(got, []uint32{4, 3}) {
		t.Fatalf("Acks(2) = %v, want [4 3]", got)
	}
	if got := r.Acks(0); got != nil {
		t.Errorf("Acks(0) = %v", got)
	}
}

func TestReceiverAcksLeaveWhatDoesNotFit(t *testing.T) {
	var r Receiver
	for id := uint32(0); id < 5; id++ {
		r.Receive(id, p(id))
	}
	if got := r.Acks(2); !slices.Equal(got, []uint32{0, 1}) {
		t.Fatalf("Acks(2) = %v, want [0 1]", got)
	}
	if !r.HasPendingAcks() {
		t.Fatal("2 3 4 should still be pending")
	}
	if got := r.Acks(3); !slices.Equal(got, []uint32{2, 3, 4}) {
		t.Fatalf("Acks(3) = %v, want [2 3 4]", got)
	}
	if got := r.Acks(MaxAcks); !slices.Equal(got, []uint32{2, 3, 4, 0, 1}) {
		t.Fatalf("Acks = %v, want [2 3 4 0 1]", got)
	}
	// More room than the packet format has.
	if got := r.Acks(100); len(got) > MaxAcks {
		t.Errorf("Acks(100) returned %d ids", len(got))
	}
}

func TestReceiverRecentIDsAreBounded(t *testing.T) {
	var r Receiver
	for id := uint32(0); id < 40; id++ {
		r.Receive(id, p(id))
		r.Acks(MaxAcks)
	}
	got := r.Acks(MaxAcks)
	want := []uint32{39, 38, 37, 36, 35, 34, 33, 32}
	if !slices.Equal(got, want) {
		t.Errorf("Acks = %v, want %v", got, want)
	}
}

func TestReceiverRepeatedAckMovesToFront(t *testing.T) {
	var r Receiver
	for id := uint32(0); id < 3; id++ {
		r.Receive(id, p(id))
	}
	r.Acks(MaxAcks) // recent: 0 1 2
	// A copy of 0 arrives: it is acknowledged again, and goes in front.
	if _, ack := r.Receive(0, p(0)); !ack {
		t.Fatal("a copy was not acknowledged")
	}
	if got := r.Acks(MaxAcks); !slices.Equal(got, []uint32{0, 1, 2}) {
		t.Errorf("Acks = %v, want [0 1 2]", got)
	}
	r.Receive(2, p(2))
	if got := r.Acks(MaxAcks); !slices.Equal(got, []uint32{2, 0, 1}) {
		t.Errorf("Acks = %v, want [2 0 1]", got)
	}
}

func TestReceiverFullAckListDropsNewPackets(t *testing.T) {
	var r Receiver
	// Eight packets arrive and none of their acknowledgements is sent.
	for id := uint32(0); id < MaxAcks; id++ {
		if _, ack := r.Receive(id, p(id)); !ack {
			t.Fatalf("packet %d refused", id)
		}
	}
	// A ninth is dropped, not kept: the peer sends it again.
	if d, ack := r.Receive(8, p(8)); d != nil || ack {
		t.Fatalf("Receive(8) = %v, %v with a full list", d, ack)
	}
	// A copy of one that waits is fine.
	if _, ack := r.Receive(3, p(3)); !ack {
		t.Error("a copy of a pending id was refused")
	}
	// After the acknowledgements went out, the ninth is taken, and it was not
	// kept before (it is delivered now, not lost, and not twice).
	r.Acks(MaxAcks)
	d, ack := r.Receive(8, p(8))
	if len(d) != 1 || string(d[0]) != "p8" || !ack {
		t.Fatalf("Receive(8) = %v, %v", payloads(d), ack)
	}
}

func TestReceiverKeepsAtMostTheWindowAhead(t *testing.T) {
	var r Receiver
	for id := uint32(1); id < 100; id++ {
		r.Receive(id, p(id))
		r.Acks(MaxAcks)
	}
	if len(r.ahead) != ReceiveWindow-1 {
		t.Errorf("%d packets are kept, want %d", len(r.ahead), ReceiveWindow-1)
	}
}

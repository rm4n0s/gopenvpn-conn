// SPDX-License-Identifier: GPL-2.0-only

package reliable

import (
	"math"
	"slices"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

var base = time.Unix(1_700_000_000, 0)

func at(sec float64) time.Time {
	return base.Add(time.Duration(sec * float64(time.Second)))
}

func ids(out []Outgoing) []uint32 {
	var r []uint32
	for _, o := range out {
		r = append(r, o.ID)
	}
	return r
}

func queueN(t *testing.T, s *Sender, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := s.Queue(wire.ControlV1, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSenderNumbersPacketsFromZeroAndSendsThemAtOnce(t *testing.T) {
	s := NewSender(2 * time.Second)
	for want := uint32(0); want < 3; want++ {
		id, err := s.Queue(wire.ControlV1, []byte{byte(want)})
		if err != nil || id != want {
			t.Fatalf("Queue = %d, %v; want %d", id, err, want)
		}
	}
	out := s.Due(base)
	if !slices.Equal(ids(out), []uint32{0, 1, 2}) {
		t.Fatalf("Due = %v, want 0 1 2", ids(out))
	}
	for i, o := range out {
		if o.Opcode != wire.ControlV1 || len(o.Payload) != 1 || o.Payload[0] != byte(i) {
			t.Errorf("outgoing %d = %+v", i, o)
		}
	}
	if got := s.Due(base); got != nil {
		t.Errorf("a second Due at the same time returned %v", ids(got))
	}
}

func TestSenderKeepsTheOpcodeOfEachPacket(t *testing.T) {
	// A reset stays a reset when it is sent again, and the third packet of
	// tls-crypt-v2 stays a CONTROL_WKC_V1.
	s := NewSender(2 * time.Second)
	for _, op := range []wire.Opcode{wire.HardResetClientV3, wire.ControlWKCV1, wire.ControlV1} {
		if _, err := s.Queue(op, nil); err != nil {
			t.Fatal(err)
		}
	}
	s.Due(base)
	out := s.Due(at(2))
	want := []wire.Opcode{wire.HardResetClientV3, wire.ControlWKCV1, wire.ControlV1}
	if len(out) != 3 {
		t.Fatalf("resent %d packets, want 3", len(out))
	}
	for i := range out {
		if out[i].Opcode != want[i] {
			t.Errorf("packet %d resent as %v, want %v", i, out[i].Opcode, want[i])
		}
	}
}

func TestSenderRetransmissionTimes(t *testing.T) {
	// The wait is 2 s and doubles up to 128 s: the packet goes out at these
	// seconds, and at no time in between.
	sends := []float64{0, 2, 6, 14, 30, 62, 126, 254, 382, 510}
	s := NewSender(2 * time.Second)
	queueN(t, s, 1)
	var got []float64
	for sec := 0.0; sec <= 520; sec += 0.5 {
		if len(s.Due(at(sec))) > 0 {
			got = append(got, sec)
		}
	}
	if len(got) != len(sends) {
		t.Fatalf("sent at %v, want %v", got, sends)
	}
	for i := range sends {
		if got[i] != sends[i] {
			t.Fatalf("sent at %v, want %v", got, sends)
		}
	}
}

func TestSenderInitialTimeoutIsConfigurable(t *testing.T) {
	s := NewSender(500 * time.Millisecond)
	queueN(t, s, 1)
	s.Due(base)
	if len(s.Due(base.Add(499*time.Millisecond))) != 0 {
		t.Error("sent again before the timeout")
	}
	if len(s.Due(base.Add(500*time.Millisecond))) != 1 {
		t.Error("not sent again at the timeout")
	}
	// The longest wait is 64 times the first: 32 s.
	now := base.Add(500 * time.Millisecond)
	var last time.Duration
	for i := 0; i < 12; i++ {
		d, _ := s.NextDeadline()
		last = d.Sub(now)
		now = d
		s.Due(now)
	}
	if last != 32*time.Second {
		t.Errorf("the longest wait is %v, want 32s", last)
	}
}

func TestSenderWindow(t *testing.T) {
	s := NewSender(2 * time.Second)
	queueN(t, s, SendWindow)
	if s.CanSend() || s.Len() != SendWindow {
		t.Fatalf("CanSend = %v, Len = %d with a full window", s.CanSend(), s.Len())
	}
	_, err := s.Queue(wire.ControlV1, nil)
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("Queue.SendWindowFull") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if !s.Ack(3) || !s.CanSend() {
		t.Fatal("an acknowledgement did not open the window")
	}
	// The packet that was refused had no id: the next one is 6.
	if id, err := s.Queue(wire.ControlV1, nil); err != nil || id != 6 {
		t.Errorf("Queue = %d, %v; want 6", id, err)
	}
}

func TestSenderAck(t *testing.T) {
	s := NewSender(2 * time.Second)
	queueN(t, s, 3)
	s.Due(base)
	tests := []struct {
		id   uint32
		want bool
		left int
	}{
		{id: 1, want: true, left: 2},
		{id: 1, want: false, left: 2}, // repeated
		{id: 99, want: false, left: 2},
		{id: 0, want: true, left: 1},
		{id: 2, want: true, left: 0},
		{id: 2, want: false, left: 0},
	}
	for _, tt := range tests {
		if got := s.Ack(tt.id); got != tt.want || s.Len() != tt.left {
			t.Fatalf("Ack(%d) = %v, left %d; want %v, left %d", tt.id, got, s.Len(), tt.want, tt.left)
		}
	}
	if _, ok := s.NextDeadline(); ok {
		t.Error("NextDeadline reports a packet when none waits")
	}
}

func TestSenderAckedPacketsAreNotSentAgain(t *testing.T) {
	s := NewSender(2 * time.Second)
	queueN(t, s, 3)
	s.Due(base)
	s.Ack(0)
	s.Ack(2)
	if got := ids(s.Due(at(2))); !slices.Equal(got, []uint32{1}) {
		t.Errorf("resent %v, want [1]", got)
	}
}

func TestSenderFastRetransmit(t *testing.T) {
	s := NewSender(2 * time.Second)
	queueN(t, s, 5)
	s.Due(base)
	// 1 and 2 are acknowledged, 0 is not: two later packets are not enough.
	s.Ack(1)
	s.Ack(2)
	if got := s.Due(at(0.1)); got != nil {
		t.Fatalf("resent %v after two later acks", ids(got))
	}
	if d, ok := s.NextDeadline(); !ok || !d.Equal(at(2)) {
		t.Errorf("NextDeadline = %v, %v; want %v", d, ok, at(2))
	}
	// The third later packet: 0 goes out at once, and 4 (not acked) does not.
	s.Ack(3)
	if d, ok := s.NextDeadline(); !ok || d.After(at(0.1)) {
		t.Errorf("NextDeadline = %v, %v; want a time that is not after now", d, ok)
	}
	if got := ids(s.Due(at(0.1))); !slices.Equal(got, []uint32{0}) {
		t.Fatalf("resent %v, want [0]", got)
	}
	// 4 was overtaken by nothing; the wait of 0 is now 4 s (from 0.1 s) and its count is 0.
	s.Ack(4)
	if got := s.Due(at(0.2)); got != nil {
		t.Errorf("resent %v again at once", ids(got))
	}
	if got := ids(s.Due(at(4.2))); !slices.Equal(got, []uint32{0}) {
		t.Errorf("at 4.2 s resent %v, want [0]", got)
	}
}

func TestSenderRepeatedAcksCountOnce(t *testing.T) {
	// The peer repeats an id in later packets. That is one packet, not three.
	s := NewSender(2 * time.Second)
	queueN(t, s, 3)
	s.Due(base)
	for i := 0; i < 5; i++ {
		s.Ack(1)
	}
	if got := s.Due(at(0.1)); got != nil {
		t.Errorf("resent %v after one packet was acknowledged five times", ids(got))
	}
}

func TestSenderAcksOfEarlierPacketsDoNotOvertake(t *testing.T) {
	// Only an acknowledgement of a later id counts against a packet.
	s := NewSender(2 * time.Second)
	queueN(t, s, 5)
	s.Due(base)
	s.Ack(0)
	s.Ack(1)
	s.Ack(2)
	if got := s.Due(at(0.1)); got != nil {
		t.Errorf("resent %v, but 3 and 4 were never overtaken", ids(got))
	}
}

func TestSenderIDsWrap(t *testing.T) {
	s := NewSender(2 * time.Second)
	s.next = math.MaxUint32 - 1
	queueN(t, s, 4) // MaxUint32-1, MaxUint32, 0, 1
	if got := ids(s.Due(base)); !slices.Equal(got, []uint32{math.MaxUint32 - 1, math.MaxUint32, 0, 1}) {
		t.Fatalf("ids = %v", got)
	}
	// 3 acknowledged ids after the first overtake it, across the wrap.
	s.Ack(math.MaxUint32)
	s.Ack(0)
	s.Ack(1)
	if got := ids(s.Due(at(0.1))); !slices.Equal(got, []uint32{math.MaxUint32 - 1}) {
		t.Errorf("resent %v, want the first id", got)
	}
}

func TestNewSenderPanicsOnABadTimeout(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second, time.Hour + 1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewSender(%v) did not panic", d)
				}
			}()
			NewSender(d)
		}()
	}
	NewSender(time.Hour) // the edge is fine
}

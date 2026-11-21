// SPDX-License-Identifier: GPL-2.0-only

package replay

import (
	"math/rand"
	"testing"
	"time"
)

// baseUnix is the clock of the tests; a constant, so that it converts to a
// 32-bit time with no doubt about its range.
const baseUnix = 1_700_000_000

var base = time.Unix(baseUnix, 0)

// toUint64 converts a size of the tests, which is never negative.
func toUint64(n int) uint64 {
	if n < 0 {
		panic("negative size")
	}
	return uint64(n)
}

// step is one packet: it is checked at time base+at, and accepted when accept.
type step struct {
	counter uint64
	at      time.Duration
	want    bool // what Check says
	accept  bool // whether the packet is authentic and is accepted
}

func TestWindowSequences(t *testing.T) {
	tests := []struct {
		name   string
		size   int
		maxAge time.Duration
		steps  []step
	}{
		{
			name: "in order, replays, out of order inside the window, and below it (size 4)",
			size: 4,
			steps: []step{
				{1, 0, true, true}, {2, 0, true, true}, {3, 0, true, true},
				{2, 0, false, false}, // replay
				{5, 0, true, true},   // a gap
				{3, 0, false, false}, // seen
				{4, 0, true, true},   // late but inside the window
				{4, 0, false, false}, // now a replay
				{1, 0, false, false}, // 5-1 = 4 >= size: too old
				{2, 0, false, false}, // seen and 3 behind
			},
		},
		{
			name: "a jump of the window's size or more forgets everything",
			size: 4,
			steps: []step{
				{1, 0, true, true}, {2, 0, true, true},
				{6, 0, true, true},   // 6-2 = 4: the old counters are all out
				{5, 0, true, true},   // 6-5 = 1: unseen
				{2, 0, false, false}, // 6-2 = 4: a window behind
				{3, 0, true, true},   // 6-3 = 3: inside, and never seen
			},
		},
		{
			name:  "0 is never valid",
			size:  64,
			steps: []step{{0, 0, false, false}, {1, 0, true, true}, {0, 0, false, false}},
		},
		{
			name:  "the first counter may be anything but 0",
			size:  64,
			steps: []step{{1 << 40, 0, true, true}, {1<<40 - 63, 0, true, true}, {1<<40 - 64, 0, false, false}, {1<<40 + 1, 0, true, true}},
		},
		{
			name:  "a window of one counter takes only higher counters",
			size:  1,
			steps: []step{{5, 0, true, true}, {5, 0, false, false}, {4, 0, false, false}, {6, 0, true, true}},
		},
		{
			name: "a newer time is a higher counter, an older time is far below it",
			size: 64,
			steps: []step{
				{10<<32 | 1, 0, true, true}, {10<<32 | 2, 0, true, true},
				{11<<32 | 1, 0, true, true},   // time moved forward: the id starts over
				{10<<32 | 3, 0, false, false}, // an older time is refused
				{11<<32 | 1, 0, false, false}, // replay
				{11<<32 | 2, 0, true, true},
			},
		},
		{
			name:   "a late packet is refused after the age, when a higher one is that old",
			size:   64,
			maxAge: 15 * time.Second,
			steps: []step{
				{10, 0, true, true},
				{20, 1 * time.Second, true, true},
				{15, 16 * time.Second, true, true},   // 10 arrived 16 s ago, but 20 only 15: 15 is above the old 10
				{5, 16 * time.Second, false, false},  // below 10, which arrived more than 15 s ago
				{18, 17 * time.Second, false, false}, // 20 now arrived more than 15 s ago too
				{25, 17 * time.Second, true, true},   // higher than everything: always fine
				{22, 18 * time.Second, true, true},   // above the old 20; 25 arrived a second ago
			},
		},
		{
			name:   "without an age a late packet is fine while it is inside the window",
			size:   64,
			maxAge: 0,
			steps:  []step{{10, 0, true, true}, {20, time.Second, true, true}, {15, time.Hour, true, true}, {14, time.Hour, true, true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWindow(tt.size, tt.maxAge)
			for i, s := range tt.steps {
				now := base.Add(s.at)
				if got := w.Check(s.counter, now); got != s.want {
					t.Fatalf("step %d: Check(%d) = %v, want %v", i, s.counter, got, s.want)
				}
				if s.accept {
					w.Accept(s.counter, now)
				}
			}
		})
	}
}

func TestWindowCheckChangesNothing(t *testing.T) {
	w := NewWindow(8, 0)
	for i := 0; i < 5; i++ {
		if !w.Check(7, base) {
			t.Fatal("a counter that was only checked is refused")
		}
	}
	w.Accept(7, base)
	if w.Check(7, base) {
		t.Error("an accepted counter is allowed again")
	}
}

func TestWindowAcceptIgnoresARefusedCounter(t *testing.T) {
	w := NewWindow(4, 0)
	w.Accept(10, base)
	w.Accept(2, base) // 8 below: refused, must not move anything
	w.Accept(0, base) // never valid
	w.Accept(10, base)
	if !w.Check(9, base) || !w.Check(11, base) {
		t.Error("the window moved after a refused counter")
	}
}

// model is the plainest window: a set of accepted counters, and for the age
// rule when each was accepted.
type model struct {
	size   uint64
	maxAge time.Duration
	seen   map[uint64]bool
	events []modelEvent
	max    uint64
	any    bool
}

type modelEvent struct {
	second  int64
	counter uint64
}

func (m *model) check(c uint64, now time.Time) bool {
	if c == 0 || m.seen[c] {
		return false
	}
	if !m.any || c > m.max {
		return true
	}
	if m.max-c >= m.size {
		return false
	}
	if m.maxAge > 0 {
		cutoff := now.Add(-m.maxAge).Unix()
		var stale uint64
		for _, e := range m.events {
			if e.second < cutoff && e.counter > stale {
				stale = e.counter
			}
		}
		return c > stale
	}
	return true
}

func (m *model) accept(c uint64, now time.Time) {
	if !m.check(c, now) {
		return
	}
	m.seen[c] = true
	m.events = append(m.events, modelEvent{second: now.Unix(), counter: c})
	if !m.any || c > m.max {
		m.max, m.any = c, true
	}
}

func TestWindowAgainstModel(t *testing.T) {
	sizes := []int{1, 2, 3, 7, 32, 63, 64, 65, 100, 128}
	ages := []time.Duration{0, 5 * time.Second}
	for _, size := range sizes {
		for _, age := range ages {
			rng := rand.New(rand.NewSource(int64(size)*1000 + int64(age/time.Second)))
			for seq := 0; seq < 60; seq++ {
				w := NewWindow(size, age)
				m := &model{size: toUint64(size), maxAge: age, seen: map[uint64]bool{}}
				now := base
				highest := rng.Uint64() % 300
				for op := 0; op < 300; op++ {
					now = now.Add(time.Duration(rng.Intn(3)) * time.Second)
					// Mostly counters near the highest, sometimes far away, sometimes 0.
					var c uint64
					switch rng.Intn(20) {
					case 0:
						c = 0
					case 1:
						c = highest + rng.Uint64()%toUint64(5*size+5)
					case 2:
						c = rng.Uint64() % (highest + 1)
					default:
						c = highest + rng.Uint64()%3 - rng.Uint64()%toUint64(size+3)
						if c > highest+3 { // the subtraction wrapped
							c = highest
						}
					}
					if c > highest {
						highest = c
					}
					got, want := w.Check(c, now), m.check(c, now)
					if got != want {
						t.Fatalf("size %d age %v seq %d op %d: Check(%d) = %v, model says %v (highest %d)", size, age, seq, op, c, got, want, m.max)
					}
					if rng.Intn(10) != 0 { // one packet in ten is not authentic and not accepted
						w.Accept(c, now)
						m.accept(c, now)
					}
				}
			}
		}
	}
}

func TestWindowRingWraps(t *testing.T) {
	// 10,000 counters in order, for sizes around the machine word, each accepted once.
	for _, size := range []int{1, 63, 64, 65, 128, 1000} {
		w := NewWindow(size, 0)
		for c := uint64(1); c <= 10000; c++ {
			if !w.Check(c, base) {
				t.Fatalf("size %d: counter %d refused", size, c)
			}
			w.Accept(c, base)
			if w.Check(c, base) {
				t.Fatalf("size %d: counter %d allowed twice", size, c)
			}
			if behind := c - toUint64(size); c > toUint64(size) && w.Check(behind, base) {
				t.Fatalf("size %d: counter %d is allowed, it is a full window behind %d", size, behind, c)
			}
		}
	}
}

func TestWindowHistoryStaysSmall(t *testing.T) {
	// 100,000 packets over 200 seconds: the history is a point a second at
	// most, and old ones are dropped.
	w := NewWindow(64, 15*time.Second)
	now := base
	for c := uint64(1); c <= 100000; c++ {
		if c%500 == 0 {
			now = now.Add(time.Second)
		}
		w.Accept(c, now)
	}
	if len(w.history) > 20 {
		t.Errorf("history has %d points, want about 17", len(w.history))
	}
}

func TestNewWindowPanicsOnASizeBelowOne(t *testing.T) {
	for _, size := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewWindow(%d, 0) did not panic", size)
				}
			}()
			NewWindow(size, 0)
		}()
	}
}

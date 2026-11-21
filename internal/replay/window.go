// SPDX-License-Identifier: GPL-2.0-only

package replay

import "time"

// Window is a sliding replay window over a 64-bit packet counter. It tells
// whether a counter that arrived is new, and remembers the counters that were
// accepted. A Window is not safe for concurrent use.
//
// A counter is refused when it is 0, when it was accepted before, when it is
// size or more below the highest accepted counter, and (if the window has a
// maximum age) when a counter higher than it was accepted more than the
// maximum age ago, so that a packet that was held back cannot arrive late.
//
// Draft: "Replay protection" and the replay rules of "HMAC authentication of
// control channel packets". The numbers OpenVPN uses are a window of 64
// counters and 15 seconds.
//
// Receiving takes two steps, so that a forged packet changes nothing: Check
// before the packet is authenticated, and Accept after it was.
type Window struct {
	size    uint64
	maxAge  time.Duration
	highest uint64
	seen    bool     // whether any counter was accepted
	bits    []uint64 // a ring of size bits: the bit of counter c is c % size
	history []point  // the highest counter at the end of each second, for maxAge
}

// point is the highest counter that was accepted by the end of a second.
type point struct {
	second  int64
	highest uint64
}

// NewWindow makes a window of size counters. maxAge is the age rule described
// on Window; 0 turns it off. It panics if size is less than 1.
func NewWindow(size int, maxAge time.Duration) *Window {
	if size < 1 {
		panic("replay: the size of a window is at least 1")
	}
	return &Window{
		size:   uint64(size),
		maxAge: maxAge,
		bits:   make([]uint64, (size+63)/64),
	}
}

// Check reports whether a packet with this counter may be accepted. It changes
// nothing: call Accept when the packet has been authenticated.
func (w *Window) Check(counter uint64, now time.Time) bool {
	if counter == 0 {
		return false
	}
	if !w.seen || counter > w.highest {
		return true
	}
	if w.highest-counter >= w.size {
		return false
	}
	if w.bit(counter) {
		return false
	}
	// The counter is below the highest and not yet seen. With an age rule it
	// must also be above every counter that was accepted more than maxAge ago.
	return w.maxAge <= 0 || counter > w.staleHighest(now)
}

// Accept records a counter that Check allowed and whose packet has been
// authenticated. A counter that Check would refuse is ignored.
func (w *Window) Accept(counter uint64, now time.Time) {
	if !w.Check(counter, now) {
		return
	}
	if !w.seen || counter > w.highest {
		w.advance(counter, now)
		return
	}
	w.setBit(counter)
}

// advance makes counter the highest. The bits of the counters that the window
// slides over are cleared first: the ring reuses them for the new counters.
func (w *Window) advance(counter uint64, now time.Time) {
	switch {
	case !w.seen || counter-w.highest >= w.size:
		clear(w.bits)
	default:
		for c := w.highest + 1; c <= counter; c++ {
			w.clearBit(c)
		}
	}
	w.seen = true
	w.highest = counter
	w.setBit(counter)
	if w.maxAge > 0 {
		w.record(now)
	}
}

func (w *Window) bit(counter uint64) bool {
	i := counter % w.size
	return w.bits[i/64]&(1<<(i%64)) != 0
}

func (w *Window) setBit(counter uint64) {
	i := counter % w.size
	w.bits[i/64] |= 1 << (i % 64)
}

func (w *Window) clearBit(counter uint64) {
	i := counter % w.size
	w.bits[i/64] &^= 1 << (i % 64)
}

// record notes the highest counter at the end of the current second. A second
// is the unit: the age rule is exact to a second, and the history has at most
// maxAge in seconds plus 2 points however many packets come.
func (w *Window) record(now time.Time) {
	sec := now.Unix()
	if n := len(w.history); n > 0 && w.history[n-1].second >= sec {
		// Same second (or the clock went back): update the point.
		w.history[n-1].highest = w.highest
		return
	}
	w.history = append(w.history, point{second: sec, highest: w.highest})
	w.prune(now)
}

// staleHighest is the highest counter that was accepted before the last
// maxAge: counters at or below it that were not seen are too late. It is 0
// when no counter is that old.
func (w *Window) staleHighest(now time.Time) uint64 {
	cutoff := now.Add(-w.maxAge).Unix()
	var stale uint64
	for _, p := range w.history {
		if p.second >= cutoff {
			break
		}
		stale = p.highest
	}
	return stale
}

// prune drops the points that no longer matter: of the points older than the
// cutoff only the newest is needed.
func (w *Window) prune(now time.Time) {
	cutoff := now.Add(-w.maxAge).Unix()
	drop := 0
	for drop+1 < len(w.history) && w.history[drop+1].second < cutoff {
		drop++
	}
	if drop > 0 {
		w.history = append(w.history[:0], w.history[drop:]...)
	}
}

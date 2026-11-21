// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"os"
	"sync"
	"time"
)

// deadline is a point in time that a Read or a Write must not wait past, as
// SetReadDeadline and SetWriteDeadline of a net.Conn set it. It starts no goroutine
// and no timer by itself: a call that waits makes a timer for its own wait, and
// is told when the deadline changes under it.
type deadline struct {
	mu      sync.Mutex
	t       time.Time
	changed chan struct{} // closed, and replaced, by every set
}

func newDeadline() *deadline { return &deadline{changed: make(chan struct{})} }

// set makes t the deadline; the zero time is no deadline. A call that waits on the
// old one wakes up and looks again.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	d.t = t
	close(d.changed)
	d.changed = make(chan struct{})
	d.mu.Unlock()
}

// get is the deadline, and a channel that is closed when it changes.
func (d *deadline) get() (time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.t, d.changed
}

// timerFor starts a timer for the deadline t: its channel fires when t comes, and nil
// when there is none. The caller stops the timer.
func timerFor(t time.Time) (*time.Timer, <-chan time.Time) {
	if t.IsZero() {
		return nil, nil
	}
	tm := time.NewTimer(time.Until(t))
	return tm, tm.C
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// errDeadline is the value that Read and Write return when their deadline passes: the
// one of the os package, which is a net.Error whose Timeout is true, untouched (SPEC
// §5.3).
var errDeadline = os.ErrDeadlineExceeded

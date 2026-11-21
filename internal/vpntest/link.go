// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

// LinkOptions make a datagram link unreliable, the way a network is. The zero
// value is a perfect link.
type LinkOptions struct {
	Seed      int64         // the faults are the same for the same seed
	Loss      float64       // the share of datagrams that are lost, 0 to 1
	Duplicate float64       // the share that arrive twice
	MaxDelay  time.Duration // each datagram is held for a random time up to this: later ones may overtake it
}

// NewDatagramPair returns the two ends of a link in memory that keeps the
// boundaries of datagrams, like connected UDP sockets. A datagram that does not
// fit the queue of the receiver is lost.
func NewDatagramPair(opts LinkOptions) (a, b net.Conn) {
	l := &link{opts: opts, rng: rand.New(rand.NewSource(opts.Seed))}
	ca, cb := newDatagramConn(l, "a"), newDatagramConn(l, "b")
	ca.peer, cb.peer = cb, ca
	return ca, cb
}

// NewStreamPair returns the two ends of a stream in memory, like a TCP
// connection.
func NewStreamPair() (a, b net.Conn) {
	return net.Pipe()
}

// link is what the two ends share: the options and the one source of chance.
type link struct {
	opts LinkOptions
	mu   sync.Mutex
	rng  *rand.Rand
}

// fates decides what happens to one datagram: how long each copy is held, and
// no copy at all when it is lost.
func (l *link) fates() []time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rng.Float64() < l.opts.Loss {
		return nil
	}
	n := 1
	if l.rng.Float64() < l.opts.Duplicate {
		n = 2
	}
	delays := make([]time.Duration, n)
	if l.opts.MaxDelay > 0 {
		for i := range delays {
			delays[i] = time.Duration(l.rng.Int63n(int64(l.opts.MaxDelay) + 1))
		}
	}
	return delays
}

type addr string

func (addr) Network() string  { return "vpntest" }
func (a addr) String() string { return string(a) }

const datagramQueue = 1024

type datagramConn struct {
	link   *link
	name   string
	peer   *datagramConn
	in     chan []byte
	closed chan struct{}
	once   sync.Once
	rd, wd deadline
}

func newDatagramConn(l *link, name string) *datagramConn {
	return &datagramConn{
		link: l, name: name,
		in: make(chan []byte, datagramQueue), closed: make(chan struct{}),
		rd: newDeadline(), wd: newDeadline(),
	}
}

// Read returns one datagram; what does not fit b is dropped, as with UDP.
func (c *datagramConn) Read(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	select {
	case p := <-c.in:
		return copy(b, p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.rd.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

// Write sends one datagram to the other end, or loses it.
func (c *datagramConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	select {
	case <-c.wd.wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	pkt := append([]byte(nil), b...)
	for _, d := range c.link.fates() {
		if d == 0 {
			c.peer.enqueue(pkt)
			continue
		}
		time.AfterFunc(d, func() { c.peer.enqueue(pkt) })
	}
	return len(b), nil
}

func (c *datagramConn) enqueue(p []byte) {
	select {
	case <-c.closed:
		return
	default:
	}
	select {
	case c.in <- p:
	default: // the queue is full: lost
	}
}

func (c *datagramConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.rd.set(time.Time{})
		c.wd.set(time.Time{})
	})
	return nil
}

func (c *datagramConn) LocalAddr() net.Addr  { return addr(c.name) }
func (c *datagramConn) RemoteAddr() net.Addr { return addr(c.peer.name) }

func (c *datagramConn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return nil
}
func (c *datagramConn) SetReadDeadline(t time.Time) error  { c.rd.set(t); return nil }
func (c *datagramConn) SetWriteDeadline(t time.Time) error { c.wd.set(t); return nil }

// deadline is a channel that is closed when a time has passed, and can be set
// again: a call that waits on it is released by a new, earlier deadline.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func newDeadline() deadline { return deadline{cancel: make(chan struct{})} }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired: its function closes the channel
	}
	d.timer = nil
	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

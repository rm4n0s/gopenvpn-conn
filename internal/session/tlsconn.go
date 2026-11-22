// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl.c (write_outgoing_tls_ciphertext, read_incoming_tls_ciphertext, calc_control_channel_frame_overhead) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package session

import (
	"net"
	"sync"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

const (
	// tlsMTU is the size that a control packet may have on the link, with its
	// protection: OpenVPN's tls_mtu (--tls-mtu), 1250 by default. The server
	// sends no packet larger than that, and none that the client sends needs to be.
	tlsMTU = 1250
	// linkOverhead is what the link adds to a UDP packet, counted as OpenVPN
	// counts it, for IPv6: 40 bytes of IP and 8 of UDP. TCP is not counted
	// differently, as a packet that the link has to cut costs nothing there.
	linkOverhead = 48
	// ackBlockMax is the acknowledgements of a packet in the worst case: the
	// count, the session id of the peer and 8 ids.
	ackBlockMax = 1 + wire.SessionIDSize + 4*wire.MaxAcks
	// minPayload is the least that a packet carries when the wrapped key of
	// tls-crypt-v2 leaves no room: OpenVPN sends 16 bytes then.
	minPayload = 16
	// inboundLimit is how many bytes of TLS may wait for the TLS side to read
	// them. Beyond it a packet is not acknowledged, and the peer sends it again
	// later: the peer cannot make the buffer grow (SPEC §15 rule 6).
	inboundLimit = 256 << 10
)

// payloadBudget is how many bytes of TLS fit one control packet whose
// protection is w: what is left of tlsMTU after the first byte, the session
// id, the acknowledgements (all that can be there), the packet id, the
// protection and the overhead of the link. A packet that carries the wrapped
// key of tls-crypt-v2 has that much less.
func payloadBudget(w ctrlwrap.Wrapper) int {
	return tlsMTU - linkOverhead - 1 - wire.SessionIDSize - ackBlockMax - 4 - w.Overhead()
}

// controlConn is the net.Conn that crypto/tls runs over: the bytes it writes
// go to the loop, which cuts them into control packets, and the bytes of the
// control packets that arrive in order come out of its Read.
type controlConn struct {
	s      *Session
	ks     *keyState
	notify chan struct{} // there is something to read, or the conn is closed
	gone   chan struct{} // closed with the conn

	mu     sync.Mutex
	buf    []byte
	closed bool
}

func newControlConn(s *Session, ks *keyState) *controlConn {
	return &controlConn{s: s, ks: ks, notify: make(chan struct{}, 1), gone: make(chan struct{})}
}

// outMsg is what crypto/tls wrote to the conn of a key state, on its way to the loop.
type outMsg struct {
	ks   *keyState
	data []byte
}

// push adds the bytes that came in order. The loop calls it.
func (c *controlConn) push(p []byte) {
	c.mu.Lock()
	c.buf = append(c.buf, p...)
	c.mu.Unlock()
	c.wake()
}

// queued is how many bytes wait to be read.
func (c *controlConn) queued() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.buf)
}

func (c *controlConn) wake() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// Read returns what has arrived, and waits when nothing has.
func (c *controlConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			c.buf = c.buf[n:]
			if len(c.buf) == 0 {
				c.buf = nil
			}
			c.mu.Unlock()
			return n, nil
		}
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		select {
		case <-c.notify:
		case <-c.s.done:
			return 0, net.ErrClosed
		}
	}
}

// Write gives p to the loop, which sends it as control packets as the send
// window allows. It returns when the loop has taken all of p, which it does not
// do while the bytes of an earlier Write are still waiting for room.
func (c *controlConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-c.ks.room: // the bytes of the Write before this one are all in packets
	case <-c.gone:
		return 0, net.ErrClosed
	case <-c.s.done:
		return 0, net.ErrClosed
	}
	select {
	case c.s.out <- outMsg{ks: c.ks, data: append([]byte(nil), p...)}:
		return len(p), nil
	case <-c.gone:
		return 0, net.ErrClosed
	case <-c.s.done:
		return 0, net.ErrClosed
	}
}

// Close ends the use of the conn by crypto/tls (it closes the conn when its
// context ends and after an alert). The link is the session's: it stays.
func (c *controlConn) Close() error {
	c.shut()
	return nil
}

// shut closes the conn: reads and writes that wait return net.ErrClosed.
func (c *controlConn) shut() {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.gone)
	}
	c.mu.Unlock()
	c.wake()
}

func (c *controlConn) LocalAddr() net.Addr  { return c.s.opts.Link.LocalAddr() }
func (c *controlConn) RemoteAddr() net.Addr { return c.s.opts.Link.RemoteAddr() }

// The control channel has no deadlines of its own: the timers of the session,
// the handshake timeout and the keepalive, end it. crypto/tls sets a write
// deadline for its close alert, and that is all that these are for.
func (c *controlConn) SetDeadline(time.Time) error      { return nil }
func (c *controlConn) SetReadDeadline(time.Time) error  { return nil }
func (c *controlConn) SetWriteDeadline(time.Time) error { return nil }

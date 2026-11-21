// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/reliable.c (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package reliable

import (
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

const (
	// fastRetransmitAcks is how many packets sent later must be acknowledged
	// for a packet that is not, before it is sent again without waiting.
	fastRetransmitAcks = 3
	// maxBackoffShift is how many times the wait doubles at most: the longest
	// wait is the first one shifted by it (2 s becomes 128 s).
	maxBackoffShift = 6
	// maxInitialTimeout keeps the longest wait far from overflowing.
	maxInitialTimeout = time.Hour
)

// Outgoing is a packet to send, or to send again.
type Outgoing struct {
	ID      uint32
	Opcode  wire.Opcode
	Payload []byte // the Sender's own slice: do not change it
}

type entry struct {
	id        uint32
	opcode    wire.Opcode
	payload   []byte
	due       time.Time // when to send it again; the zero time is: now
	timeout   time.Duration
	laterAcks int // packets sent after this one that the peer has acknowledged
}

// Sender numbers the control packets that this side sends and keeps the ones
// that are not acknowledged. It is not safe for concurrent use.
//
// OpenVPN: reliable.c reliable_send, reliable_send_purge.
type Sender struct {
	initial time.Duration
	next    uint32
	queue   []entry // in id order, at most SendWindow
}

// NewSender makes a Sender whose first wait before a retransmission is
// initialTimeout (OpenVPN's --tls-timeout, 2 seconds by default) and doubles
// each time up to 64 times as much. It panics when initialTimeout is not
// between 0 (excluded) and an hour: the caller validates its configuration.
func NewSender(initialTimeout time.Duration) *Sender {
	if initialTimeout <= 0 || initialTimeout > maxInitialTimeout {
		panic("reliable: the initial timeout is out of range")
	}
	return &Sender{initial: initialTimeout}
}

// CanSend reports whether a packet can be queued: fewer than SendWindow
// packets wait for their acknowledgement.
func (s *Sender) CanSend() bool {
	return len(s.queue) < SendWindow
}

// Len is the number of packets that wait for their acknowledgement.
func (s *Sender) Len() int {
	return len(s.queue)
}

// Queue gives the next id to a packet and keeps it until it is acknowledged.
// The packet is due at once: the next call of Due returns it. The Sender keeps
// payload, which the caller must not change. Queue fails when the send window
// is full.
func (s *Sender) Queue(op wire.Opcode, payload []byte) (uint32, error) {
	if !s.CanSend() {
		return 0, errors.New(tagSendWindowFull, "the send window is full", "window", SendWindow)
	}
	id := s.next
	s.next++
	s.queue = append(s.queue, entry{id: id, opcode: op, payload: payload, timeout: s.initial})
	return id, nil
}

// Due returns the packets to send now, lowest id first: those never sent, those
// whose wait is over, and those that three later packets overtook (the peer
// acknowledged three packets sent after them). It sets each one's next wait,
// which is twice the last one up to the longest.
func (s *Sender) Due(now time.Time) []Outgoing {
	var out []Outgoing
	longest := s.initial << maxBackoffShift
	for i := range s.queue {
		e := &s.queue[i]
		if e.laterAcks < fastRetransmitAcks && now.Before(e.due) {
			continue
		}
		out = append(out, Outgoing{ID: e.id, Opcode: e.opcode, Payload: e.payload})
		e.due = now.Add(e.timeout)
		if e.timeout < longest {
			e.timeout *= 2
		}
		e.laterAcks = 0
	}
	return out
}

// NextDeadline is when Due next has something to return. It reports false when
// no packet waits. A time that is not after the current one means: now.
func (s *Sender) NextDeadline() (time.Time, bool) {
	if len(s.queue) == 0 {
		return time.Time{}, false
	}
	var first time.Time
	for i, e := range s.queue {
		if e.laterAcks >= fastRetransmitAcks {
			return time.Time{}, true
		}
		if i == 0 || e.due.Before(first) {
			first = e.due
		}
	}
	return first, true
}

// Ack takes the acknowledgement of one packet id from the peer. It reports
// whether the id was a packet waiting for it; an id that is not (an
// acknowledgement repeated, or of a packet never sent) changes nothing.
//
// Deviation: OpenVPN counts every acknowledgement of a later id against the
// packets before it, so an id the peer repeats in each packet (it does, so that
// a lost acknowledgement is harmless) counts again each time. Here only the
// first acknowledgement of a packet counts, so "three later packets" means three.
// SPEC §20 V6.
func (s *Sender) Ack(id uint32) bool {
	idx := -1
	for i := range s.queue {
		if s.queue[i].id == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	s.queue = append(s.queue[:idx], s.queue[idx+1:]...)
	for i := range s.queue {
		if before(s.queue[i].id, id) {
			s.queue[i].laterAcks++
		}
	}
	return true
}

const tagSendWindowFull = "SendWindowFull"

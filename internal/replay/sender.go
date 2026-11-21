// SPDX-License-Identifier: GPL-2.0-only

package replay

import (
	"math"
	"time"

	"github.com/rm4n0s/errors"
)

// Sender makes the packet ids of the packets that this side sends, in the long
// form that tls-auth and tls-crypt use: a counter and the time at which the
// counting started. The first id is 1. A Sender is not safe for concurrent use.
//
// Draft: "OpenVPN mixed timestamp/packet counter format".
type Sender struct {
	id      uint32
	time    uint32
	started bool
}

// NewSender makes a sender whose first id is start+1. tls-crypt-v2 starts at
// 0x0f000000 to tell the server that the client can resend its wrapped key.
func NewSender(start uint32) *Sender {
	return &Sender{id: start}
}

// Next returns the id and the time for the next packet. The time is the clock
// when the first packet was made and stays the same after it. When the ids
// run out (a counter of 32 bits), counting starts again at 1 with the new time,
// which the receiver sees as a newer counter; it needs the clock to have moved
// on by a second, and Next fails when it has not.
func (s *Sender) Next(now time.Time) (id, sentTime uint32, err error) {
	sec := now.Unix()
	if sec < 0 || sec > math.MaxUint32 {
		return 0, 0, errors.New(tagClockOutOfRange, "the clock does not fit a 32-bit time", "unix", sec)
	}
	t := uint32(sec)
	if !s.started {
		s.started = true
		s.time = t
	}
	if s.id == math.MaxUint32 {
		if t <= s.time {
			return 0, 0, errors.New(tagPacketIDExhausted, "the packet ids ran out and the clock has not moved on", "time", s.time)
		}
		s.time = t
		s.id = 0
	}
	s.id++
	return s.id, s.time, nil
}

const (
	tagClockOutOfRange   = "ClockOutOfRange"
	tagPacketIDExhausted = "PacketIDExhausted"
)

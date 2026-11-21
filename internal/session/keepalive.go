// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ping.c, ping.h and forward.c (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package session

import (
	"time"

	"github.com/rm4n0s/errors"
)

// touchSent records that a packet went to the link: the idle time that decides the
// next ping counts from it. Any packet counts, the control channel's too.
//
// OpenVPN: forward.c process_outgoing_link (ping_send_interval is reset there).
func (s *Session) touchSent() {
	s.sentAt.Store(int64(time.Since(s.base)))
}

// sinceSent is how long ago a packet went to the link.
func (s *Session) sinceSent() time.Duration {
	return time.Since(s.base) - time.Duration(s.sentAt.Load())
}

// startKeepalive arms the two timers when the handshake is complete: a pushed ping
// and ping-restart win over the ones of the options. The loop goroutine calls it.
func (s *Session) startKeepalive() {
	p := s.pushed
	s.kaInterval, s.kaTimeout = s.opts.PingInterval, s.opts.PingTimeout
	if p.PingInterval > 0 {
		s.kaInterval = p.PingInterval
	}
	if p.PingRestart > 0 {
		s.kaTimeout = p.PingRestart
	}
	s.lastRecv = time.Now()
	s.touchSent()
	s.kaOn = s.kaInterval > 0 || s.kaTimeout > 0
}

// keepaliveWait is how long until the next thing the keepalive has to do: send a
// ping or give up. It reports false when the keepalive is off.
func (s *Session) keepaliveWait() (time.Duration, bool) {
	if !s.kaOn {
		return 0, false
	}
	wait := time.Duration(-1)
	if s.kaInterval > 0 {
		wait = s.kaInterval - s.sinceSent()
	}
	if s.kaTimeout > 0 {
		if left := s.kaTimeout - time.Since(s.lastRecv); wait < 0 || left < wait {
			wait = left
		}
	}
	return max(0, wait), true
}

// keepaliveTick does what is due: it ends the session when nothing authentic came
// for the timeout, and sends a ping when nothing went out for the interval. It
// reports false when the session has failed.
//
// OpenVPN: ping.h check_ping_restart, ping.c check_ping_send_dowork.
func (s *Session) keepaliveTick() bool {
	if s.kaTimeout > 0 && time.Since(s.lastRecv) >= s.kaTimeout {
		s.fail(errors.New(TagPingTimeout, "nothing came from the server in time", "timeout", s.kaTimeout.String()))
		return false
	}
	if s.kaInterval > 0 && s.sinceSent() >= s.kaInterval {
		d := s.data.Load()
		if err := s.lockWrite(d, false); err != nil {
			return false // the session has ended
		}
		err := s.writeLocked(d, pingString, false)
		d.unlockWrite()
		if err != nil {
			return false
		}
	}
	return true
}

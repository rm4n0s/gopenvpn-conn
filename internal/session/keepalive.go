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
	s.kaTimeoutNs.Store(int64(s.kaTimeout))
	s.kaOn = s.kaInterval > 0 || s.kaTimeout > 0
}

// keepaliveWait is how long until the next thing the keepalive has to do: send a
// ping or give up. It reports false when the keepalive is off. A ping that is
// overdue is due now: it must not wait for the timeout.
func (s *Session) keepaliveWait() (time.Duration, bool) {
	if !s.kaOn {
		return 0, false
	}
	var wait time.Duration
	have := false
	if s.kaInterval > 0 {
		wait, have = s.kaInterval-s.sinceSent(), true
	}
	if s.kaTimeout > 0 {
		if left := s.kaTimeout - time.Since(s.lastRecv); !have || left < wait {
			wait = left
		}
	}
	return max(0, wait), true
}

// kaGrace is how long past the timeout the loop still looks at the packets that wait
// before it gives the server up.
const kaGrace = time.Second

// keepaliveTick does what is due: it ends the session when nothing authentic came
// for the timeout, and sends a ping when nothing went out for the interval. It
// returns the error that ends the session, or nil.
//
// OpenVPN: ping.h check_ping_restart, ping.c check_ping_send_dowork.
func (s *Session) keepaliveTick() error {
	if s.kaTimeout > 0 && time.Since(s.lastRecv) >= s.kaTimeout {
		if len(s.in) > 0 && time.Since(s.lastRecv) < s.kaTimeout+kaGrace {
			// Packets wait to be looked at: they may be the server's, read while the
			// loop was busy. Not for long: packets that do not authenticate must not put
			// the timeout off.
			return nil
		}
		return errors.New(TagPingTimeout, "nothing came from the server in time", "timeout", s.kaTimeout.String())
	}
	if s.kaInterval > 0 && s.sinceSent() >= s.kaInterval {
		return s.sendPing()
	}
	return nil
}

// sendPing seals a ping and gives it to the writer of the link. When a Write of the
// connection has the data path, a packet of its own is going out, or waits for the
// link as the ping would: the ping is left for the next interval. It returns the
// error that ends the session (the end of the packet ids of the key), or nil.
func (s *Session) sendPing() error {
	d := s.data.Load()
	s.touchSent() // the try counts: the next one is an interval from now
	select {
	case d.sem <- struct{}{}:
	default:
		return nil
	}
	packet, k, err := s.sealLocked(d, pingString)
	if err != nil {
		d.unlockWrite()
		return err
	}
	out := append([]byte(nil), packet...)
	d.unlockWrite()
	s.queueForLink(out)
	if k.ch.NeedsRenegotiation() {
		s.requestRenegotiation(k.id)
	}
	return nil
}

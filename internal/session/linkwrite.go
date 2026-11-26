// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/forward.c (process_outgoing_link) and error.c (x_check_status) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package session

import (
	"io"
	"net"
	"os"
	"time"

	"github.com/rm4n0s/errors"
)

// ctlQueue is how many packets of the loop (control packets, keepalive pings) wait
// for the link. When the link does not take them the queue fills and the next ones
// are dropped: the reliability layer sends a control packet again, and a ping is
// only a ping.
const ctlQueue = 64

// writeFailLimit is how long the writes of a datagram link may fail, one after the
// other with none that works, before the session ends, when no keepalive timeout is
// there to decide it. It is OpenVPN's ping-restart of a client before the server has
// pushed one.
//
// OpenVPN: init.c PRE_PULL_INITIAL_PING_RESTART.
const writeFailLimit = 120 * time.Second

// What a failed write of the link means.
const (
	writeFatal    = iota // the session ends
	writeDeadline        // the write deadline of the connection passed and nothing went out
	writeDropped         // the packet is lost, as a network loses one; the session goes on
)

// writeLoop writes the packets of the loop to the link. The loop gives them to it
// and never waits for the link itself: a link that does not take bytes (a TCP
// connection whose path is dead, a peer that does not read) must not stop the
// timers, the keepalive that ends such a session among them, nor the reading.
//
// It returns the error of a write that ends the session, or nil when the session
// has ended; its goroutine stores the error and sends what is left (runWrite).
//
// OpenVPN: forward.c io_wait (its loop does not block on the link either).
func (s *Session) writeLoop() error {
	for {
		select {
		case <-s.done:
			return nil
		case p := <-s.ctl:
			if err := s.writeLink(p, false); err != nil {
				return err
			}
		}
	}
}

// drainCtl writes what the loop still gave for the link, after Close: the session
// ends in order, and what was to be sent (the acknowledgement that completes an
// exchange of resets, say) goes out. The loop has set a write deadline on the link
// by then, so a link that takes nothing ends this soon. After a failure nothing is
// written: the link is closed at once.
func (s *Session) drainCtl() {
	<-s.loopDone
	if !s.closing.Load() {
		return
	}
	timer := time.NewTimer(exitWait)
	defer timer.Stop()
	for {
		select {
		case p := <-s.ctl:
			select {
			case s.linkSem <- struct{}{}:
			case <-timer.C:
				return
			}
			_, err := s.opts.Link.Write(p)
			<-s.linkSem
			if err != nil {
				return
			}
		default:
			return
		}
	}
}

// queueForLink gives a packet of the loop to the writer of the link. The packet is
// the writer's from here. When the queue is full the packet is dropped.
func (s *Session) queueForLink(p []byte) {
	select {
	case s.ctl <- p:
	default:
		s.log.Debug("dropped a packet of the loop: the link does not take packets")
	}
}

// lockLink takes the link for one write: the writers take turns. It gives up when
// the session ends (the error that ended it) or, for a user's write, when the write
// deadline passes (errDeadline).
func (s *Session) lockLink(user bool) error {
	select {
	case s.linkSem <- struct{}{}:
		return nil
	default:
	}
	for {
		var t time.Time
		var changed <-chan struct{}
		if user {
			t, changed = s.wdl.get()
			if !t.IsZero() && !time.Now().Before(t) {
				return errDeadline
			}
		}
		timer, expired := timerFor(t)
		select {
		case s.linkSem <- struct{}{}:
			stopTimer(timer)
			return nil
		case <-s.done:
			stopTimer(timer)
			return s.result()
		case <-expired:
			return errDeadline
		case <-changed:
			stopTimer(timer)
		}
	}
}

// writeLink writes one packet (or frame) to the link. With user set it is a Write
// of the connection, and the write deadline applies, also one that is set while the
// write waits. It returns nil when the packet is out, and also when a datagram link
// refused it in a way that says nothing of the next packet (the packet is lost, as
// a network loses one); errDeadline when the deadline passed and nothing went out;
// else the error that ends the session: the one that has ended it already, or one
// that is made here and that the caller stores (a Write at once, the writer of the
// link when it has returned it through its hand-off).
//
// OpenVPN: forward.c process_outgoing_link, error.c x_check_status (a failed write
// of a datagram is logged, and the keepalive decides).
func (s *Session) writeLink(p []byte, user bool) error {
	if err := s.lockLink(user); err != nil {
		return err
	}
	defer func() { <-s.linkSem }()
	var n int
	var err error
	if user {
		n, err = s.writeUser(p)
	} else {
		n, err = s.opts.Link.Write(p)
	}
	if err == nil {
		s.touchSent()
		if s.wfailSince.Load() != 0 {
			s.wfailSince.Store(0)
		}
		return nil
	}
	switch s.classifyWrite(err, n, user) {
	case writeDeadline:
		return errDeadline // nothing of the packet is out: the session goes on
	case writeDropped:
		s.log.Debug("a write of the datagram link failed; the packet is lost", "err", err)
		return nil
	}
	return errors.NewErr(TagLinkFailed, err).SetMetadata("op", "write")
}

// writeUser is the write of a Write of the connection: the link has the write
// deadline of the connection while it lasts, and SetWriteDeadline reaches it there
// (setWriteDeadline), so that a write that the link does not take can be woken.
func (s *Session) writeUser(p []byte) (int, error) {
	s.wmu.Lock()
	s.userWriting = true
	t, _ := s.wdl.get()
	var err error
	if !t.IsZero() {
		s.linkDeadline = true
		err = s.opts.Link.SetWriteDeadline(t)
	}
	s.wmu.Unlock()
	n := 0
	if err == nil {
		n, err = s.opts.Link.Write(p)
	}
	s.wmu.Lock()
	s.userWriting = false
	if s.linkDeadline {
		s.linkDeadline = false
		// The deadline never reaches a write of the loop.
		if rerr := s.opts.Link.SetWriteDeadline(time.Time{}); rerr != nil && err == nil {
			err = rerr
		}
	}
	s.wmu.Unlock()
	return n, err
}

// setWriteDeadline makes t the write deadline of the connection, and of the link
// too while a Write of the connection has it.
func (s *Session) setWriteDeadline(t time.Time) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.wdl.set(t)
	if !s.userWriting {
		return
	}
	s.linkDeadline = true
	if err := s.opts.Link.SetWriteDeadline(t); err != nil {
		s.log.Debug("could not set the write deadline of the link", "err", err)
	}
}

// classifyWrite says what a failed write means. A stream cannot go on after a
// failure (a part of a frame may be out), except a user's deadline that passed
// before any byte went. A datagram link goes on after any failure that says nothing
// of the next packet: the ICMP error of an earlier packet (ECONNREFUSED), a route
// that is gone for a moment (ENETUNREACH), a full queue of the interface (ENOBUFS on
// macOS), a firewall (EPERM), a packet that is too large for the path (EMSGSIZE).
// It ends when the link is closed, before the server has ever answered (so that a
// dial fails at once and the next remote is tried, as OpenVPN restarts there), and
// when every write has failed for writeFailLimit with no keepalive timeout to end
// the session.
func (s *Session) classifyWrite(err error, n int, user bool) int {
	select {
	case <-s.done:
		return writeFatal // the session has ended: the caller gets what ended it
	default:
	}
	if user && errors.Is(err, os.ErrDeadlineExceeded) && (!s.opts.Stream || n == 0) {
		return writeDeadline
	}
	if s.opts.Stream || !s.sawServer.Load() {
		return writeFatal
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return writeFatal
	}
	now := int64(time.Since(s.base)) | 1 // never 0, which is "not failing"
	since := s.wfailSince.Load()
	if since == 0 {
		s.wfailSince.CompareAndSwap(0, now)
		return writeDropped
	}
	if s.kaTimeoutNs.Load() == 0 && time.Duration(now-since) > writeFailLimit {
		return writeFatal
	}
	return writeDropped
}

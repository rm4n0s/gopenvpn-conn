// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/sig.c (process_explicit_exit_notification_init), push.c (receive_exit_message) and occ.c (OCC_EXIT) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package session

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
)

// occExit is the data packet of the older exit notification: the 16 bytes of the
// OCC magic and the byte OCC_EXIT (6). A server that has no cc-exit sends it, and
// takes it, over UDP.
//
// OpenVPN: occ.c occ_magic, occ.h OCC_EXIT.
var occExit = []byte{
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
	6,
}

// goodbye tells the server that the client is leaving, as well as the link allows.
// Close calls it before it ends the session. With cc-exit it writes EXIT in the
// control channel and waits up to exitWait for the acknowledgement, while the loop
// goes on sending it again; without it, on a datagram link, one data packet says it
// (OpenVPN's default is one try); on a stream there is nothing to send. Failing to
// say goodbye is no failure of Close: it is logged.
//
// OpenVPN: sig.c process_explicit_exit_notification_init.
func (s *Session) goodbye() {
	switch {
	case s.ccExit:
		conn := s.tlsConn
		if _, err := conn.Write(ctrlmsg.AppendMessage(nil, ctrlmsg.Exit)); err != nil {
			s.log.Debug("could not send EXIT", "err", err)
			return
		}
		s.exitSent.Store(true)
		select { // the loop looks for the acknowledgement when it runs
		case s.wake <- struct{}{}:
		default:
		}
		timer := time.NewTimer(exitWait)
		defer timer.Stop()
		select {
		case <-s.drained:
		case <-timer.C:
			s.log.Debug("the server did not acknowledge EXIT in time")
		case <-s.done:
		}
	case !s.opts.Stream:
		d := s.data.Load()
		if d == nil {
			return // no data channel: a handshake that is only the exchange of resets
		}
		if err := s.lockWrite(d, false); err != nil {
			return
		}
		defer d.unlockWrite()
		if err := s.writeLocked(d, occExit, false); err != nil {
			s.log.Debug("could not send the exit packet", "err", err)
		}
	}
}

// serverExited ends the session cleanly because the server left: io.EOF once the
// handshake is complete (the value that a Read at the end of a stream returns, SPEC
// §5.3), a tagged error before, when there is no caller of Read yet to tell it to.
func (s *Session) serverExited() {
	select {
	case <-s.ready:
		s.fail(io.EOF)
	default:
		s.fail(errors.New(TagServerExit, "the server ended the session before the handshake was complete"))
	}
}

// isOCCExit reports whether a decrypted data packet is the exit message of the data
// channel.
func isOCCExit(plain []byte) bool { return bytes.Equal(plain, occExit) }

// hasFlag reports whether the pushed protocol-flags have flag.
func hasFlag(flags []string, flag string) bool { return slices.Contains(flags, flag) }

// isExit reports whether a control message is EXIT. OpenVPN matches the head of the
// message; so does this.
func isExit(text string) bool { return strings.HasPrefix(text, ctrlmsg.Exit) }

// TagServerExit is the tag of the error of a session that the server ended with EXIT
// before the handshake was complete.
const TagServerExit = "ServerExit"

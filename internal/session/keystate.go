// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl_common.h (struct key_state) and ssl.c (key_state_init, tls_session_get_tls_wrap) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package session

import (
	"crypto/tls"
	"sync/atomic"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/reliable"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// keyState is the control channel of one key id: its own reliability layer, its own
// TLS session over it, and the data keys that the TLS session gives. A session has
// the key state of key id 0 at first, and one more for each renegotiation, so that
// the old key goes on working while the new one is made. The session ids belong to
// the session, not to a key state.
//
// OpenVPN: ssl_common.h struct key_state.
type keyState struct {
	id      uint8
	wrap    ctrlwrap.Wrapper
	budget  int // bytes of TLS in a control packet
	resetOp wire.Opcode
	adapter *controlConn
	room    chan struct{} // holds a token while no Write of crypto/tls waits for the loop

	// closing is set before the key state is thrown away: its goroutines then stop
	// without it being a failure.
	closing atomic.Bool

	// Owned by the loop goroutine.
	sender    *reliable.Sender
	receiver  reliable.Receiver
	pending   []byte // what crypto/tls wrote, not yet in packets
	holding   bool   // a Write of crypto/tls has the token: the loop gives it back when pending is empty
	peerReset bool   // the peer's reset (hard for key 0, else soft) has come
	thirdSent bool   // an acknowledgement of the peer's reset went out
	wkcAsked  bool   // the server's reset asked for the wrapped key again (key 0)
	wkcSent   bool   // the first packet after the reset went out as CONTROL_WKC_V1
	wkcQueued bool   // ResetOnly: the empty CONTROL_WKC_V1 is queued

	// established is when the data keys were made, zero while the TLS session is
	// still being made; mustDie is when the key stops being valid, zero for never.
	established time.Time
	mustDie     time.Time
	tlsConn     *tls.Conn
	dk          *dataKey // the data keys, nil while there are none
}

// newKeyState makes the control state of a key id. The first packet that it sends
// is its reset: HARD_RESET_CLIENT for key id 0, SOFT_RESET for the others.
func (s *Session) newKeyState(id uint8, wrap ctrlwrap.Wrapper) *keyState {
	ks := &keyState{
		id:      id,
		wrap:    wrap,
		budget:  payloadBudget(wrap),
		resetOp: wire.SoftResetV1,
		sender:  reliable.NewSender(s.opts.RetransmitTimeout),
		room:    make(chan struct{}, 1),
	}
	if id == 0 {
		ks.resetOp = s.resetOp
	}
	ks.room <- struct{}{}
	ks.adapter = newControlConn(s, ks)
	return ks
}

// wrapperFor is the protection of the control packets of a key id: the static one
// of the configuration for key id 0, and for the others the dynamic tls-crypt key
// when the server negotiated it, else the same static one.
//
// OpenVPN: ssl_pkt.h tls_session_get_tls_wrap.
func (s *Session) wrapperFor(id uint8) ctrlwrap.Wrapper {
	if id > 0 {
		if dyn := s.dyn.Load(); dyn != nil {
			return *dyn
		}
	}
	return s.opts.Wrapper
}

// giveBack hands the token to the Write of crypto/tls that waits for it, when what
// it wrote is all in packets.
func (ks *keyState) giveBack() {
	if ks.holding && len(ks.pending) == 0 {
		ks.holding = false
		select {
		case ks.room <- struct{}{}:
		default:
		}
	}
}

// retire throws a key state away: its control channel stops, so the goroutine of its
// TLS session ends, and nothing more is sent or taken for it. The loop calls it.
func (s *Session) retire(ks *keyState) {
	ks.closing.Store(true)
	ks.adapter.shut()
	s.keys[ks.id] = nil
}

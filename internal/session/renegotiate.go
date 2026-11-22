// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl.c (key_state_soft_reset, tls_process, tls_select_encryption_key, should_trigger_renegotiation, lame_duck_must_die), tls_crypt.c (tls_session_generate_dynamic_tls_crypt_key) and push.c (auth token) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package session

import (
	"crypto/tls"
	"encoding/base64"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/datachan"
	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
)

// The renegotiation (SPEC §11.3) makes a new key while the old one goes on working.
// A session holds at most two keys that carry data: the newest (primary) and the one
// before it (lame). A new control channel, with its own key id, is made first: a soft
// reset in both directions, then TLS (the client is the TLS client in every one), and
// the key exchange again, with no PUSH_REQUEST. When it is done its data keys open
// packets at once and seal them after a delay, so that the server has surely got them.
// The old key stops being valid a transition window after the renegotiation began.
//
// The loop goroutine owns all of it: the TLS goroutines of the new keys tell it with
// events, and the data channel tells it with requestRenegotiation.

// keyEvent is what the TLS goroutine of a renegotiation tells the loop: the TLS
// session is made and the key exchange done (conn and state), or it failed (err).
type keyEvent struct {
	ks    *keyState
	conn  *tls.Conn
	state tls.ConnectionState
	err   error
}

// wakeLoop makes the loop look at what changed.
func (s *Session) wakeLoop() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// requestRenegotiation is how the data channel says that the key of an id is used up
// (the packet ids, the AEAD usage limit, the epochs). Any goroutine may call it.
func (s *Session) requestRenegotiation(id uint8) {
	if v := int32(id) + 1; s.needKey.Swap(v) != v {
		s.wakeLoop()
	}
}

// startRenegotiation is called when the handshake is complete: the key of the first
// control channel is the one in use, from now.
func (s *Session) startRenegotiation() {
	ks := s.ks0
	if d := s.data.Load(); d != nil {
		ks.dk = d.table.Load().byID[0]
	}
	s.keyMade(ks, time.Now())
}

// keyMade records that the data keys of a key state exist.
func (s *Session) keyMade(ks *keyState, now time.Time) {
	ks.established = now
	if after := s.opts.RenegotiateAfter; after > 0 {
		ks.mustDie = now.Add(after + s.transitionWindow())
	}
	s.dirty = true
}

func (s *Session) transitionWindow() time.Duration {
	if w := s.opts.TransitionWindow; w > 0 {
		return w
	}
	return DefaultTransitionWindow
}

// promoteDelay is how long a new key waits before it is sealed with.
//
// OpenVPN: ssl.c auth_deferred_expire_window.
func (s *Session) promoteDelay() time.Duration {
	switch d := s.opts.PromoteDelay; {
	case d < 0:
		return 0
	case d > 0:
		return d
	}
	if r := s.opts.RenegotiateAfter; r > 0 {
		return min(s.opts.HandshakeTimeout, r/2)
	}
	return s.opts.HandshakeTimeout
}

// dueAt is when the key in use is due to be replaced, if it is: when the data
// channel asked for it, now; else RenegotiateAfter after it was made.
//
// OpenVPN: ssl.c should_trigger_renegotiation.
func (s *Session) dueAt() (time.Time, bool) {
	p := s.primary
	if v := s.needKey.Load(); v > 0 && uint8((v-1)&0xff) == p.id {
		return time.Time{}, true
	}
	if after := s.opts.RenegotiateAfter; after > 0 {
		return p.established.Add(after), true
	}
	return time.Time{}, false
}

// renegTick does what is due: it gives up a renegotiation that takes too long, drops
// the keys that are past their end, starts a renegotiation when the key in use is due
// to be replaced, and chooses the key that data is sealed with. It reports false when
// the session has failed.
func (s *Session) renegTick() bool {
	now := time.Now()
	p := s.primary
	if p.established.IsZero() && !now.Before(s.attemptEnd) {
		// The server has thrown its side of the session away by now, or will, and takes
		// no other soft reset of it (ssl.c tls_multi_process: move_session to the lame
		// duck; tls_pre_decrypt: "stale session-id", "key IDs out of sync"): a retry in
		// this session cannot work, so the session ends and the caller dials again.
		s.fail(errors.New(TagRenegotiationFailed, "a renegotiation did not finish in time",
			"key_id", p.id, "timeout", s.opts.HandshakeTimeout.String()))
		return false
	}
	if l := s.lame; l != nil && !l.mustDie.IsZero() && !now.Before(l.mustDie) {
		if p.established.IsZero() {
			return s.expired(l)
		}
		s.dropKey(l)
		s.lame = nil
	}
	if !p.mustDie.IsZero() && !p.established.IsZero() && !now.Before(p.mustDie) {
		return s.expired(p)
	}
	if !p.established.IsZero() {
		if at, due := s.dueAt(); due && !now.Before(at) {
			id := s.nextID
			for s.keys[id] != nil {
				id = id%datachan.MaxKeyID + 1
			}
			if _, err := s.beginKey(id, now); err != nil {
				s.fail(err)
				return false
			}
		}
	}
	if s.dirty || (!s.sendAt.IsZero() && !now.Before(s.sendAt)) {
		s.updateTable(now)
	}
	return true
}

// expired ends the session: the key in use is past its end and there is no other.
func (s *Session) expired(ks *keyState) bool {
	s.fail(errors.New(TagRenegotiationFailed, "the key reached the end of its life and no new key was made",
		"key_id", ks.id))
	return false
}

// renegWait is the next time that renegTick has something to do.
func (s *Session) renegWait() (time.Time, bool) {
	var at time.Time
	found := false
	add := func(t time.Time) {
		if !found || t.Before(at) {
			at, found = t, true
		}
	}
	p := s.primary
	if p == nil {
		return at, false
	}
	if p.established.IsZero() {
		add(s.attemptEnd)
	} else {
		if due, ok := s.dueAt(); ok {
			add(due)
		}
		if !p.mustDie.IsZero() {
			add(p.mustDie)
		}
	}
	if l := s.lame; l != nil && !l.mustDie.IsZero() {
		add(l.mustDie)
	}
	if !s.sendAt.IsZero() {
		add(s.sendAt)
	}
	return at, found
}

// beginKey makes the control state of a new key id the newest key, and starts its TLS
// session. The key before the newest becomes the older of the two (the one before it
// is gone). The client starts it after RenegotiateAfter; the server's soft reset makes
// the client do it too (acceptSoftReset).
//
// OpenVPN: ssl.c key_state_soft_reset.
func (s *Session) beginKey(id uint8, now time.Time) (*keyState, error) {
	if s.lame != nil {
		s.dropKey(s.lame)
	}
	old := s.primary
	if end := now.Add(s.transitionWindow()); old.mustDie.IsZero() || old.mustDie.After(end) {
		old.mustDie = end
	}
	ks := s.newKeyState(id, s.wrapperFor(id))
	if _, err := ks.sender.Queue(ks.resetOp, nil); err != nil {
		return nil, err
	}
	s.lame, s.primary = old, ks
	s.keys[id] = ks
	s.nextID = id%datachan.MaxKeyID + 1
	s.attemptEnd = now.Add(s.opts.HandshakeTimeout)
	s.needKey.Store(0)
	s.dirty = true
	s.log.Debug("a renegotiation began", "key_id", id)
	s.wg.Add(1)
	go s.tlsMain(ks)
	return ks, nil
}

// acceptSoftReset starts a renegotiation that the server began: a soft reset of a key
// id that is free, while the newest key is complete (OpenVPN takes it in no other
// state). It returns nil when the soft reset is not accepted.
func (s *Session) acceptSoftReset(id uint8) *keyState {
	if s.primary.established.IsZero() || s.keys[id] != nil || id == 0 {
		return nil
	}
	ks, err := s.beginKey(id, time.Now())
	if err != nil {
		s.fail(err)
		return nil
	}
	return ks
}

// dropKey throws away a key that is past its end: the data key and the control state.
func (s *Session) dropKey(ks *keyState) {
	s.retire(ks)
	ks.dk = nil
	if v := int32(ks.id) + 1; s.needKey.Load() == v {
		s.needKey.CompareAndSwap(v, 0)
	}
	s.dirty = true
}

// onKeyEvent takes what the TLS goroutine of a renegotiation says.
func (s *Session) onKeyEvent(ev keyEvent) {
	ks := ev.ks
	if s.keys[ks.id] != ks || ks != s.primary || !ks.established.IsZero() {
		return // a key state that is gone
	}
	now := time.Now()
	if ev.err != nil {
		// The session ends with what made the renegotiation fail: see renegTick for
		// why it is not tried again.
		s.log.Warn("a renegotiation failed", "key_id", ks.id, "err", ev.err)
		s.fail(ev.err)
		return
	}
	d := s.data.Load()
	dk, err := s.makeKey(d, ks.id, &ev.state)
	if err != nil {
		s.log.Warn("a renegotiation failed", "key_id", ks.id, "err", err)
		s.fail(err)
		return
	}
	ks.dk, ks.tlsConn = dk, ev.conn
	s.ctlTLS.Store(ev.conn)
	s.keyMade(ks, now)
	s.log.Debug("a renegotiation is done", "key_id", ks.id)
}

// updateTable publishes the keys that are valid, and chooses the one to seal with:
// the newest when its delay has passed, else the one before it, else the newest.
//
// OpenVPN: ssl.c tls_select_encryption_key.
func (s *Session) updateTable(now time.Time) {
	d := s.data.Load()
	if d == nil {
		return
	}
	var t keyTable
	p, l := s.primary, s.lame
	if l != nil && l.dk != nil {
		t.byID[l.id] = l.dk
	}
	if p.dk != nil {
		t.byID[p.id] = p.dk
	}
	s.sendAt = time.Time{}
	switch {
	case p.dk != nil:
		t.send = p.dk
		if at := p.established.Add(s.promoteDelay()); l != nil && l.dk != nil && now.Before(at) {
			t.send, s.sendAt = l.dk, at
		}
	case l != nil:
		t.send = l.dk
	}
	d.table.Store(&t)
	s.dirty = false
}

// renegotiationCredentials are the user name and password of a key exchange after
// the first. When the server pushed an auth token the token is the password (and its
// user name, when it has one, is the user name): the credentials are not asked for
// again, and may be one-time. Without a token the first ones are sent again, as
// OpenVPN does; with AuthNoCache the password was not kept, and again is true: the
// caller is asked for the credentials again.
//
// OpenVPN: push.c, auth-token handling in ssl.c key_method_2_write.
func (s *Session) renegotiationCredentials() (user, pass string, again bool) {
	s.mu.Lock()
	token, tokenUser := s.token, s.tokenUser
	s.mu.Unlock()
	if token == "" {
		return s.user, s.pass, s.opts.AuthNoCache
	}
	user = s.user
	if tokenUser != "" {
		if b, err := base64.StdEncoding.DecodeString(tokenUser); err == nil {
			user = string(b)
		}
	}
	return user, token, false
}

// keepToken remembers the auth token that the server pushed, and its user name.
func (s *Session) keepToken(token, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	if user != "" {
		s.tokenUser = user
	}
}

// pushUpdate takes a PUSH_REPLY that comes after the handshake. A server with
// auth-gen-token sends a new token this way at each renegotiation, and the next
// renegotiation has to use it. Nothing else in it is applied: the options of the
// tunnel do not change in a session.
//
// OpenVPN: auth_token.c resend_auth_token_renegotiation, push.c send_push_reply_auth_token.
func (s *Session) pushUpdate(text string) {
	reply, err := ctrlmsg.ParsePushReply(text)
	if err != nil {
		s.log.Debug("a later push reply does not parse", "err", err)
		return
	}
	if s.opts.PullFilter != nil {
		if err := reply.Filter(s.opts.PullFilter); err != nil {
			s.log.Debug("a later push reply is filtered out", "err", err)
			return
		}
	}
	var update ctrlmsg.Pushed
	if err := update.Add(reply, s.opts.Ciphers); err != nil {
		s.log.Debug("a later push reply is not taken", "err", err)
		return
	}
	if update.AuthToken != "" {
		s.keepToken(update.AuthToken, update.AuthTokenUser)
		s.log.Debug("the server sent a new auth token")
	}
}

// setupDynamic makes the protection of the renegotiations from the TLS session of
// the first key, when the server asked for dynamic tls-crypt.
//
// OpenVPN: tls_crypt.c tls_session_generate_dynamic_tls_crypt_key.
func (s *Session) setupDynamic(x exporter) error {
	material, err := x.ExportKeyingMaterial(ctrlwrap.DynamicLabel, nil, keys.StaticKeySize)
	if err != nil {
		return errors.NewErr(TagKeyExportFailed, err)
	}
	defer clear(material)
	var original *keys.StaticKey
	if w, ok := s.opts.Wrapper.(ctrlwrap.StaticKeyed); ok {
		original = w.StaticKey()
	}
	w, err := ctrlwrap.NewDynamic(material, original, false, time.Now)
	if err != nil {
		return err
	}
	s.dyn = w
	return nil
}

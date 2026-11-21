// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/push.c (receive_auth_failed, server_pushed_signal, receive_auth_pending, parse_auth_pending_keywords) and options_util.c (parse_auth_failed_temp) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package ctrlmsg

import (
	"strconv"
	"strings"
	"time"
)

// maxReason is the longest reason that is kept from a message of the server:
// what ends up in an error and in a log line.
const maxReason = 1024

// AuthFailed is the server's refusal of the client's credentials.
//
// The forms are "AUTH_FAILED", "AUTH_FAILED,reason", "AUTH_FAILED,SESSION:reason",
// "AUTH_FAILED,TEMP:reason" and "AUTH_FAILED,TEMP[backoff 42,advance no]:reason".
//
// Draft: "AUTH_FAILED". OpenVPN: push.c receive_auth_failed.
type AuthFailed struct {
	// Reason is the text of the server, or empty.
	Reason string
	// Session is true for "SESSION:" (the session or its token has expired: a
	// new login may work).
	Session bool
	// Temporary is true for "TEMP": the refusal is for now, and the client may
	// try again after Backoff.
	Temporary bool
	// Backoff is how long the server asks the client to wait, or zero.
	Backoff time.Duration
	// Advance is what the server says about the next server: "no", "remote" or
	// "addr", or empty when it said nothing.
	Advance string
}

// IsAuthFailed reports whether a message is an AUTH_FAILED.
func IsAuthFailed(text string) bool {
	return text == "AUTH_FAILED" || strings.HasPrefix(text, "AUTH_FAILED,")
}

// ParseAuthFailed reads an AUTH_FAILED message. It does not fail: a message that
// does not follow a form is read as far as it goes, as OpenVPN reads it, and the
// rest is the reason. A flag that is not known is ignored, and a backoff that is
// not a number is none.
func ParseAuthFailed(text string) *AuthFailed {
	f := &AuthFailed{}
	rest, ok := strings.CutPrefix(text, "AUTH_FAILED,")
	if !ok {
		return f
	}
	switch {
	case strings.HasPrefix(rest, "TEMP"):
		f.Temporary = true
		rest = strings.TrimPrefix(rest, "TEMP")
		if flags, after, ok := cutFlags(rest); ok {
			for _, flag := range strings.Split(flags, ",") {
				flag = strings.TrimSpace(flag)
				if v, ok := strings.CutPrefix(flag, "backoff "); ok {
					if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 && n <= 1<<24 {
						f.Backoff = time.Duration(n) * time.Second
					}
				} else if v, ok := strings.CutPrefix(flag, "advance "); ok {
					switch v = strings.TrimSpace(v); v {
					case "no", "remote", "addr":
						f.Advance = v
					}
				}
			}
			rest = after
		}
		rest = strings.TrimPrefix(rest, ":")
	case strings.HasPrefix(rest, "SESSION:"):
		f.Session = true
		rest = strings.TrimPrefix(rest, "SESSION:")
	}
	f.Reason = limit(rest)
	return f
}

// cutFlags splits "[flags]after" at the closing bracket. It reports false when s
// does not start with "[" or has no "]".
func cutFlags(s string) (flags, after string, ok bool) {
	if !strings.HasPrefix(s, "[") {
		return "", s, false
	}
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return "", s, false
	}
	return s[1:end], s[end+1:], true
}

// limit cuts a text from the server to maxReason bytes.
func limit(s string) string {
	if len(s) > maxReason {
		return s[:maxReason]
	}
	return s
}

// Signal is a HALT or RESTART message: the server tells the client to stop, or to
// connect again.
//
// Draft: "RESTART and HALT". OpenVPN: push.c server_pushed_signal.
type Signal struct {
	// Restart is true for RESTART and false for HALT.
	Restart bool
	// Reason is the text of the server, or empty.
	Reason string
	// Flags are the letters between square brackets that may start a RESTART's
	// text: P (keep the credentials) and N (go on to the next server).
	Flags string
}

// ParseSignal reads a message that is HALT or RESTART, with or without a comma and
// a text. It reports false for any other message.
func ParseSignal(text string) (*Signal, bool) {
	var s Signal
	var rest string
	switch {
	case text == "HALT" || strings.HasPrefix(text, "HALT,"):
		rest = strings.TrimPrefix(strings.TrimPrefix(text, "HALT"), ",")
	case text == "RESTART" || strings.HasPrefix(text, "RESTART,"):
		s.Restart = true
		rest = strings.TrimPrefix(strings.TrimPrefix(text, "RESTART"), ",")
	default:
		return nil, false
	}
	if flags, after, ok := cutFlags(rest); ok {
		s.Flags = flags
		rest = after
	}
	s.Reason = limit(rest)
	return &s, true
}

// IsAuthPending reports whether a message is AUTH_PENDING.
func IsAuthPending(text string) bool {
	return text == "AUTH_PENDING" || strings.HasPrefix(text, "AUTH_PENDING,")
}

// ParseAuthPending reads an AUTH_PENDING message and returns the time the server
// asks the client to wait, or zero when it asks for none ("AUTH_PENDING" alone,
// or without a "timeout" keyword). Other keywords are ignored, as OpenVPN ignores
// them.
//
// Draft: "AUTH_PENDING". OpenVPN: push.c parse_auth_pending_keywords.
func ParseAuthPending(text string) time.Duration {
	rest, ok := strings.CutPrefix(text, "AUTH_PENDING,")
	if !ok {
		return 0
	}
	var timeout time.Duration
	for _, kw := range strings.Split(rest, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(kw), "timeout "); ok {
			if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32); err == nil {
				timeout = time.Duration(n) * time.Second
			}
		}
	}
	return timeout
}

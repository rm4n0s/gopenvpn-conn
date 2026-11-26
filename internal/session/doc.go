// SPDX-License-Identifier: GPL-2.0-only

// Package session is the state machine of one connection to a server: it owns
// the link, reads and writes control packets through the control channel
// protection and the reliability layer, and runs the handshake.
//
// A Session has its goroutines, started by the first Handshake: one reads the
// link, one writes it, the loop owns every piece of state, and the TLS session
// of each key has one (the loop starts those of the renegotiations). They stop
// when the session fails or is closed, and none runs after Close returns. The
// error that ends a session is made once, where it is found, and kept: every
// later call returns that same error. The work of each goroutine is handed off
// with errors.Async, so the route of that error begins at the Handshake that
// started the session; the work returns the error, and its goroutine stores it
// after the hand-off (SPEC §14.2).
package session

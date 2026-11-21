// SPDX-License-Identifier: GPL-2.0-only

// Package session is the state machine of one connection to a server: it owns
// the link, reads and writes control packets through the control channel
// protection and the reliability layer, and runs the handshake.
//
// A Session has two goroutines, both started by the first Handshake: one reads
// the link, the other (the loop) owns every piece of state and is the only one
// that writes the link. They stop when the session fails or is closed, and none
// runs after Close returns. The error that ends a session is made once, where
// it is found, and kept: every later call returns that same error.
package session

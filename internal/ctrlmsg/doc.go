// SPDX-License-Identifier: GPL-2.0-only

// Package ctrlmsg has the messages that travel inside the TLS session of the
// control channel: the key exchange message (OpenVPN's "key method 2"), the
// options string and the peer info that go in it, and, in later steps, the
// text messages (PUSH_REPLY, AUTH_FAILED, HALT, RESTART).
//
// The functions are pure: bytes to structs and back, with explicit bounds on
// every length. Nothing here reads a clock, a random source or a connection,
// except NewClientKeyExchange, which reads crypto/rand.
package ctrlmsg

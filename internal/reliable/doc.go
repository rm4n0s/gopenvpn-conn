// SPDX-License-Identifier: GPL-2.0-only

// Package reliable is the reliability layer of the control channel: it makes a
// link that loses, repeats and reorders packets deliver the control payloads
// exactly once and in order.
//
// A Sender numbers the packets this side sends, keeps those the peer has not
// acknowledged and says when to send them again. A Receiver puts the packets
// of the peer in order and keeps the acknowledgements to send back. Neither
// does I/O, starts a goroutine or reads a clock: the session that owns them
// calls them with the time, and sends what they return. One Sender and one
// Receiver belong to one TLS session (one key id): a renegotiation makes new
// ones, which count from 0 again.
//
// The packet ids are 32-bit and are compared with serial number arithmetic, so
// that nothing breaks when they wrap.
package reliable

// Numbers the peer depends on: they are OpenVPN's.
const (
	// SendWindow is the most packets that are sent and not yet acknowledged.
	SendWindow = 6
	// ReceiveWindow is how far ahead of the next expected id a packet may be
	// and still be kept; a packet further ahead is dropped.
	ReceiveWindow = 12
	// MaxAcks is the most acknowledgements in one packet.
	MaxAcks = 8
)

// before reports whether id a comes before id b in serial number order: b is
// ahead of a by less than half of the id space.
func before(a, b uint32) bool {
	return a-b >= 1<<31
}

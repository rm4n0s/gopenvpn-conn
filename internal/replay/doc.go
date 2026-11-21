// SPDX-License-Identifier: GPL-2.0-only

// Package replay protects against replayed packets: a Window decides whether a
// received packet counter is new, and a Sender makes the packet ids of the
// packets this side sends.
//
// The counters are the ones of OpenVPN: 64-bit values that grow. For tls-auth
// and tls-crypt the value is (time << 32) | id, the "long form" of the draft's
// section "OpenVPN mixed timestamp/packet counter format"; for the data
// channel it is the packet id of the AEAD format.
package replay

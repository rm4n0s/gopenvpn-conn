// SPDX-License-Identifier: GPL-2.0-only

// Package wire has the formats of OpenVPN packets as pure functions from bytes
// to structs and back: the first byte (opcode and key id), session ids, the
// control packet with its acknowledgement array, and the 16-bit length that
// frames packets on a TCP stream. It does no authentication, no encryption and
// no I/O beyond reading a frame from an io.Reader.
//
// Every parser checks each length before it reads, never panics, and returns a
// tagged error for input that is malformed. Slices in a parsed value point into
// the input: copy them to keep them after the buffer is reused.
//
// The formats are those of the draft "OpenVPN Wire Protocol" (sections "OpenVPN
// wire packet format", "General Control channel format", "Control channel wire
// packet structure" and "Acknowledgements"), checked against OpenVPN 2.7.9.
package wire

// SPDX-License-Identifier: GPL-2.0-only

// Package datachan seals and opens the packets of the data channel: the
// 32-bit packet id AEAD format of OpenVPN's DATA_V1 and DATA_V2 packets, with
// AES-GCM and ChaCha20-Poly1305, and the replay protection of the receiver.
//
// It has no sockets and no clock of its own: the caller gives the packets and
// the time. A Sender and a Receiver each belong to one key and are not safe for
// concurrent use; the session keeps one of each for each key slot.
package datachan

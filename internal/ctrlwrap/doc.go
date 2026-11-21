// SPDX-License-Identifier: GPL-2.0-only

// Package ctrlwrap protects the packets of the control channel: it adds the
// authentication (tls-auth) or the encryption and authentication (tls-crypt,
// tls-crypt-v2) that a pre-shared key gives, and takes it off again, with the
// replay protection that goes with it.
//
// A Wrapper works on the part of a packet after its first byte and its session
// id, which stay in the clear: Wrap takes the three and makes the packet that
// goes on the link, Unwrap takes a packet that came from it and gives back the
// body, the part that wire.ParseControlBody reads.
//
// A packet is authenticated before anything in it is used, and its replay
// counter is recorded only after it was authenticated, so a forged packet
// changes nothing. A packet that fails is an error for the caller to drop
// silently: anyone on the network could have sent it.
package ctrlwrap

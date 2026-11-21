// SPDX-License-Identifier: GPL-2.0-only

// Package openvpn is an OpenVPN client library with the patterns of the Go
// standard library.
//
// A program gives a Config (or an .ovpn profile, parsed by package ovpn) and
// gets a *Conn: a net.Conn whose Read returns one IP packet from the VPN and
// whose Write sends one. It needs no root and changes nothing on the machine.
// Package vpnnet builds on a *Conn to give DialContext, Listen and
// ListenPacket over the tunnel, with a TCP/IP stack inside the program.
//
// The library speaks the modern OpenVPN protocol (servers from OpenVPN 2.6 on)
// over UDP and TCP, with TLS from crypto/tls, the control channel protections
// tls-auth, tls-crypt and tls-crypt-v2, and AEAD data channel ciphers.
//
// This is not OpenVPN's own program and is not affiliated with OpenVPN Inc.
// The library is licensed GPL-2.0-only; see the files LICENSE and NOTICE.
package openvpn

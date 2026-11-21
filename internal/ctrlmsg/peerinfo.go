// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl.c (push_peer_info) and ssl.h (IV_PROTO_*) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package ctrlmsg

import (
	"slices"
	"strconv"
	"strings"
)

// The bits of IV_PROTO: what a client says it can do. A bit is set only by the
// step that implements the feature (SPEC §8.2).
//
// OpenVPN: ssl.h IV_PROTO_*.
const (
	// IVProtoDataV2 is the data packet with a peer id: P_DATA_V2.
	IVProtoDataV2 = 1 << 1
	// IVProtoRequestPush is "push before the request": the server may send
	// PUSH_REPLY without waiting for PUSH_REQUEST.
	IVProtoRequestPush = 1 << 2
	// IVProtoTLSKeyExport is the data keys from the TLS exporter.
	IVProtoTLSKeyExport = 1 << 3
	// IVProtoAuthPendingKW is the keywords of AUTH_PENDING.
	IVProtoAuthPendingKW = 1 << 4
	// IVProtoCCExitNotify is the exit message in the control channel.
	IVProtoCCExitNotify = 1 << 7
	// IVProtoAuthFailTemp is AUTH_FAILED,TEMP.
	IVProtoAuthFailTemp = 1 << 8
	// IVProtoDynTLSCrypt is dynamic tls-crypt at a renegotiation.
	IVProtoDynTLSCrypt = 1 << 9
	// IVProtoDataEpoch is the epoch data format.
	IVProtoDataEpoch = 1 << 10
	// IVProtoDNSOptionV2 is the dns option.
	IVProtoDNSOptionV2 = 1 << 11
)

// PeerInfo is what a client tells the server about itself, as the lines
// "NAME=value" of the key exchange message.
type PeerInfo struct {
	// Version is IV_VER. The server does not read it (it only gives it to its
	// scripts), so it says what this client is.
	Version string
	// Platform is IV_PLAT: "linux", "win" or "mac".
	Platform string
	// MTU is IV_MTU, the largest tun MTU that the client can use; the server
	// does not push a larger one.
	MTU int
	// Ciphers is IV_CIPHERS, the data ciphers the client offers, best first.
	Ciphers []string
	// Proto is IV_PROTO, the sum of the IVProto bits.
	Proto int
	// UV is the variables the caller set, which all start with "UV_".
	UV map[string]string
}

// String is the text of the peer info: one line for each variable, in the order
// of OpenVPN's client, with the UV_ variables sorted by name at the end.
//
// IV_NCP=2 is sent when AES-128-GCM and AES-256-GCM are both offered (the
// servers that know IV_CIPHERS ignore it, and older ones need it), and
// IV_TCPNL=1 says that the client does not need packets in order over TCP.
func (p *PeerInfo) String() string {
	var b strings.Builder
	line := func(name, value string) {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(value)
		b.WriteByte('\n')
	}
	line("IV_VER", p.Version)
	line("IV_PLAT", p.Platform)
	line("IV_TCPNL", "1")
	line("IV_MTU", strconv.Itoa(p.MTU))
	if slices.Contains(p.Ciphers, "AES-128-GCM") && slices.Contains(p.Ciphers, "AES-256-GCM") {
		line("IV_NCP", "2")
	}
	line("IV_CIPHERS", strings.Join(p.Ciphers, ":"))
	line("IV_PROTO", strconv.Itoa(p.Proto))
	names := make([]string, 0, len(p.UV))
	for name := range p.UV {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		line(name, p.UV[name])
	}
	return b.String()
}

// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/options.c (options_string) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package ctrlmsg

import "strconv"

// OptionsParams are the values of the options string of a client.
type OptionsParams struct {
	// Stream is true for TCP.
	Stream bool
	// IPv6 is true when the link is IPv6.
	IPv6 bool
	// TunMTU is the MTU of the tunnel.
	TunMTU int
	// Cipher is the data cipher the client expects to use (its first choice),
	// and KeySizeBits is its key size.
	Cipher      string
	KeySizeBits int
}

// linkOverhead is what OpenVPN adds to the tun MTU to say its link MTU in the
// options string (the data channel's header, packet id and tag, and for TCP the
// frame length): the figures that its servers print for their own side.
const (
	linkOverheadUDP = 41
	linkOverheadTCP = 43
)

// OptionsString is the options string of the key exchange message, in the form
// of OpenVPN's client. The server only compares it with its own idea of what
// the client sends and warns (SPEC §20 V1), so the values are honest rather
// than exact: they describe this client.
func OptionsString(o OptionsParams) string {
	proto, overhead := "UDPv4", linkOverheadUDP
	switch {
	case o.Stream && o.IPv6:
		proto, overhead = "TCPv6_CLIENT", linkOverheadTCP
	case o.Stream:
		proto, overhead = "TCPv4_CLIENT", linkOverheadTCP
	case o.IPv6:
		proto = "UDPv6"
	}
	return "V4,dev-type tun" +
		",link-mtu " + strconv.Itoa(o.TunMTU+overhead) +
		",tun-mtu " + strconv.Itoa(o.TunMTU) +
		",proto " + proto +
		",cipher " + o.Cipher +
		",auth [null-digest]" +
		",keysize " + strconv.Itoa(o.KeySizeBits) +
		",key-method 2,tls-client"
}

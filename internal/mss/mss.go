// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/mss.c (mss_fixup_ipv4, mss_fixup_ipv6, mss_fixup_dowork, frame_calculate_mssfix) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

// Package mss lowers the TCP maximum segment size that the SYN packets of a
// tunnel announce, so that a TCP segment and the OpenVPN packet around it fit in
// one packet of the network under the tunnel (SPEC §10).
package mss

import (
	"encoding/binary"
	"iter"
	"math"
)

// Sizes of the headers that the clamp reads.
const (
	ipv4MinHeader = 20
	ipv6Header    = 40
	tcpMinHeader  = 20
	protoTCP      = 6
	tcpFlagSYN    = 0x02
	optEOL        = 0
	optNOP        = 1
	optMSS        = 2
	optMSSLen     = 4
)

// Settings is how the largest MSS is made, as OpenVPN's mssfix option says.
type Settings struct {
	// Size is the mssfix number: 0 turns the clamp off.
	Size int
	// Encap is the bytes of the IP and UDP or TCP headers of the link, which
	// Size counts too ("mssfix N mtu" and the default); 0 when Size does not
	// count them ("mssfix N").
	Encap int
	// Fixed means that Size is the largest IP packet in the tunnel ("mssfix N
	// fixed"): the MSS is Size less the IPv4 and TCP headers, whatever the
	// overhead.
	Fixed bool
}

// Max is the largest MSS of a TCP segment over IPv4 in the tunnel, when each IP
// packet travels with overhead bytes of OpenVPN header (the length of a stream
// frame, the opcode, the peer id, the packet id and the tag): what is left of
// Size once the headers are out. 0 means no clamp. The ciphers are all AEAD, so
// there is no block to round down to.
//
// OpenVPN: mss.c frame_calculate_mssfix, mtu.c frame_calculate_protocol_header_size.
func (s Settings) Max(overhead int) int {
	if s.Size <= 0 {
		return 0
	}
	const ipTCP = ipv4MinHeader + tcpMinHeader
	if s.Fixed {
		return max(s.Size-ipTCP, 0)
	}
	return max(s.Size-s.Encap-overhead-ipTCP, 0)
}

// Clamp lowers the MSS option of a TCP SYN (or SYN-ACK) in the IP packet p to
// maxMSS, or to maxMSS-20 over IPv6, whose header is 20 bytes longer, and mends the
// TCP checksum. It changes p in place and reports whether it changed it. A packet
// that is not a whole TCP SYN with an MSS option larger than the limit is left as
// it is, and so is a fragment that is not the first; maxMSS 0 changes nothing.
//
// OpenVPN: mss.c mss_fixup_ipv4, mss_fixup_ipv6, mss_fixup_dowork.
func Clamp(p []byte, maxMSS int) bool {
	tcp, limit := synSegment(p, maxMSS)
	changed := false
	for at := range mssOptions(tcp) {
		old := binary.BigEndian.Uint16(tcp[at:])
		if old <= limit {
			continue
		}
		binary.BigEndian.PutUint16(tcp[at:], limit)
		sum := binary.BigEndian.Uint16(tcp[16:])
		binary.BigEndian.PutUint16(tcp[16:], adjustChecksum(sum, old, limit))
		changed = true
	}
	return changed
}

// Needs reports whether Clamp would change p, without changing it.
func Needs(p []byte, maxMSS int) bool {
	tcp, limit := synSegment(p, maxMSS)
	for at := range mssOptions(tcp) {
		if binary.BigEndian.Uint16(tcp[at:]) > limit {
			return true
		}
	}
	return false
}

// synSegment is the TCP segment of p when p is a whole IPv4 or IPv6 packet that
// carries the start of a TCP SYN, and the MSS limit for its version; nil
// otherwise, and nil when the limit leaves nothing to lower (no MSS is above
// 65535). IPv6 extension headers are not followed: a packet whose first next
// header is not TCP is left alone, as OpenVPN leaves it.
func synSegment(p []byte, maxMSS int) (tcp []byte, limit uint16) {
	if maxMSS <= 0 || len(p) == 0 {
		return nil, 0
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < ipv4MinHeader {
			return nil, 0
		}
		hlen := int(p[0]&0x0f) * 4
		// Deviation (SPEC §20 V14): OpenVPN does not check that the header
		// length is at least 20; a shorter one is not an IPv4 packet, and is
		// left alone here.
		if hlen < ipv4MinHeader || int(binary.BigEndian.Uint16(p[2:])) != len(p) ||
			binary.BigEndian.Uint16(p[6:])&0x1fff != 0 || p[9] != protoTCP || len(p)-hlen < tcpMinHeader {
			return nil, 0
		}
		tcp = p[hlen:]
	case 6:
		if len(p) < ipv6Header+tcpMinHeader || int(binary.BigEndian.Uint16(p[4:]))+ipv6Header != len(p) || p[6] != protoTCP {
			return nil, 0
		}
		tcp = p[ipv6Header:]
		maxMSS -= 20
	default:
		return nil, 0
	}
	if tcp[13]&tcpFlagSYN == 0 || maxMSS <= 0 || maxMSS >= math.MaxUint16 {
		return nil, 0
	}
	return tcp, uint16(maxMSS)
}

// mssOptions yields the offset in the segment of the value of each well-formed
// MSS option; none for a nil segment. The walk stops at the end of the options, at
// EOL, and at an option whose length does not fit; an MSS option whose length is
// not 4 is skipped.
func mssOptions(tcp []byte) iter.Seq[int] {
	return func(yield func(int) bool) {
		if tcp == nil {
			return
		}
		hlen := int(tcp[12]>>4) * 4
		if hlen <= tcpMinHeader || hlen > len(tcp) {
			return
		}
		opts := tcp[tcpMinHeader:hlen]
		for i := 0; len(opts)-i > 1; {
			switch opts[i] {
			case optEOL:
				return
			case optNOP:
				i++
				continue
			}
			n := int(opts[i+1])
			if n == 0 || n > len(opts)-i {
				return
			}
			if opts[i] == optMSS && n == optMSSLen && !yield(tcpMinHeader+i+2) {
				return
			}
			i += n
		}
	}
}

// adjustChecksum is the Internet checksum sum after a 16-bit word of what it
// covers changed from old to new.
//
// RFC 1624 §3, equation 3: HC' = ~(~HC + ~m + m').
func adjustChecksum(sum, old, new uint16) uint16 {
	s := uint32(^sum) + uint32(^old) + uint32(new)
	s = (s & 0xffff) + s>>16
	s = (s & 0xffff) + s>>16
	return ^uint16(s & 0xffff)
}

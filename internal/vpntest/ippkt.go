// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"encoding/binary"
	"net/netip"
)

// ICMP types of the echo request and reply.
const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// Checksum is the Internet checksum (RFC 1071) of b: the complement of the sum of
// its 16-bit words in one's complement arithmetic, with an odd last byte padded by
// a zero.
func Checksum(b []byte) uint16 {
	var sum uint32
	for ; len(b) >= 2; b = b[2:] {
		sum += uint32(binary.BigEndian.Uint16(b))
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// EchoRequest builds an IPv4 packet that carries an ICMP echo request, with both
// checksums right. src and dst must be IPv4 addresses.
func EchoRequest(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	const ipHeader, icmpHeader = 20, 8
	p := make([]byte, ipHeader+icmpHeader+len(payload))
	p[0] = 0x45 // version 4, a header of 5 words
	binary.BigEndian.PutUint16(p[2:], uint16(min(len(p), 1<<16-1)))
	binary.BigEndian.PutUint16(p[6:], 0x4000) // don't fragment
	p[8] = 64                                 // TTL
	p[9] = 1                                  // ICMP
	s, d := src.As4(), dst.As4()
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	binary.BigEndian.PutUint16(p[10:], Checksum(p[:ipHeader]))

	icmp := p[ipHeader:]
	icmp[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	copy(icmp[icmpHeader:], payload)
	binary.BigEndian.PutUint16(icmp[2:], Checksum(icmp))
	return p
}

// Echo is the parts of an ICMP echo reply.
type Echo struct {
	Src, Dst netip.Addr
	ID, Seq  uint16
	Payload  []byte
}

// ParseEchoReply reads an IPv4 packet that carries an ICMP echo reply. It reports
// false for anything else, and for a packet whose length or checksums are wrong.
func ParseEchoReply(p []byte) (Echo, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return Echo{}, false
	}
	ihl := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:]))
	if ihl < 20 || total < ihl+8 || total > len(p) || p[9] != 1 {
		return Echo{}, false
	}
	if Checksum(p[:ihl]) != 0 {
		return Echo{}, false
	}
	icmp := p[ihl:total]
	if icmp[0] != icmpEchoReply || icmp[1] != 0 || Checksum(icmp) != 0 {
		return Echo{}, false
	}
	return Echo{
		Src: netip.AddrFrom4([4]byte(p[12:16])), Dst: netip.AddrFrom4([4]byte(p[16:20])),
		ID: binary.BigEndian.Uint16(icmp[4:]), Seq: binary.BigEndian.Uint16(icmp[6:]),
		Payload: icmp[8:],
	}, true
}

// MakeEchoReply turns an echo request that EchoRequest built into the reply a
// host would send: the addresses swapped, the type 0, and the checksums redone. It
// returns nil when the packet is not a request of this form.
func MakeEchoReply(request []byte) []byte {
	if len(request) < 28 || request[0] != 0x45 || request[9] != 1 || request[20] != icmpEchoRequest {
		return nil
	}
	r := append([]byte(nil), request...)
	copy(r[12:16], request[16:20])
	copy(r[16:20], request[12:16])
	r[10], r[11] = 0, 0
	binary.BigEndian.PutUint16(r[10:], Checksum(r[:20]))
	r[20] = icmpEchoReply
	r[22], r[23] = 0, 0
	binary.BigEndian.PutUint16(r[22:], Checksum(r[20:]))
	return r
}

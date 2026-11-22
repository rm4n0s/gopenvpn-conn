// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"encoding/binary"
	"math"
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

// TCPSYN is a TCP SYN (a SYN-ACK when ack is set) from src to dst with an MSS
// option of mss and the other options that Linux sends, over IPv4 or IPv6 as the
// addresses are, with its checksums right.
func TCPSYN(src, dst netip.Addr, mss uint16, ack bool) []byte {
	opts := binary.BigEndian.AppendUint16([]byte{2, 4}, mss)
	opts = append(opts, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7) // SACK, timestamps, NOP, window scale
	tcp := make([]byte, 20+len(opts))
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	binary.BigEndian.PutUint32(tcp[4:], 1000)
	tcp[12] = 10 << 4 // 40 bytes: 20 and the options
	tcp[13] = 0x02
	if ack {
		tcp[13] |= 0x10
		binary.BigEndian.PutUint32(tcp[8:], 2001)
	}
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[20:], opts)
	var p []byte
	if src.Is4() {
		p = make([]byte, 20, 20+len(tcp))
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:], uint16(min(20+len(tcp), math.MaxUint16)))
		binary.BigEndian.PutUint16(p[6:], 0x4000)
		p[8], p[9] = 64, 6
		s, d := src.As4(), dst.As4()
		copy(p[12:], s[:])
		copy(p[16:], d[:])
		binary.BigEndian.PutUint16(p[10:], Checksum(p))
	} else {
		p = make([]byte, 40, 40+len(tcp))
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:], uint16(min(len(tcp), math.MaxUint16)))
		p[6], p[7] = 6, 64
		s, d := src.As16(), dst.As16()
		copy(p[8:], s[:])
		copy(p[24:], d[:])
	}
	p = append(p, tcp...)
	binary.BigEndian.PutUint16(p[len(p)-len(tcp)+16:], tcpChecksum(p))
	return p
}

// SYNMSS is the MSS option of a TCP SYN that TCPSYN made (or another with the MSS
// option first), and whether its TCP checksum is right; ok is false for a packet
// that is not such a SYN.
func SYNMSS(p []byte) (mss uint16, checksumOK, ok bool) {
	hlen := 0
	switch {
	case len(p) >= 20 && p[0]>>4 == 4 && p[9] == 6:
		hlen = int(p[0]&0x0f) * 4
	case len(p) >= 40 && p[0]>>4 == 6 && p[6] == 6:
		hlen = 40
	default:
		return 0, false, false
	}
	tcp := p[hlen:]
	if len(tcp) < 24 || tcp[13]&0x02 == 0 || tcp[20] != 2 || tcp[21] != 4 {
		return 0, false, false
	}
	return binary.BigEndian.Uint16(tcp[22:]), tcpChecksum(p) == 0, true
}

// tcpChecksum is the checksum of the TCP segment of p with its pseudo header, the
// checksum field counted: 0 when the field is right, and what the field must be
// when it is 0.
func tcpChecksum(p []byte) uint16 {
	var pseudo []byte
	var tcp []byte
	if p[0]>>4 == 4 {
		hlen := int(p[0]&0x0f) * 4
		tcp = p[hlen:]
		pseudo = append(pseudo, p[12:20]...)
		pseudo = append(pseudo, 0, 6)
		pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(min(len(tcp), math.MaxUint16)))
	} else {
		tcp = p[40:]
		pseudo = append(pseudo, p[8:40]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(min(len(tcp), math.MaxUint16)))
		pseudo = append(pseudo, 0, 0, 0, 6)
	}
	return Checksum(append(pseudo, tcp...))
}

// SPDX-License-Identifier: GPL-2.0-only

package mss

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// segment is a TCP segment with the given flags and options (padded to 4 bytes
// with EOL), and a payload, its checksum zero.
func segment(flags byte, opts []byte, payload []byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, optEOL)
	}
	tcp := make([]byte, tcpMinHeader, tcpMinHeader+len(opts)+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = byte(min((tcpMinHeader+len(opts))/4, 15)) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	return append(append(tcp, opts...), payload...)
}

// ipv4 is an IPv4 packet around tcp, with both checksums right.
func ipv4(tcp []byte) []byte {
	p := make([]byte, ipv4MinHeader, ipv4MinHeader+len(tcp))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(min(ipv4MinHeader+len(tcp), 0xffff)))
	p[8], p[9] = 64, protoTCP
	copy(p[12:], []byte{10, 8, 0, 2, 10, 8, 0, 1})
	p = append(p, tcp...)
	binary.BigEndian.PutUint16(p[ipv4MinHeader+16:], 0)
	binary.BigEndian.PutUint16(p[ipv4MinHeader+16:], ^tcpSum(p))
	return p
}

// ipv6 is an IPv6 packet around tcp, with the TCP checksum right.
func ipv6(tcp []byte) []byte {
	p := make([]byte, ipv6Header, ipv6Header+len(tcp))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(min(len(tcp), 0xffff)))
	p[6], p[7] = protoTCP, 64
	p[8], p[23] = 0xfd, 2
	p[24], p[39] = 0xfd, 1
	p = append(p, tcp...)
	binary.BigEndian.PutUint16(p[ipv6Header+16:], 0)
	binary.BigEndian.PutUint16(p[ipv6Header+16:], ^tcpSum(p))
	return p
}

// tcpSum is the one's complement sum of the TCP segment of p with its pseudo
// header, folded: 0xffff when the checksum in the segment is right.
func tcpSum(p []byte) uint16 {
	var s uint32
	add := func(b []byte) {
		for len(b) >= 2 {
			s += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) == 1 {
			s += uint32(b[0]) << 8
		}
	}
	var tcp []byte
	if p[0]>>4 == 4 {
		hlen := int(p[0]&0x0f) * 4
		tcp = p[hlen:]
		add(p[12:20])
	} else {
		tcp = p[ipv6Header:]
		add(p[8:40])
	}
	s += protoTCP + uint32(min(len(tcp), 0xffff))
	add(tcp)
	for s > 0xffff {
		s = (s & 0xffff) + s>>16
	}
	return uint16(s)
}

func mssOpt(v uint16) []byte { return binary.BigEndian.AppendUint16([]byte{optMSS, optMSSLen}, v) }

func TestClamp(t *testing.T) {
	linuxSYN := append(mssOpt(1460), 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, optNOP, 3, 3, 7) // MSS, SACK, timestamps, NOP, window scale
	tests := []struct {
		name    string
		packet  []byte
		max     int
		changed bool
		mss     uint16 // the MSS in the packet afterwards; 0 when there is none to read
	}{
		{"IPv4 SYN", ipv4(segment(tcpFlagSYN, mssOpt(1460), nil)), 1400, true, 1400},
		{"IPv4 SYN-ACK", ipv4(segment(tcpFlagSYN|0x10, mssOpt(1460), nil)), 1400, true, 1400},
		{"IPv4 SYN with the options of Linux", ipv4(segment(tcpFlagSYN, linuxSYN, nil)), 1396, true, 1396},
		{"IPv4 SYN after NOPs", ipv4(segment(tcpFlagSYN, append([]byte{optNOP, optNOP}, mssOpt(9000)...), nil)), 1400, true, 1400},
		{"IPv4 SYN that is small enough", ipv4(segment(tcpFlagSYN, mssOpt(1300), nil)), 1400, false, 1300},
		{"IPv4 SYN at the limit", ipv4(segment(tcpFlagSYN, mssOpt(1400), nil)), 1400, false, 1400},
		{"IPv4 ACK", ipv4(segment(0x10, mssOpt(1460), nil)), 1400, false, 1460},
		{"IPv4 SYN with the clamp off", ipv4(segment(tcpFlagSYN, mssOpt(1460), nil)), 0, false, 1460},
		{"IPv4 SYN with no options", ipv4(segment(tcpFlagSYN, nil, nil)), 1400, false, 0},
		{"IPv4 SYN with an MSS of 3 bytes", ipv4(segment(tcpFlagSYN, []byte{optMSS, 3, 5, optNOP}, nil)), 1400, false, 0},
		{"IPv4 SYN with the MSS after EOL", ipv4(segment(tcpFlagSYN, append([]byte{optEOL, 0, 0, 0}, mssOpt(1460)...), nil)), 1400, false, 0},
		{"IPv4 SYN with an option of length 0", ipv4(segment(tcpFlagSYN, append([]byte{8, 0, 0, 0}, mssOpt(1460)...), nil)), 1400, false, 0},
		{"IPv4 SYN with data", ipv4(segment(tcpFlagSYN, mssOpt(1460), []byte("hello"))), 1400, true, 1400},
		{"IPv6 SYN", ipv6(segment(tcpFlagSYN, mssOpt(1440), nil)), 1400, true, 1380},
		{"IPv6 SYN that is small enough", ipv6(segment(tcpFlagSYN, mssOpt(1380), nil)), 1400, false, 1380},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := bytes.Clone(tt.packet)
			if got := Needs(p, tt.max); got != tt.changed {
				t.Errorf("Needs = %v, want %v", got, tt.changed)
			}
			if !bytes.Equal(p, tt.packet) {
				t.Fatal("Needs changed the packet")
			}
			if got := Clamp(p, tt.max); got != tt.changed {
				t.Errorf("Clamp = %v, want %v", got, tt.changed)
			}
			if !tt.changed && !bytes.Equal(p, tt.packet) {
				t.Error("a packet that is not clamped changed")
			}
			if tcpSum(p) != 0xffff {
				t.Errorf("the TCP checksum is wrong after the clamp: sum %#04x", tcpSum(p))
			}
			if tt.mss != 0 {
				tcp, _ := synSegment(p, 1)
				if tcp == nil {
					tcp = p[ipv4MinHeader:]
				}
				for at := range mssOptions(tcp) {
					if got := binary.BigEndian.Uint16(tcp[at:]); got != tt.mss {
						t.Errorf("MSS = %d, want %d", got, tt.mss)
					}
				}
			}
		})
	}
}

// TestClampEveryMSSOption: a SYN with two MSS options has both lowered, as OpenVPN
// lowers them.
func TestClampEveryMSSOption(t *testing.T) {
	p := ipv4(segment(tcpFlagSYN, append(mssOpt(1460), mssOpt(1500)...), nil))
	if !Clamp(p, 1400) {
		t.Fatal("not clamped")
	}
	tcp := p[ipv4MinHeader:]
	for at := range mssOptions(tcp) {
		if got := binary.BigEndian.Uint16(tcp[at:]); got != 1400 {
			t.Errorf("MSS = %d", got)
		}
	}
	if tcpSum(p) != 0xffff {
		t.Error("the checksum is wrong")
	}
}

// TestClampLeavesOtherPackets: what is not a whole TCP SYN that starts the segment
// is never changed.
func TestClampLeavesOtherPackets(t *testing.T) {
	syn := ipv4(segment(tcpFlagSYN, mssOpt(1460), nil))
	fragment := bytes.Clone(syn)
	binary.BigEndian.PutUint16(fragment[6:], 100) // a later fragment
	udp := bytes.Clone(syn)
	udp[9] = 17
	short := bytes.Clone(syn)
	binary.BigEndian.PutUint16(short[2:], binary.BigEndian.Uint16(syn[2:])+4) // longer than what arrived
	badIHL := bytes.Clone(syn)
	badIHL[0] = 0x44
	hop := ipv6(segment(tcpFlagSYN, mssOpt(1460), nil))
	hop[6] = 0 // an extension header first
	tests := []struct {
		name   string
		packet []byte
	}{
		{"a later fragment", fragment},
		{"UDP", udp},
		{"a total length that is not the packet's", short},
		{"an IPv4 header shorter than 20 bytes", badIHL},
		{"IPv6 with an extension header", hop},
		{"version 5", append([]byte{0x50}, syn[1:]...)},
		{"empty", nil},
		{"one byte", []byte{0x45}},
		{"an IPv4 header and nothing more", syn[:ipv4MinHeader]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := bytes.Clone(tt.packet)
			if Needs(p, 1400) || Clamp(p, 1400) || !bytes.Equal(p, tt.packet) {
				t.Error("the packet was clamped")
			}
		})
	}
}

func TestSettingsMax(t *testing.T) {
	const aeadV2 = 4 + 4 + 16    // DATA_V2 header, 32-bit packet id, tag
	const aeadEpoch = 4 + 8 + 16 // the epoch format: a 64-bit packet id
	const aeadV1 = 1 + 4 + 16    // DATA_V1
	tests := []struct {
		name     string
		s        Settings
		overhead int
		want     int
	}{
		// The default over UDP and IPv4: 1492 - 28 - 24 - 40.
		{"default, UDP over IPv4", Settings{Size: 1492, Encap: 28}, aeadV2, 1400},
		// What the server of SPEC §21 O32 put on a SYN with the epoch format.
		{"default, epoch format", Settings{Size: 1492, Encap: 28}, aeadEpoch, 1396},
		{"default, TCP over IPv6", Settings{Size: 1492, Encap: 60}, 2 + aeadV2, 1366},
		{"DATA_V1", Settings{Size: 1492, Encap: 28}, aeadV1, 1403},
		{"mssfix 1450", Settings{Size: 1450}, aeadV2, 1386},
		{"mssfix 1400 fixed", Settings{Size: 1400, Fixed: true}, aeadV2, 1360},
		{"off", Settings{}, aeadV2, 0},
		{"too small to leave anything", Settings{Size: 60, Encap: 28}, aeadV2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.Max(tt.overhead); got != tt.want {
				t.Errorf("Max = %d, want %d", got, tt.want)
			}
		})
	}
}

// FuzzClamp: any bytes give no panic, Clamp changes at most the MSS options and the
// checksum, agrees with Needs, leaves nothing for a second Clamp, and keeps a
// checksum that was right.
func FuzzClamp(f *testing.F) {
	f.Add(ipv4(segment(tcpFlagSYN, mssOpt(1460), nil)), uint16(1400))
	f.Add(ipv6(segment(tcpFlagSYN, mssOpt(1440), nil)), uint16(1400))
	f.Add(ipv4(segment(tcpFlagSYN, append([]byte{optNOP, 3, 3, 7}, mssOpt(9000)...), []byte("x"))), uint16(536))
	f.Add([]byte{0x45}, uint16(1))
	f.Fuzz(func(t *testing.T, p []byte, max uint16) {
		orig := bytes.Clone(p)
		needs := Needs(p, int(max))
		if !bytes.Equal(p, orig) {
			t.Fatal("Needs changed the packet")
		}
		validBefore := len(p) > 0 && (p[0]>>4 == 4 && len(p) >= ipv4MinHeader && int(p[0]&0x0f)*4 >= ipv4MinHeader && int(p[0]&0x0f)*4 <= len(p) ||
			p[0]>>4 == 6 && len(p) >= ipv6Header) && tcpSum(p) == 0xffff
		changed := Clamp(p, int(max))
		if changed != needs {
			t.Fatalf("Clamp %v, Needs %v", changed, needs)
		}
		if len(p) != len(orig) {
			t.Fatal("the length changed")
		}
		diff := 0
		for i := range p {
			if p[i] != orig[i] {
				diff++
			}
		}
		if !changed && diff != 0 {
			t.Fatal("not clamped, but changed")
		}
		if Needs(p, int(max)) {
			t.Fatal("a second clamp would change it again")
		}
		if changed && validBefore && tcpSum(p) != 0xffff {
			t.Fatalf("the checksum was right and is wrong now: %x", orig)
		}
	})
}

// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestChecksum(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint16
	}{
		// The example of RFC 1071 §3: the words 0001 f203 f4f5 f6f7 sum to ddf2 (in one's complement), so the checksum is 220d.
		{"RFC 1071", []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}, 0x220d},
		{"empty", nil, 0xffff},
		{"an odd length pads with zero", []byte{0x01}, 0xfeff},
		{"a carry that wraps twice", bytes.Repeat([]byte{0xff, 0xff}, 5), 0x0000},
	}
	for _, tt := range tests {
		if got := Checksum(tt.data); got != tt.want {
			t.Errorf("%s: Checksum = %#04x, want %#04x", tt.name, got, tt.want)
		}
	}
	// A packet with its checksum in place sums to 0.
	p := EchoRequest(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.1"), 7, 9, []byte("abc"))
	if Checksum(p[:20]) != 0 || Checksum(p[20:]) != 0 {
		t.Error("the checksums of EchoRequest are wrong")
	}
}

func TestEchoRequestBytes(t *testing.T) {
	p := EchoRequest(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.1"), 0x1234, 0x0001, []byte{0xaa, 0xbb})
	// The checksums are summed by hand from RFC 791 and RFC 792. The header words
	// 4500 001e 0000 4000 4001 0a08 0002 0a08 0001 add up to d932, whose complement
	// is 26cd; the ICMP words 0800 1234 0001 aabb add up to c4f0, whose complement
	// is 3b0f.
	want := []byte{
		0x45, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x26, 0xcd, 10, 8, 0, 2, 10, 8, 0, 1,
		0x08, 0x00, 0x3b, 0x0f, 0x12, 0x34, 0x00, 0x01, 0xaa, 0xbb,
	}
	if !bytes.Equal(p, want) {
		t.Errorf("EchoRequest = % x\nwant          % x", p, want)
	}
}

func TestEchoRoundTrip(t *testing.T) {
	src, dst := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.1")
	for _, size := range []int{0, 1, 2, 31, 56, 1400} {
		payload := bytes.Repeat([]byte{0xab}, size)
		request := EchoRequest(src, dst, 4660, 77, payload)
		if _, ok := ParseEchoReply(request); ok {
			t.Errorf("size %d: a request parsed as a reply", size)
		}
		reply := MakeEchoReply(request)
		got, ok := ParseEchoReply(reply)
		if !ok || got.Src != dst || got.Dst != src || got.ID != 4660 || got.Seq != 77 || !bytes.Equal(got.Payload, payload) {
			t.Errorf("size %d: reply = %+v, %v", size, got, ok)
		}
	}
}

func TestParseEchoReplyRefusals(t *testing.T) {
	src, dst := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.1")
	good := MakeEchoReply(EchoRequest(src, dst, 1, 2, []byte("payload")))
	if _, ok := ParseEchoReply(good); !ok {
		t.Fatal("the good reply does not parse")
	}
	with := func(f func(p []byte) []byte) []byte { return f(bytes.Clone(good)) }
	tests := []struct {
		name string
		p    []byte
	}{
		{"nothing", nil},
		{"too short", good[:27]},
		{"IPv6", with(func(p []byte) []byte { p[0] = 0x65; return p })},
		{"a header that is too small", with(func(p []byte) []byte { p[0] = 0x44; return p })},
		{"not ICMP", with(func(p []byte) []byte { p[9] = 17; return p })},
		{"a bad header checksum", with(func(p []byte) []byte { p[10] ^= 1; return p })},
		{"a bad ICMP checksum", with(func(p []byte) []byte { p[len(p)-1] ^= 1; return p })},
		{"a length longer than the packet", with(func(p []byte) []byte { return p[:len(p)-1] })},
		{"a request", EchoRequest(src, dst, 1, 2, nil)},
	}
	for _, tt := range tests {
		if _, ok := ParseEchoReply(tt.p); ok {
			t.Errorf("%s: parsed", tt.name)
		}
	}
	if MakeEchoReply([]byte{1, 2, 3}) != nil || MakeEchoReply(good) != nil {
		t.Error("MakeEchoReply made a reply of what is not a request")
	}
}

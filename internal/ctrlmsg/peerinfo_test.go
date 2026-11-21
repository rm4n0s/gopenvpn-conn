// SPDX-License-Identifier: GPL-2.0-only

package ctrlmsg

import "testing"

func TestPeerInfoString(t *testing.T) {
	tests := []struct {
		name string
		p    PeerInfo
		want string
	}{
		{
			name: "the defaults of the library",
			p: PeerInfo{
				Version: "gopenvpn-conn 0.2.0", Platform: "linux", MTU: 1600,
				Ciphers: []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"},
				Proto:   IVProtoDataV2 | IVProtoRequestPush | IVProtoTLSKeyExport,
			},
			want: "IV_VER=gopenvpn-conn 0.2.0\nIV_PLAT=linux\nIV_TCPNL=1\nIV_MTU=1600\nIV_NCP=2\n" +
				"IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nIV_PROTO=14\n",
		},
		{
			name: "no NCP line when only one of the two AES ciphers is offered",
			p:    PeerInfo{Version: "v", Platform: "win", MTU: 1500, Ciphers: []string{"AES-256-GCM", "CHACHA20-POLY1305"}, Proto: 2},
			want: "IV_VER=v\nIV_PLAT=win\nIV_TCPNL=1\nIV_MTU=1500\nIV_CIPHERS=AES-256-GCM:CHACHA20-POLY1305\nIV_PROTO=2\n",
		},
		{
			name: "UV variables sorted at the end",
			p: PeerInfo{
				Version: "v", Platform: "mac", MTU: 1500, Ciphers: []string{"CHACHA20-POLY1305"}, Proto: 14,
				UV: map[string]string{"UV_ZED": "last", "UV_APP": "first", "UV_MID": "m"},
			},
			want: "IV_VER=v\nIV_PLAT=mac\nIV_TCPNL=1\nIV_MTU=1500\nIV_CIPHERS=CHACHA20-POLY1305\nIV_PROTO=14\n" +
				"UV_APP=first\nUV_MID=m\nUV_ZED=last\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("peer info =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestIVProtoBits(t *testing.T) {
	// The values are those of OpenVPN's ssl.h; the peer reads them.
	for name, c := range map[string]struct{ got, want int }{
		"DATA_V2": {IVProtoDataV2, 2}, "REQUEST_PUSH": {IVProtoRequestPush, 4}, "TLS_KEY_EXPORT": {IVProtoTLSKeyExport, 8},
		"AUTH_PENDING_KW": {IVProtoAuthPendingKW, 16}, "CC_EXIT_NOTIFY": {IVProtoCCExitNotify, 128},
		"AUTH_FAIL_TEMP": {IVProtoAuthFailTemp, 256}, "DYN_TLS_CRYPT": {IVProtoDynTLSCrypt, 512},
		"DATA_EPOCH": {IVProtoDataEpoch, 1024}, "DNS_OPTION_V2": {IVProtoDNSOptionV2, 2048},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", name, c.got, c.want)
		}
	}
}

func TestOptionsString(t *testing.T) {
	tests := []struct {
		name string
		o    OptionsParams
		want string
	}{
		{
			"UDP over IPv4", OptionsParams{TunMTU: 1500, Cipher: "AES-256-GCM", KeySizeBits: 256},
			"V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
		{
			"TCP over IPv4", OptionsParams{Stream: true, TunMTU: 1500, Cipher: "AES-128-GCM", KeySizeBits: 128},
			"V4,dev-type tun,link-mtu 1543,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-128-GCM,auth [null-digest],keysize 128,key-method 2,tls-client",
		},
		{
			"UDP over IPv6", OptionsParams{IPv6: true, TunMTU: 1400, Cipher: "CHACHA20-POLY1305", KeySizeBits: 256},
			"V4,dev-type tun,link-mtu 1441,tun-mtu 1400,proto UDPv6,cipher CHACHA20-POLY1305,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
		{
			"TCP over IPv6", OptionsParams{Stream: true, IPv6: true, TunMTU: 1500, Cipher: "AES-256-GCM", KeySizeBits: 256},
			"V4,dev-type tun,link-mtu 1543,tun-mtu 1500,proto TCPv6_CLIENT,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OptionsString(tt.o); got != tt.want {
				t.Errorf("options =\n%s\nwant\n%s", got, tt.want)
			}
			if len(tt.want)+1 > MaxOptionsLen {
				t.Errorf("the string is %d bytes with its NUL, the limit is %d", len(tt.want)+1, MaxOptionsLen)
			}
		})
	}
}

// SPDX-License-Identifier: GPL-2.0-only

package ctrlmsg

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/errors"
)

var offeredAll = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func adr(s string) netip.Addr   { return netip.MustParseAddr(s) }

// pushOne parses a whole reply in one part and finishes it.
func pushOne(t *testing.T, text string) (*Pushed, error) {
	t.Helper()
	reply, err := ParsePushReply(text)
	if err != nil {
		return nil, err
	}
	p := &Pushed{}
	if err := p.Add(reply, offeredAll); err != nil {
		return nil, err
	}
	if err := p.Finish(); err != nil {
		return nil, err
	}
	return p, nil
}

func TestAppendMessage(t *testing.T) {
	if got := AppendMessage([]byte("x"), PushRequest); string(got) != "xPUSH_REQUEST\x00" {
		t.Errorf("AppendMessage = %q", got)
	}
}

func TestName(t *testing.T) {
	for in, want := range map[string]string{
		"auth-token abc": "auth-token", "PUSH_REPLY,ping 10": "PUSH_REPLY", "x": "x", "": "",
		strings.Repeat("a", 100): strings.Repeat("a", 40),
	} {
		if got := Name(in); got != want {
			t.Errorf("Name(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePushReply(t *testing.T) {
	tests := []struct {
		text string
		want PushReply
	}{
		{"PUSH_REPLY", PushReply{}},
		{"PUSH_REPLY,ping 10,ping-restart 60", PushReply{Options: []string{"ping 10", "ping-restart 60"}}},
		{"PUSH_REPLY,route 10.0.0.0 255.0.0.0,push-continuation 2", PushReply{Options: []string{"route 10.0.0.0 255.0.0.0"}, More: true}},
		{"PUSH_REPLY,ping 10,push-continuation 1", PushReply{Options: []string{"ping 10"}}},
		{"PUSH_REPLY,,ping 10,,", PushReply{Options: []string{"ping 10"}}},
	}
	for _, tt := range tests {
		got, err := ParsePushReply(tt.text)
		if err != nil {
			t.Errorf("%q: %v", tt.text, err)
			continue
		}
		if !reflect.DeepEqual(*got, tt.want) {
			t.Errorf("%q = %+v, want %+v", tt.text, *got, tt.want)
		}
		if !IsPushReply(tt.text) {
			t.Errorf("IsPushReply(%q) is false", tt.text)
		}
	}
	for _, text := range []string{"PUSH_REPLYX", "PUSH_REQUEST", "", "push_reply"} {
		if IsPushReply(text) {
			t.Errorf("IsPushReply(%q) is true", text)
		}
		_, err := ParsePushReply(text)
		if appErr, ok := errors.FromError(err); !ok || !appErr.HasRoute("ParsePushReply.BadControlMessage") {
			t.Errorf("ParsePushReply(%q) = %v, want a bad control message", text, err)
		}
	}
	for _, text := range []string{"PUSH_REPLY,push-continuation 3", "PUSH_REPLY,push-continuation x", "PUSH_REPLY,push-continuation 0"} {
		_, err := ParsePushReply(text)
		if appErr, ok := errors.FromError(err); !ok || !appErr.HasRoute("ParsePushReply.BadPushedOption") {
			t.Errorf("ParsePushReply(%q) = %v, want a bad pushed option", text, err)
		}
	}
}

func TestPushedOptionsUsed(t *testing.T) {
	tests := []struct {
		name  string
		reply string
		check func(t *testing.T, p *Pushed)
	}{
		{"ifconfig, topology subnet", "PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.255.255.0", func(t *testing.T, p *Pushed) {
			want := []netip.Prefix{pfx("10.8.0.2/24")}
			if !reflect.DeepEqual(p.Addrs, want) || p.Topology != "subnet" {
				t.Errorf("addrs = %v, topology %q", p.Addrs, p.Topology)
			}
		}},
		{"ifconfig, topology after ifconfig", "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet", func(t *testing.T, p *Pushed) {
			if !reflect.DeepEqual(p.Addrs, []netip.Prefix{pfx("10.8.0.2/24")}) {
				t.Errorf("addrs = %v", p.Addrs)
			}
		}},
		{"ifconfig, net30 by default", "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5", func(t *testing.T, p *Pushed) {
			if !reflect.DeepEqual(p.Addrs, []netip.Prefix{pfx("10.8.0.6/30")}) || p.Topology != "net30" {
				t.Errorf("addrs = %v, topology %q", p.Addrs, p.Topology)
			}
		}},
		{"ifconfig, p2p", "PUSH_REPLY,topology p2p,ifconfig 10.8.0.2 10.8.0.1", func(t *testing.T, p *Pushed) {
			if !reflect.DeepEqual(p.Addrs, []netip.Prefix{pfx("10.8.0.2/32")}) {
				t.Errorf("addrs = %v", p.Addrs)
			}
		}},
		{"ifconfig-ipv6 after ifconfig", "PUSH_REPLY,ifconfig-ipv6 fd00::1000/64 fd00::1,topology subnet,ifconfig 10.8.0.2 255.255.255.0", func(t *testing.T, p *Pushed) {
			want := []netip.Prefix{pfx("10.8.0.2/24"), pfx("fd00::1000/64")}
			if !reflect.DeepEqual(p.Addrs, want) {
				t.Errorf("addrs = %v, want %v", p.Addrs, want)
			}
		}},
		{"route-gateway", "PUSH_REPLY,route-gateway 10.8.0.1", func(t *testing.T, p *Pushed) {
			if p.Gateway != adr("10.8.0.1") {
				t.Errorf("gateway = %v", p.Gateway)
			}
		}},
		{"route-gateway dhcp", "PUSH_REPLY,route-gateway dhcp", func(t *testing.T, p *Pushed) {
			if p.Gateway.IsValid() {
				t.Errorf("gateway = %v", p.Gateway)
			}
		}},
		{"routes", "PUSH_REPLY,route 192.168.50.0 255.255.255.0,route 10.9.0.5,route 172.16.0.0 255.240.0.0 10.8.0.1 7,route default,route 10.1.0.0 255.255.0.0 vpn_gateway default,route-ipv6 2001:db8::/32,route-ipv6 fd00:1::/48 fd00::1 20", func(t *testing.T, p *Pushed) {
			want := []Route{
				{Prefix: pfx("192.168.50.0/24")},
				{Prefix: pfx("10.9.0.5/32")},
				{Prefix: pfx("172.16.0.0/12"), Gateway: adr("10.8.0.1"), Metric: 7},
				{Prefix: pfx("0.0.0.0/0")},
				{Prefix: pfx("10.1.0.0/16")},
				{Prefix: pfx("2001:db8::/32")},
				{Prefix: pfx("fd00:1::/48"), Gateway: adr("fd00::1"), Metric: 20},
			}
			if !reflect.DeepEqual(p.Routes, want) {
				t.Errorf("routes = %+v\nwant %+v", p.Routes, want)
			}
		}},
		{"route with a host part is masked", "PUSH_REPLY,route 192.168.50.7 255.255.255.0", func(t *testing.T, p *Pushed) {
			if p.Routes[0].Prefix != pfx("192.168.50.0/24") {
				t.Errorf("route = %v", p.Routes[0])
			}
		}},
		{"redirect-gateway", "PUSH_REPLY,redirect-gateway def1 bypass-dhcp", func(t *testing.T, p *Pushed) {
			if !p.RedirectGateway {
				t.Error("RedirectGateway is false")
			}
		}},
		{"dhcp-option", "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS6 fd00::53,dhcp-option DOMAIN corp.example,dhcp-option DOMAIN-SEARCH a.example,dhcp-option DNS 10.8.0.1,dhcp-option WINS 1.2.3.4,dhcp-option DISABLE-NBT", func(t *testing.T, p *Pushed) {
			if !reflect.DeepEqual(p.DNSServers, []netip.Addr{adr("10.8.0.1"), adr("fd00::53")}) {
				t.Errorf("DNS = %v", p.DNSServers)
			}
			if !reflect.DeepEqual(p.SearchDomains, []string{"corp.example", "a.example"}) {
				t.Errorf("domains = %v", p.SearchDomains)
			}
		}},
		{"dns", "PUSH_REPLY,dns server 1 address 10.8.0.1 [fd00::1]:53 192.0.2.7,dns search-domains x.example y.example,dns server 1 resolve-domains corp", func(t *testing.T, p *Pushed) {
			want := []netip.Addr{adr("10.8.0.1"), adr("fd00::1"), adr("192.0.2.7")}
			if !reflect.DeepEqual(p.DNSServers, want) || !reflect.DeepEqual(p.SearchDomains, []string{"x.example", "y.example"}) {
				t.Errorf("DNS = %v, domains = %v", p.DNSServers, p.SearchDomains)
			}
		}},
		{"tun-mtu", "PUSH_REPLY,tun-mtu 1400", func(t *testing.T, p *Pushed) {
			if p.MTU != 1400 {
				t.Errorf("MTU = %d", p.MTU)
			}
		}},
		{"ping and ping-restart", "PUSH_REPLY,ping 10,ping-restart 60", func(t *testing.T, p *Pushed) {
			if p.PingInterval != 10*time.Second || p.PingRestart != 60*time.Second {
				t.Errorf("ping = %v, ping-restart = %v", p.PingInterval, p.PingRestart)
			}
		}},
		{"reneg-sec", "PUSH_REPLY,reneg-sec 0", func(t *testing.T, p *Pushed) {
			if !p.HasReneg || p.RenegInterval != 0 {
				t.Errorf("reneg-sec = %v (%v)", p.RenegInterval, p.HasReneg)
			}
		}},
		{"peer-id", "PUSH_REPLY,peer-id 7", func(t *testing.T, p *Pushed) {
			if !p.HasPeerID || p.PeerID != 7 {
				t.Errorf("peer-id = %d (%v)", p.PeerID, p.HasPeerID)
			}
		}},
		{"cipher, in capitals or not", "PUSH_REPLY,cipher aes-256-gcm", func(t *testing.T, p *Pushed) {
			if p.Cipher != "AES-256-GCM" {
				t.Errorf("cipher = %q", p.Cipher)
			}
		}},
		{"key-derivation and protocol-flags", "PUSH_REPLY,key-derivation tls-ekm,protocol-flags cc-exit tls-ekm dyn-tls-crypt,protocol-flags aead-epoch", func(t *testing.T, p *Pushed) {
			if p.KeyDerivation != "tls-ekm" || !reflect.DeepEqual(p.ProtocolFlags, []string{"cc-exit", "tls-ekm", "dyn-tls-crypt", "aead-epoch"}) {
				t.Errorf("key-derivation = %q, flags = %v", p.KeyDerivation, p.ProtocolFlags)
			}
		}},
		{"auth-token, which is not kept in the options", "PUSH_REPLY,auth-token SECRETTOKEN,auth-token-user YWxpY2U=", func(t *testing.T, p *Pushed) {
			if p.AuthToken != "SECRETTOKEN" || p.AuthTokenUser != "YWxpY2U=" {
				t.Errorf("token = %q user = %q", p.AuthToken, p.AuthTokenUser)
			}
			for _, o := range p.Options {
				if strings.Contains(o, "SECRETTOKEN") {
					t.Errorf("the token is in the options: %q", o)
				}
			}
			if !reflect.DeepEqual(p.Options, []string{"auth-token", "auth-token-user YWxpY2U="}) {
				t.Errorf("options = %q", p.Options)
			}
		}},
		{"explicit-exit-notify", "PUSH_REPLY,explicit-exit-notify", func(t *testing.T, p *Pushed) {
			if p.ExitNotify != 1 {
				t.Errorf("explicit-exit-notify = %d", p.ExitNotify)
			}
		}},
		{"explicit-exit-notify 3", "PUSH_REPLY,explicit-exit-notify 3", func(t *testing.T, p *Pushed) {
			if p.ExitNotify != 3 {
				t.Errorf("explicit-exit-notify = %d", p.ExitNotify)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := pushOne(t, tt.reply)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, p)
		})
	}
}

func TestPushedOptionsIgnoredAndUnknown(t *testing.T) {
	p, err := pushOne(t, "PUSH_REPLY,block-outside-dns,register-dns,sndbuf 393216,persist-tun,frobnicate 1,another-new-one")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Options) != 6 || p.Options[2] != "sndbuf 393216" {
		t.Errorf("options = %q: every option is kept as received", p.Options)
	}
	if !reflect.DeepEqual(p.Unknown, []string{"frobnicate", "another-new-one"}) {
		t.Errorf("unknown = %v: the ignored ones are not unknown", p.Unknown)
	}
}

func TestPushedParts(t *testing.T) {
	p := &Pushed{}
	for _, text := range []string{
		"PUSH_REPLY,route 10.1.0.0 255.255.0.0,topology subnet,push-continuation 2",
		"PUSH_REPLY,route 10.2.0.0 255.255.0.0,push-continuation 2",
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping 10,push-continuation 1",
	} {
		reply, err := ParsePushReply(text)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Add(reply, offeredAll); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Finish(); err != nil {
		t.Fatal(err)
	}
	if len(p.Routes) != 2 || len(p.Addrs) != 1 || p.Addrs[0] != pfx("10.8.0.2/24") || p.PingInterval != 10*time.Second || len(p.Options) != 5 {
		t.Errorf("after three parts: routes %v, addrs %v, ping %v, options %d", p.Routes, p.Addrs, p.PingInterval, len(p.Options))
	}
}

func TestPushedFailures(t *testing.T) {
	tests := []struct {
		reply  string
		route  string
		option string
	}{
		{"PUSH_REPLY,topology wide", "apply.BadPushedOption", "topology"},
		{"PUSH_REPLY,topology", "apply.BadPushedOption", "topology"},
		{"PUSH_REPLY,ifconfig 10.8.0.2", "apply.BadPushedOption", "ifconfig"},
		{"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0 x", "apply.BadPushedOption", "ifconfig"},
		{"PUSH_REPLY,topology subnet,ifconfig nope 255.255.255.0", "Finish.BadPushedOption", "ifconfig"},
		{"PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 nope", "Finish.BadPushedOption", "ifconfig"},
		{"PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.0.255.0", "Finish.BadPushedOption", "ifconfig"},
		{"PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 ::1", "Finish.BadPushedOption", "ifconfig"},
		{"PUSH_REPLY,ifconfig-ipv6", "apply.BadPushedOption", "ifconfig-ipv6"},
		{"PUSH_REPLY,ifconfig-ipv6 fd00::1", "apply.BadPushedOption", "ifconfig-ipv6"},
		{"PUSH_REPLY,ifconfig-ipv6 10.0.0.1/24 x", "apply.BadPushedOption", "ifconfig-ipv6"},
		{"PUSH_REPLY,route", "apply.BadPushedOption", "route"},
		{"PUSH_REPLY,route 1.2.3.4 255.255.255.0 gw 1 2", "apply.BadPushedOption", "route"},
		{"PUSH_REPLY,route nope", "apply.BadPushedOption", "route"},
		{"PUSH_REPLY,route ::1", "apply.BadPushedOption", "route"},
		{"PUSH_REPLY,route 10.0.0.0 nope", "apply.BadPushedOption", "route"},
		{"PUSH_REPLY,route 10.0.0.0 255.0.255.0", "apply.BadPushedOption", "route"},
		{"PUSH_REPLY,route 10.0.0.0 255.0.0.0 gateway-name", "apply.BadPushedOption", "route"},
		{"PUSH_REPLY,route 10.0.0.0 255.0.0.0 10.8.0.1 -3", "apply.BadPushedOption", "route"},
		{"PUSH_REPLY,route-ipv6", "apply.BadPushedOption", "route-ipv6"},
		{"PUSH_REPLY,route-ipv6 2001:db8::", "apply.BadPushedOption", "route-ipv6"},
		{"PUSH_REPLY,route-ipv6 10.0.0.0/8", "apply.BadPushedOption", "route-ipv6"},
		{"PUSH_REPLY,route-ipv6 fd00::/8 a b c", "apply.BadPushedOption", "route-ipv6"},
		{"PUSH_REPLY,route-gateway", "apply.BadPushedOption", "route-gateway"},
		{"PUSH_REPLY,route-gateway nope", "apply.BadPushedOption", "route-gateway"},
		{"PUSH_REPLY,dhcp-option DNS nope", "apply.BadPushedOption", "dhcp-option"},
		{"PUSH_REPLY,dns server 1 address nope", "apply.BadPushedOption", "dns"},
		{"PUSH_REPLY,tun-mtu 67", "apply.BadPushedOption", "tun-mtu"},
		{"PUSH_REPLY,tun-mtu 65536", "apply.BadPushedOption", "tun-mtu"},
		{"PUSH_REPLY,tun-mtu x", "apply.BadPushedOption", "tun-mtu"},
		{"PUSH_REPLY,ping -1", "apply.BadPushedOption", "ping"},
		{"PUSH_REPLY,ping", "apply.BadPushedOption", "ping"},
		{"PUSH_REPLY,ping-restart x", "apply.BadPushedOption", "ping-restart"},
		{"PUSH_REPLY,reneg-sec -5", "apply.BadPushedOption", "reneg-sec"},
		{"PUSH_REPLY,peer-id 16777216", "apply.BadPushedOption", "peer-id"},
		{"PUSH_REPLY,peer-id -1", "apply.BadPushedOption", "peer-id"},
		{"PUSH_REPLY,cipher", "apply.BadPushedOption", "cipher"},
		{"PUSH_REPLY,key-derivation", "apply.BadPushedOption", "key-derivation"},
		{"PUSH_REPLY,auth-token", "apply.BadPushedOption", "auth-token"},
		{"PUSH_REPLY,auth-token-user", "apply.BadPushedOption", "auth-token-user"},
		{"PUSH_REPLY,explicit-exit-notify x", "apply.BadPushedOption", "explicit-exit-notify"},
		{"PUSH_REPLY,compress lz4", "apply.UnsupportedPushedOption", "compress"},
		{"PUSH_REPLY,compress", "apply.UnsupportedPushedOption", "compress"},
		{"PUSH_REPLY,comp-lzo no", "apply.UnsupportedPushedOption", "comp-lzo"},
		{"PUSH_REPLY,fragment 1300", "apply.UnsupportedPushedOption", "fragment"},
		{"PUSH_REPLY,cipher AES-256-CBC", "apply.UnsupportedPushedOption", "cipher"},
		{"PUSH_REPLY,cipher none", "apply.UnsupportedPushedOption", "cipher"},
		{"PUSH_REPLY,cipher AES-192-GCM", "apply.CipherNegotiationFailed", ""},
	}
	for _, tt := range tests {
		t.Run(tt.reply, func(t *testing.T) {
			p, err := pushOne(t, tt.reply)
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute(tt.route) {
				t.Errorf("unexpected failure path: %s, want %s", appErr.Route(), tt.route)
			}
			if tt.option != "" && appErr.Metadata["option"] != tt.option {
				t.Errorf("metadata = %v, want option %q", appErr.Metadata, tt.option)
			}
			if p != nil {
				t.Error("a result came with the error")
			}
		})
	}
}

func TestTooManyPushedOptions(t *testing.T) {
	p := &Pushed{}
	part := &PushReply{More: true}
	for i := 0; i < 1000; i++ {
		part.Options = append(part.Options, "persist-tun")
	}
	var err error
	for i := 0; i < 5 && err == nil; i++ {
		err = p.Add(part, offeredAll)
	}
	appErr, ok := errors.FromError(err)
	if !ok || !appErr.HasRoute("Add.TooManyPushedOptions") {
		t.Fatalf("Add = %v, want too many options", err)
	}
	if len(p.Options) > maxPushedOptions {
		t.Errorf("%d options kept, the limit is %d", len(p.Options), maxPushedOptions)
	}
}

func TestPushedErrorsCarryNoValues(t *testing.T) {
	_, err := pushOne(t, "PUSH_REPLY,tun-mtu SECRETVALUE")
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatal(err)
	}
	for _, v := range appErr.Metadata {
		if s, isString := v.(string); isString && strings.Contains(s, "SECRETVALUE") {
			t.Errorf("a value is in the metadata: %q", s)
		}
	}
	if strings.Contains(appErr.Message, "SECRETVALUE") {
		t.Error("a value is in the message")
	}
}

func FuzzParsePushReply(f *testing.F) {
	f.Add("PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.255.255.0,route 10.1.0.0 255.255.0.0,ping 10,push-continuation 1")
	f.Add("PUSH_REPLY,ifconfig-ipv6 fd00::1000/64 fd00::1,route-ipv6 2001:db8::/32,dhcp-option DNS 10.8.0.1")
	f.Add("PUSH_REPLY,auth-token SECRETSECRET,cipher AES-256-GCM,dns server 1 address 10.0.0.1")
	f.Add("PUSH_REPLY,compress lz4")
	f.Add("PUSH_REPLY")
	f.Fuzz(func(t *testing.T, text string) {
		reply, err := ParsePushReply(text)
		if err != nil {
			if _, ok := errors.FromError(err); !ok {
				t.Fatalf("the error is not tagged: %T", err)
			}
			return
		}
		p := &Pushed{}
		if err := p.Add(reply, offeredAll); err != nil {
			if _, ok := errors.FromError(err); !ok {
				t.Fatalf("the error is not tagged: %T", err)
			}
			return
		}
		if err := p.Finish(); err != nil {
			if _, ok := errors.FromError(err); !ok {
				t.Fatalf("the error is not tagged: %T", err)
			}
			return
		}
		for _, o := range p.Options {
			if strings.HasPrefix(o, "auth-token ") {
				t.Fatalf("auth-token kept its value: %q", o)
			}
		}
		for _, a := range p.Addrs {
			if !a.IsValid() {
				t.Fatalf("an invalid address: %v", a)
			}
		}
		for _, r := range p.Routes {
			if !r.Prefix.IsValid() || r.Prefix != r.Prefix.Masked() {
				t.Fatalf("a bad route: %+v", r)
			}
		}
	})
}

// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// kxRig runs a handshake with TLS and the key exchange against the in-process
// server, and returns what the server received.
func kxRig(t *testing.T, k kind, cfg *Config) (*Conn, *vpntest.ClientKeyExchange) {
	t.Helper()
	pki := servertest.NewPKI(t)
	link, srv := tlsPair(t, k, protections()[0], serverTLS(pki, pki.ServerCert))
	cfg.TLS = NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}})
	conn := newClient(k, link, cfg)
	closeAtEnd(t, conn)
	if err := conn.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-srv.KeyExchangeDone()
	kx := srv.KeyExchange()
	if kx == nil {
		t.Fatal("the server got no key exchange message")
	}
	return conn, kx
}

func peerInfoLines(info string) map[string]string {
	lines := map[string]string{}
	for _, l := range strings.Split(strings.TrimSuffix(info, "\n"), "\n") {
		name, value, _ := strings.Cut(l, "=")
		lines[name] = value
	}
	return lines
}

func TestKeyExchangeMessage(t *testing.T) {
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, kx := kxRig(t, k, &Config{})
				if !kx.LeadingZeros {
					t.Error("the message does not start with 4 zero bytes")
				}
				if allSame(kx.PreMaster) || allSame(kx.Random1) || allSame(kx.Random2) {
					t.Error("a random field is not random")
				}
				wantProto := "UDPv4"
				if k.stream {
					wantProto = "TCPv4_CLIENT"
				}
				if !strings.HasPrefix(kx.Options, "V4,dev-type tun,") || !strings.Contains(kx.Options, ",proto "+wantProto+",") ||
					!strings.Contains(kx.Options, ",cipher AES-256-GCM,") || !strings.HasSuffix(kx.Options, ",key-method 2,tls-client") {
					t.Errorf("options string = %q", kx.Options)
				}
				if kx.Username != "" || kx.Password != "" {
					t.Errorf("credentials were sent without being asked: %q %q", kx.Username, kx.Password)
				}
				info := peerInfoLines(kx.PeerInfo)
				for name, want := range map[string]string{
					"IV_TCPNL": "1", "IV_NCP": "2", "IV_MTU": "1600", "IV_PROTO": "286",
					"IV_CIPHERS": "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
				} {
					if info[name] != want {
						t.Errorf("%s = %q, want %q", name, info[name], want)
					}
				}
				if !strings.HasPrefix(info["IV_VER"], "gopenvpn-conn ") || strings.HasPrefix(info["IV_VER"], "2.") {
					t.Errorf("IV_VER = %q: it must say what this client is", info["IV_VER"])
				}
				if want := platform(); info["IV_PLAT"] != want {
					t.Errorf("IV_PLAT = %q, want %q", info["IV_PLAT"], want)
				}
			})
		})
	}
}

func allSame(b []byte) bool {
	for _, x := range b {
		if x != b[0] {
			return false
		}
	}
	return true
}

func TestKeyExchangeFollowsTheConfig(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		var ctxErrAtCall error
		_, kx := kxRig(t, kinds[0], &Config{
			DataCiphers: []string{"chacha20-poly1305", "AES-256-GCM"},
			MTU:         1400,
			PeerInfo:    map[string]string{"UV_REGION": "eu", "UV_APP": "tests"},
			Credentials: func(ctx context.Context) (Credentials, error) {
				calls++
				ctxErrAtCall = ctx.Err()
				return Credentials{Username: "alice", Password: "s3cret"}, nil
			},
		})
		if kx.Username != "alice" || kx.Password != "s3cret" {
			t.Errorf("credentials = %q %q", kx.Username, kx.Password)
		}
		if calls != 1 || ctxErrAtCall != nil {
			t.Errorf("Credentials was called %d times, with a context error %v", calls, ctxErrAtCall)
		}
		if !strings.Contains(kx.Options, ",tun-mtu 1400,") || !strings.Contains(kx.Options, ",cipher CHACHA20-POLY1305,") ||
			!strings.Contains(kx.Options, ",keysize 256,") {
			t.Errorf("options string = %q", kx.Options)
		}
		info := peerInfoLines(kx.PeerInfo)
		if info["IV_CIPHERS"] != "CHACHA20-POLY1305:AES-256-GCM" || info["IV_NCP"] != "" || info["IV_MTU"] != "1600" {
			t.Errorf("peer info = %v", info)
		}
		if info["UV_REGION"] != "eu" || info["UV_APP"] != "tests" {
			t.Errorf("the UV variables are lost: %v", info)
		}
		if !strings.HasSuffix(kx.PeerInfo, "UV_APP=tests\nUV_REGION=eu\n") {
			t.Errorf("the UV variables are not sorted at the end: %q", kx.PeerInfo)
		}
	})
}

func TestIVMTUIsNotBelowTheTunnelMTU(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, kx := kxRig(t, kinds[0], &Config{MTU: 9000})
		if got := peerInfoLines(kx.PeerInfo)["IV_MTU"]; got != "9000" {
			t.Errorf("IV_MTU = %q, want 9000", got)
		}
	})
}

func TestCredentialsFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, _ := tlsPair(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert))
		boom := context.DeadlineExceeded // any error: the cause must survive
		conn := PacketClient(link, &Config{
			TLS:         NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}}),
			Credentials: func(context.Context) (Credentials, error) { return Credentials{}, boom },
		})
		closeAtEnd(t, conn)
		err := conn.HandshakeContext(t.Context())
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != TagCredentialsFailed || !errors.Is(err, boom) || !appErr.HasRoute("keyExchange.CredentialsFailed") {
			t.Fatalf("HandshakeContext = %v, want %s", err, TagCredentialsFailed)
		}
	})
}

func TestCredentialsContextEndsWithTheConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, _ := tlsPair(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert))
		entered := make(chan struct{})
		conn := PacketClient(link, &Config{
			TLS: NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}}),
			Credentials: func(ctx context.Context) (Credentials, error) {
				close(entered)
				<-ctx.Done() // a prompt that nobody answers
				return Credentials{}, ctx.Err()
			},
		})
		result := make(chan error, 1)
		go func() { result <- conn.HandshakeContext(t.Context()) }()
		<-entered
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != net.ErrClosed {
			t.Errorf("HandshakeContext = %v, want net.ErrClosed", err)
		}
		synctest.Wait() // no goroutine is left waiting for the prompt
	})
}

func TestInvalidConfigFields(t *testing.T) {
	long := strings.Repeat("v", peerInfoMaxValue+1)
	tests := []struct {
		name  string
		cfg   Config
		field string
	}{
		{"negative handshake timeout", Config{HandshakeTimeout: -1}, "HandshakeTimeout"},
		{"no TLS", Config{}, "TLS"},
		{"MTU too small", Config{resetOnly: true, MTU: 575}, "MTU"},
		{"MTU too large", Config{resetOnly: true, MTU: 9001}, "MTU"},
		{"MTU negative", Config{resetOnly: true, MTU: -1}, "MTU"},
		{"a cipher that is not supported", Config{resetOnly: true, DataCiphers: []string{"AES-256-GCM", "AES-256-CBC"}}, "DataCiphers"},
		{"an empty cipher", Config{resetOnly: true, DataCiphers: []string{""}}, "DataCiphers"},
		{"peer info without UV_", Config{resetOnly: true, PeerInfo: map[string]string{"IV_VER": "x"}}, "PeerInfo"},
		{"peer info name with a newline", Config{resetOnly: true, PeerInfo: map[string]string{"UV_A\nIV_PROTO": "x"}}, "PeerInfo"},
		{"peer info name that is UV_ only", Config{resetOnly: true, PeerInfo: map[string]string{"UV_": "x"}}, "PeerInfo"},
		{"peer info value with a newline", Config{resetOnly: true, PeerInfo: map[string]string{"UV_A": "x\nIV_PROTO=0"}}, "PeerInfo"},
		{"peer info value with a NUL", Config{resetOnly: true, PeerInfo: map[string]string{"UV_A": "x\x00"}}, "PeerInfo"},
		{"peer info value too long", Config{resetOnly: true, PeerInfo: map[string]string{"UV_A": long}}, "PeerInfo"},
		{"too many peer info variables", Config{resetOnly: true, PeerInfo: manyVariables(peerInfoMaxEntries + 1)}, "PeerInfo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			appErr, ok := errors.FromError(err)
			if !ok || appErr.Tag != tagInvalidConfig || !appErr.HasRoute("Config.validate.InvalidConfig") {
				t.Fatalf("validate = %v, want an invalid config", err)
			}
			if appErr.Metadata["field"] != tt.field {
				t.Errorf("metadata = %v, want field %q", appErr.Metadata, tt.field)
			}
		})
	}
	good := Config{
		resetOnly: true, MTU: 1500, DataCiphers: []string{"aes-192-gcm", "AES-256-GCM"},
		PeerInfo: map[string]string{"UV_Ok_1": strings.Repeat("v", peerInfoMaxValue)},
	}
	if err := good.validate(); err != nil {
		t.Errorf("a good config is refused: %v", err)
	}
	for _, mtu := range []int{minMTU, maxMTU} {
		if err := (&Config{resetOnly: true, MTU: mtu}).validate(); err != nil {
			t.Errorf("MTU %d is refused: %v", mtu, err)
		}
	}
	if err := (&Config{resetOnly: true, PeerInfo: manyVariables(peerInfoMaxEntries)}).validate(); err != nil {
		t.Errorf("%d variables are refused: %v", peerInfoMaxEntries, err)
	}
}

func manyVariables(n int) map[string]string {
	m := map[string]string{}
	for i := 0; i < n; i++ {
		m["UV_"+strings.Repeat("a", i/26)+string(rune('a'+i%26))] = "v"
	}
	return m
}

func TestIsIPv6AndPlatform(t *testing.T) {
	tests := []struct {
		addr net.Addr
		want bool
	}{
		{&net.UDPAddr{IP: net.ParseIP("10.0.0.1")}, false},
		{&net.UDPAddr{IP: net.ParseIP("2001:db8::1")}, true},
		{&net.TCPAddr{IP: net.ParseIP("192.0.2.1")}, false},
		{&net.TCPAddr{IP: net.ParseIP("::1")}, true},
		{&net.UDPAddr{}, false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := isIPv6(tt.addr); got != tt.want {
			t.Errorf("isIPv6(%v) = %v, want %v", tt.addr, got, tt.want)
		}
	}
	want := map[string]string{"linux": "linux", "windows": "win", "darwin": "mac"}[runtime.GOOS]
	if want != "" && platform() != want {
		t.Errorf("platform() = %q on %s, want %q", platform(), runtime.GOOS, want)
	}
}

func TestConnectionState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, _ := tlsPairWith(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert), func(o *vpntest.ServerOptions) {
			o.PushMessages = []string{
				"PUSH_REPLY,topology subnet,ifconfig 10.8.0.5 255.255.255.0,ifconfig-ipv6 fd00::1000/64 fd00::1,route-gateway 10.8.0.1," +
					"route 192.168.50.0 255.255.255.0,route-ipv6 2001:db8::/32,redirect-gateway def1,dhcp-option DNS 10.8.0.1," +
					"dhcp-option DOMAIN corp.example,tun-mtu 1400,ping 10,ping-restart 60,peer-id 3,cipher AES-128-GCM," +
					"auth-token SECRETTOKEN,frobnicate,key-derivation tls-ekm,push-continuation 1",
			}
		})
		conn := PacketClient(link, &Config{
			TLS: NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}}),
			MTU: 1300,
		})
		closeAtEnd(t, conn)

		before := conn.ConnectionState()
		if before.HandshakeComplete || before.MTU != 1300 || before.PeerID != 0xffffff || before.Cipher != "" || before.Addrs != nil {
			t.Errorf("state before the handshake = %+v", before)
		}
		if err := conn.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		st := conn.ConnectionState()
		if !st.HandshakeComplete || st.TLS.Version == 0 || !st.TLS.HandshakeComplete {
			t.Errorf("HandshakeComplete = %v, TLS = %+v", st.HandshakeComplete, st.TLS.Version)
		}
		if st.Cipher != "AES-128-GCM" || st.PeerID != 3 || st.MTU != 1400 || !st.RedirectGateway {
			t.Errorf("cipher %q, peer id %d, MTU %d, redirect %v", st.Cipher, st.PeerID, st.MTU, st.RedirectGateway)
		}
		wantAddrs := []netip.Prefix{netip.MustParsePrefix("10.8.0.5/24"), netip.MustParsePrefix("fd00::1000/64")}
		if !reflect.DeepEqual(st.Addrs, wantAddrs) || st.Gateway != netip.MustParseAddr("10.8.0.1") {
			t.Errorf("addrs %v, gateway %v", st.Addrs, st.Gateway)
		}
		wantRoutes := []Route{{Prefix: netip.MustParsePrefix("192.168.50.0/24")}, {Prefix: netip.MustParsePrefix("2001:db8::/32")}}
		if !reflect.DeepEqual(st.Routes, wantRoutes) {
			t.Errorf("routes = %+v", st.Routes)
		}
		if !reflect.DeepEqual(st.DNSServers, []netip.Addr{netip.MustParseAddr("10.8.0.1")}) || !reflect.DeepEqual(st.SearchDomains, []string{"corp.example"}) {
			t.Errorf("DNS %v, domains %v", st.DNSServers, st.SearchDomains)
		}
		if st.PingInterval != 10*time.Second || st.PingTimeout != time.Minute {
			t.Errorf("ping %v, timeout %v", st.PingInterval, st.PingTimeout)
		}
		if len(st.PushedOptions) != 17 {
			t.Errorf("%d pushed options: %q", len(st.PushedOptions), st.PushedOptions)
		}
		if !slices.Contains(st.PushedOptions, "frobnicate") || !slices.Contains(st.PushedOptions, "auth-token") {
			t.Errorf("pushed options = %q", st.PushedOptions)
		}
		for _, o := range st.PushedOptions {
			if strings.Contains(o, "SECRETTOKEN") {
				t.Errorf("the token is in the pushed options: %q", o)
			}
		}
		// A copy: changing it changes nothing.
		st.Addrs[0] = netip.Prefix{}
		st.PushedOptions[0] = "changed"
		st.DNSServers[0] = netip.Addr{}
		if again := conn.ConnectionState(); again.Addrs[0] != wantAddrs[0] || again.PushedOptions[0] == "changed" || !again.DNSServers[0].IsValid() {
			t.Error("ConnectionState does not return a copy")
		}
	})
}

func TestPushedOptionThatEndsTheHandshake(t *testing.T) {
	tests := []struct {
		reply string
		tag   string
		meta  string
		value string
	}{
		{"PUSH_REPLY,compress lz4", TagUnsupportedPushedOption, "option", "compress"},
		{"PUSH_REPLY,fragment 1200", TagUnsupportedPushedOption, "option", "fragment"},
		{"PUSH_REPLY,cipher AES-256-CBC", TagUnsupportedPushedOption, "option", "cipher"},
		{"PUSH_REPLY,cipher AES-192-GCM", TagCipherNegotiationFailed, "cipher", "AES-192-GCM"},
	}
	for _, tt := range tests {
		t.Run(tt.reply, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pki := servertest.NewPKI(t)
				link, _ := tlsPairWith(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert), func(o *vpntest.ServerOptions) {
					o.PushMessages = []string{tt.reply}
				})
				conn := PacketClient(link, &Config{TLS: NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}})})
				closeAtEnd(t, conn)
				err := conn.HandshakeContext(t.Context())
				appErr, ok := errors.FromError(err)
				if !ok || appErr.Tag != tt.tag || appErr.Metadata[tt.meta] != tt.value {
					t.Fatalf("HandshakeContext = %v, want %s with %s=%s", err, tt.tag, tt.meta, tt.value)
				}
				if conn.ConnectionState().HandshakeComplete {
					t.Error("the state says the handshake is complete")
				}
			})
		})
	}
}

func TestOnlyTheOfferedCiphersAreAccepted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, _ := tlsPairWith(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert), func(o *vpntest.ServerOptions) {
			o.PushMessages = []string{"PUSH_REPLY,cipher AES-128-GCM"}
		})
		conn := PacketClient(link, &Config{
			TLS:         NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}}),
			DataCiphers: []string{"CHACHA20-POLY1305"},
		})
		closeAtEnd(t, conn)
		err := conn.HandshakeContext(t.Context())
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagCipherNegotiationFailed {
			t.Fatalf("HandshakeContext = %v, want %s", err, TagCipherNegotiationFailed)
		}
	})
}

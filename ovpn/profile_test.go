// SPDX-License-Identifier: GPL-2.0-only

package ovpn

import (
	"crypto/tls"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// fixture has the certificates and the keys that a profile needs, as text.
type fixture struct {
	ca, cert, key, tlsAuth, tlsCrypt, v2 string
}

func readText(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func staticKeyText(seed byte) string {
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key (made for the tests)\n#\n-----BEGIN OpenVPN Static key V1-----\n")
	for line := range 16 {
		for i := range 16 {
			fmt.Fprintf(&b, "%02x", byte(line*16+i)+seed)
		}
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	pki := servertest.NewPKI(t)
	return &fixture{
		ca: readText(t, pki.CAFile), cert: readText(t, pki.ClientCertFile), key: readText(t, pki.ClientKeyFile),
		tlsAuth: staticKeyText(1), tlsCrypt: staticKeyText(2), v2: readText(t, "../internal/keys/testdata/tls-crypt-v2-client.key"),
	}
}

// base is a profile with the certificates inline and one remote.
func (f *fixture) base() string {
	return "client\nremote vpn.example.com 1194 udp\n<ca>\n" + f.ca + "</ca>\n<cert>\n" + f.cert + "</cert>\n<key>\n" + f.key + "</key>\n"
}

func parseText(t *testing.T, text string) *Profile {
	t.Helper()
	p, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

// errInfo is what a test looks at of a tagged error besides its tag and route.
type errInfo struct {
	Metadata map[string]any
	Message  string
}

// errMeta checks the tag and the route of an error and returns its metadata.
func errMeta(t *testing.T, err error, tag, route string) errInfo {
	t.Helper()
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not an *errors.Error", err, err)
	}
	if appErr.Tag != tag || !appErr.HasRoute(route) {
		t.Fatalf("tag %s, route %s; want tag %s, route %s", appErr.Tag, appErr.Route(), tag, route)
	}
	return errInfo{Metadata: appErr.Metadata, Message: appErr.Message}
}

// wantErr is errMeta for a test that does not need the metadata.
func wantErr(t *testing.T, err error, tag, route string) {
	t.Helper()
	errMeta(t, err, tag, route)
}

// TestSupportedOptions has one row for each option of the supported table: what it
// is made of, and what the Profile has for it.
func TestSupportedOptions(t *testing.T) {
	f := newFixture(t)
	fp := strings.Repeat("ab", 32)
	fpColons := strings.TrimSuffix(strings.Repeat("ab:", 32), ":")
	rows := []struct {
		option string
		extra  string
		check  func(t *testing.T, p *Profile)
	}{
		{"client", "", func(t *testing.T, p *Profile) {}},
		{"tls-client", "tls-client\n", func(t *testing.T, p *Profile) {}},
		{"pull", "pull\n", func(t *testing.T, p *Profile) {}},
		{"push-peer-info", "push-peer-info\n", func(t *testing.T, p *Profile) {}},
		{"dev", "dev tun\n", func(t *testing.T, p *Profile) {
			if !slices.Contains(p.Ignored, "dev") {
				t.Errorf("Ignored = %v", p.Ignored)
			}
		}},
		{"dev-type", "dev-type tun\n", func(t *testing.T, p *Profile) {}},
		{"remote", "remote 2001:db8::1 443 tcp\n", func(t *testing.T, p *Profile) {
			if len(p.Remotes) != 2 || p.Remotes[1] != (Remote{"tcp", "[2001:db8::1]:443"}) {
				t.Errorf("Remotes = %v", p.Remotes)
			}
		}},
		{"proto", "proto tcp-client\n", func(t *testing.T, p *Profile) {
			if p.Remotes[0].Network != "udp" { // the remote line names its protocol
				t.Errorf("Remotes = %v", p.Remotes)
			}
		}},
		{"port", "port 443\nremote b.example.com\n", func(t *testing.T, p *Profile) {
			if p.Remotes[1].Address != "b.example.com:443" || p.Remotes[0].Address != "vpn.example.com:1194" {
				t.Errorf("Remotes = %v", p.Remotes)
			}
		}},
		{"rport", "rport 4443\nremote b.example.com\n", func(t *testing.T, p *Profile) {
			if p.Remotes[1].Address != "b.example.com:4443" {
				t.Errorf("Remotes = %v", p.Remotes)
			}
		}},
		{"remote-random", "remote-random\n", func(t *testing.T, p *Profile) {
			if !p.RemoteRandom {
				t.Error("RemoteRandom is false")
			}
		}},
		{"connect-timeout", "connect-timeout 7\n", func(t *testing.T, p *Profile) {
			if p.ConnectTimeout != 7*time.Second {
				t.Errorf("ConnectTimeout = %v", p.ConnectTimeout)
			}
		}},
		{"server-poll-timeout", "server-poll-timeout 9\n", func(t *testing.T, p *Profile) {
			if p.ConnectTimeout != 9*time.Second {
				t.Errorf("ConnectTimeout = %v", p.ConnectTimeout)
			}
			for _, name := range p.Ignored {
				if name == "server-poll-timeout" {
					t.Errorf("server-poll-timeout is in Ignored: %v", p.Ignored)
				}
			}
		}},
		{"ca", "", func(t *testing.T, p *Profile) {
			if p.Config.TLS == nil || p.Config.TLS.VerifyConnection == nil {
				t.Error("no verification")
			}
		}},
		{"cert", "", func(t *testing.T, p *Profile) {
			if len(p.Config.TLS.Certificates) != 1 {
				t.Errorf("%d certificates", len(p.Config.TLS.Certificates))
			}
		}},
		{"key", "", func(t *testing.T, p *Profile) {}},
		{"tls-auth", "<tls-auth>\n" + f.tlsAuth + "</tls-auth>\nkey-direction 1\n", func(t *testing.T, p *Profile) {
			if p.Config.ControlWrap == nil {
				t.Error("no control wrap")
			}
		}},
		{"key-direction", "<tls-auth>\n" + f.tlsAuth + "</tls-auth>\nkey-direction bidirectional\n", func(t *testing.T, p *Profile) {
			if p.Config.ControlWrap == nil {
				t.Error("no control wrap")
			}
		}},
		{"tls-crypt", "<tls-crypt>\n" + f.tlsCrypt + "</tls-crypt>\n", func(t *testing.T, p *Profile) {
			if p.Config.ControlWrap == nil {
				t.Error("no control wrap")
			}
		}},
		{"tls-crypt-v2", "<tls-crypt-v2>\n" + f.v2 + "</tls-crypt-v2>\n", func(t *testing.T, p *Profile) {
			if p.Config.ControlWrap == nil {
				t.Error("no control wrap")
			}
		}},
		{"auth", "auth SHA256\n<tls-auth>\n" + f.tlsAuth + "</tls-auth>\n", func(t *testing.T, p *Profile) {
			if p.Config.ControlWrap == nil {
				t.Error("no control wrap")
			}
		}},
		{"auth-user-pass", "<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\n", func(t *testing.T, p *Profile) {
			c, err := p.Config.Credentials(t.Context())
			if err != nil || c.Username != "alice" || c.Password != "secret" || p.NeedsCredentials {
				t.Errorf("credentials %q, error %v, needs %v", c.Username, err, p.NeedsCredentials)
			}
		}},
		{"auth-nocache", "auth-nocache\n", func(t *testing.T, p *Profile) {
			if !p.Config.AuthNoCache {
				t.Error("AuthNoCache is false")
			}
		}},
		{"data-ciphers", "data-ciphers AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC\n", func(t *testing.T, p *Profile) {
			if !slices.Equal(p.Config.DataCiphers, []string{"AES-128-GCM", "CHACHA20-POLY1305"}) || !slices.Contains(p.Ignored, "data-ciphers: AES-256-CBC") {
				t.Errorf("DataCiphers = %v, Ignored = %v", p.Config.DataCiphers, p.Ignored)
			}
		}},
		{"ncp-ciphers", "ncp-ciphers aes-256-gcm\n", func(t *testing.T, p *Profile) {
			if !slices.Equal(p.Config.DataCiphers, []string{"AES-256-GCM"}) {
				t.Errorf("DataCiphers = %v", p.Config.DataCiphers)
			}
		}},
		{"cipher", "cipher AES-192-GCM\n", func(t *testing.T, p *Profile) {
			if !slices.Equal(p.Config.DataCiphers, []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-192-GCM"}) {
				t.Errorf("DataCiphers = %v", p.Config.DataCiphers)
			}
		}},
		{"remote-cert-tls", "remote-cert-tls server\n", func(t *testing.T, p *Profile) {}},
		{"verify-x509-name", "verify-x509-name Server- name-prefix\n", func(t *testing.T, p *Profile) {}},
		{"peer-fingerprint", "peer-fingerprint " + fp + " " + fpColons + "\n", func(t *testing.T, p *Profile) {}},
		{"tls-version-min", "tls-version-min 1.3\n", func(t *testing.T, p *Profile) {
			if p.Config.TLS.MinVersion != tls.VersionTLS13 {
				t.Errorf("MinVersion = %x", p.Config.TLS.MinVersion)
			}
		}},
		{"tls-groups", "tls-groups X25519:secp256r1:SecP256r1MLKEM768\n", func(t *testing.T, p *Profile) {
			want := []tls.CurveID{tls.X25519, tls.CurveP256, tls.SecP256r1MLKEM768}
			if !slices.Equal(p.Config.TLS.CurvePreferences, want) {
				t.Errorf("CurvePreferences = %v", p.Config.TLS.CurvePreferences)
			}
		}},
		{"reneg-sec", "reneg-sec 600\n", func(t *testing.T, p *Profile) {
			if p.Config.RenegotiateAfter != 10*time.Minute {
				t.Errorf("RenegotiateAfter = %v", p.Config.RenegotiateAfter)
			}
		}},
		{"hand-window", "hand-window 90\n", func(t *testing.T, p *Profile) {
			if p.Config.HandshakeTimeout != 90*time.Second {
				t.Errorf("HandshakeTimeout = %v", p.Config.HandshakeTimeout)
			}
		}},
		{"tls-timeout", "tls-timeout 4\n", func(t *testing.T, p *Profile) {
			if p.Config.RetransmitTimeout != 4*time.Second {
				t.Errorf("RetransmitTimeout = %v", p.Config.RetransmitTimeout)
			}
		}},
		{"ping", "ping 10\n", func(t *testing.T, p *Profile) {
			if p.Config.PingInterval != 10*time.Second {
				t.Errorf("PingInterval = %v", p.Config.PingInterval)
			}
		}},
		{"ping-restart", "ping-restart 60\n", func(t *testing.T, p *Profile) {
			if p.Config.PingTimeout != time.Minute {
				t.Errorf("PingTimeout = %v", p.Config.PingTimeout)
			}
		}},
		{"ping-exit", "ping-exit 30\n", func(t *testing.T, p *Profile) {
			if p.Config.PingTimeout != 30*time.Second {
				t.Errorf("PingTimeout = %v", p.Config.PingTimeout)
			}
		}},
		{"keepalive", "keepalive 10 120\n", func(t *testing.T, p *Profile) {
			if p.Config.PingInterval != 10*time.Second || p.Config.PingTimeout != 2*time.Minute {
				t.Errorf("ping %v, ping-restart %v", p.Config.PingInterval, p.Config.PingTimeout)
			}
		}},
		{"tun-mtu", "tun-mtu 1400\n", func(t *testing.T, p *Profile) {
			if p.Config.MTU != 1400 {
				t.Errorf("MTU = %d", p.Config.MTU)
			}
		}},
		{"explicit-exit-notify", "explicit-exit-notify 3\n", func(t *testing.T, p *Profile) {
			if !slices.Contains(p.Ignored, "explicit-exit-notify: tries beyond the first") {
				t.Errorf("Ignored = %v", p.Ignored)
			}
		}},
		{"setenv", "setenv UV_ROLE admin\nsetenv UV_EMPTY\nsetenv FOR_SCRIPTS 1\n", func(t *testing.T, p *Profile) {
			if p.Config.PeerInfo["UV_ROLE"] != "admin" || p.Config.PeerInfo["UV_EMPTY"] != "" || len(p.Config.PeerInfo) != 2 || !slices.Contains(p.Ignored, "setenv") {
				t.Errorf("PeerInfo = %v, Ignored = %v", p.Config.PeerInfo, p.Ignored)
			}
		}},
		{"ignore-unknown-option", "ignore-unknown-option some-new-option\nsome-new-option 1\n", func(t *testing.T, p *Profile) {
			if !slices.Contains(p.Ignored, "some-new-option") {
				t.Errorf("Ignored = %v", p.Ignored)
			}
		}},
		{"pull-filter", "pull-filter accept \"route 192.168.1.\"\npull-filter ignore \"route \"\npull-filter reject compress\n", func(t *testing.T, p *Profile) {
			want := []openvpn.PullFilter{{Action: openvpn.PullAccept, Prefix: "route 192.168.1."}, {Action: openvpn.PullIgnore, Prefix: "route "}, {Action: openvpn.PullReject, Prefix: "compress"}}
			if !slices.Equal(p.Config.PullFilters, want) {
				t.Errorf("PullFilters = %+v", p.Config.PullFilters)
			}
		}},
		{"route-nopull", "route-nopull\n", func(t *testing.T, p *Profile) {
			if !p.Config.RouteNoPull {
				t.Error("RouteNoPull is false")
			}
		}},
	}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.option] = true
		t.Run(row.option, func(t *testing.T) {
			p := parseText(t, f.base()+row.extra)
			if p.Config == nil || len(p.Remotes) == 0 {
				t.Fatalf("Profile = %+v", p)
			}
			row.check(t, p)
		})
	}
	// Every option of the table has a row.
	for name := range handlers() {
		if !seen[name] {
			t.Errorf("the supported option %q has no row", name)
		}
	}
}

func TestEveryOptionIsInOneTable(t *testing.T) {
	supported := handlers()
	for name := range supported {
		if ignoredOptions[name] {
			t.Errorf("%q is supported and ignored", name)
		}
		if _, ok := refusedOptions[name]; ok {
			t.Errorf("%q is supported and refused", name)
		}
	}
	for name := range ignoredOptions {
		if _, ok := refusedOptions[name]; ok {
			t.Errorf("%q is ignored and refused", name)
		}
	}
	for _, name := range inlineOptions {
		if _, ok := supported[name]; !ok {
			t.Errorf("the inline option %q is not supported", name)
		}
	}
}

func TestIgnoredOptions(t *testing.T) {
	f := newFixture(t)
	var names []string
	for name := range ignoredOptions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			p := parseText(t, f.base()+name+" 1 2 3\n"+name+" again\n")
			if n := strings.Count(strings.Join(p.Ignored, ","), name); n != 1 || p.Ignored[len(p.Ignored)-1] != name {
				t.Errorf("Ignored = %v: %q should be there once", p.Ignored, name)
			}
		})
	}
}

func TestRefusedOptions(t *testing.T) {
	f := newFixture(t)
	var names []string
	for name := range refusedOptions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(f.base() + name + " x\n"))
			appErr := errMeta(t, err, TagUnsupportedOption, "apply.UnsupportedOption")
			wantLine := strings.Count(f.base(), "\n") + 1
			if appErr.Metadata["option"] != name || appErr.Metadata["line"] != wantLine || appErr.Metadata["reason"] == "" {
				t.Errorf("metadata %v, want the option %q at line %d with a reason", appErr.Metadata, name, wantLine)
			}
		})
	}
	other := []struct {
		name, text string
	}{
		{"dev tap", "dev tap\n"}, {"dev tap0", "dev tap0\n"}, {"dev-type tap", "dev-type tap\n"},
		{"remote-cert-tls client", "remote-cert-tls client\n"},
		{"tls-version-min 1.1", "tls-version-min 1.1\n"}, {"tls-version-min 1.0", "tls-version-min 1.0\n"},
		{"a group that crypto/tls does not have", "tls-groups X448\n"},
		{"a cipher that is not AEAD and no data-ciphers", "cipher AES-256-CBC\n"},
		{"an option in a connection block", "<connection>\nremote a\ntls-auth x\n</connection>\n"},
		{"a block inside a connection block", "<connection>\nremote a\n<ca>\n</ca>\n</connection>\n"},
		{"compression under setenv opt", "setenv opt compress lz4\n"},
	}
	for _, tt := range other {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(f.base() + tt.text))
			wantErr(t, err, TagUnsupportedOption, "UnsupportedOption")
		})
	}
	t.Run("a digest of tls-auth that is not supported", func(t *testing.T) {
		_, err := Parse(strings.NewReader(f.base() + "auth MD5\n<tls-auth>\n" + f.tlsAuth + "</tls-auth>\n"))
		wantErr(t, err, TagUnsupportedOption, "finish->builder.makeWrap.UnsupportedOption")
	})
}

func TestUnknownOptions(t *testing.T) {
	f := newFixture(t)
	_, err := Parse(strings.NewReader(f.base() + "frobnicate 1\n"))
	appErr := errMeta(t, err, TagUnsupportedOption, "apply.UnsupportedOption")
	if appErr.Metadata["option"] != "frobnicate" || appErr.Metadata["line"] != strings.Count(f.base(), "\n")+1 {
		t.Errorf("metadata %v", appErr.Metadata)
	}
	// ignore-unknown-option lets it pass, wherever it is in the profile.
	p := parseText(t, f.base()+"frobnicate 1\nignore-unknown-option frobnicate other\n")
	if !slices.Contains(p.Ignored, "frobnicate") {
		t.Errorf("Ignored = %v", p.Ignored)
	}
	// It does not make a known option unknown, nor a refused one allowed.
	if _, err := Parse(strings.NewReader(f.base() + "ignore-unknown-option compress\ncompress lz4\n")); err == nil {
		t.Error("compress was allowed by ignore-unknown-option")
	}
	// setenv opt: applied when known, left out when not.
	p = parseText(t, f.base()+"setenv opt ping 5\nsetenv opt future-option 1 2\nsetenv opt verb 5\n")
	if p.Config.PingInterval != 5*time.Second || !slices.Contains(p.Ignored, "future-option") || !slices.Contains(p.Ignored, "verb") {
		t.Errorf("PingInterval %v, Ignored %v", p.Config.PingInterval, p.Ignored)
	}
	// An option name with the dashes of the command line.
	p = parseText(t, f.base()+"--ping 7\n")
	if p.Config.PingInterval != 7*time.Second {
		t.Errorf("--ping: %v", p.Config.PingInterval)
	}
}

func TestBadOptions(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name, text, route string
	}{
		{"remote without a host", "remote\n", "apply.BadOption"},
		{"remote with four arguments", "remote a 1 udp x\n", "apply.BadOption"},
		{"remote with a port that is not a number", "remote a http\n", "builder.hRemote.BadOption"},
		{"remote with a port of 0", "remote a 0\n", "builder.hRemote.BadOption"},
		{"remote with a port that is too large", "remote a 70000\n", "builder.hRemote.BadOption"},
		{"remote with a protocol that a client cannot use", "remote a 1 tcp-server\n", "builder.hRemote.BadOption"},
		{"remote with an empty host", "remote \"\"\n", "builder.hRemote.BadOption"},
		{"proto that is not known", "proto sctp\n", "builder.hProto.BadOption"},
		{"proto tcp-server", "proto tcp-server\n", "builder.hProto.BadOption"},
		{"a port that is not a number", "port x\n", "builder.hPort.BadOption"},
		{"connect-timeout of 0", "connect-timeout 0\n", "builder.hConnectTimeout.BadOption"},
		{"connect-timeout that is negative", "connect-timeout -1\n", "builder.hConnectTimeout.BadOption"},
		{"reneg-sec that is not a number", "reneg-sec soon\n", "builder.hRenegSec.BadOption"},
		{"hand-window of 0", "hand-window 0\n", "builder.hHandWindow.BadOption"},
		{"tls-timeout of 0", "tls-timeout 0\n", "builder.hTLSTimeout.BadOption"},
		{"ping that is not a number", "ping x\n", "builder.hPing.BadOption"},
		{"ping-restart that is negative", "ping-restart -5\n", "builder.hPingRestart.BadOption"},
		{"ping-exit that is not a number", "ping-exit x\n", "builder.hPingExit.BadOption"},
		{"keepalive with a word", "keepalive 10 x\n", "builder.hKeepalive.BadOption"},
		{"keepalive with one argument", "keepalive 10\n", "apply.BadOption"},
		{"tun-mtu that is not a number", "tun-mtu big\n", "builder.hTunMTU.BadOption"},
		{"explicit-exit-notify of 0", "explicit-exit-notify 0\n", "builder.hExplicitExitNotify.BadOption"},
		{"pull-filter with an action that is not known", "pull-filter drop route\n", "builder.hPullFilter.BadOption"},
		{"pull-filter with one argument", "pull-filter ignore\n", "apply.BadOption"},
		{"key-direction that is not known", "key-direction 2\n", "builder.hKeyDirection.BadOption"},
		{"tls-auth with a direction that is not known", "tls-auth key.txt 2\n", "builder.hWrap.BadOption"},
		{"remote-cert-tls with a word that is not known", "remote-cert-tls both\n", "builder.hRemoteCertTLS.BadOption"},
		{"verify-x509-name with a type that is not known", "verify-x509-name a other\n", "builder.hVerifyName.BadOption"},
		{"verify-x509-name with an empty name", "verify-x509-name \"\"\n", "builder.hVerifyName.BadOption"},
		{"peer-fingerprint that is short", "peer-fingerprint abcd\n", "builder.hFingerprint.BadOption"},
		{"peer-fingerprint that is not hexadecimal", "peer-fingerprint " + strings.Repeat("zz", 32) + "\n", "builder.hFingerprint.BadOption"},
		{"peer-fingerprint with odd colons", "peer-fingerprint " + strings.Repeat("ab", 16) + ":" + strings.Repeat("ab", 16) + "\n", "builder.hFingerprint.BadOption"},
		{"tls-version-min that is not known", "tls-version-min 2.0\n", "builder.hTLSVersionMin.BadOption"},
		{"tls-version-min with a second word that is not known", "tls-version-min 1.2 or-lowest\n", "builder.hTLSVersionMin.BadOption"},
		{"tls-groups that is empty", "tls-groups :\n", "builder.hTLSGroups.BadOption"},
		{"data-ciphers with none that the library has", "data-ciphers AES-256-CBC:BF-CBC\n", "finish->builder.makeCiphers.BadOption"},
		{"ping-restart and ping-exit together", "ping-restart 10\nping-exit 20\n", "finish.BadOption"},
		{"a file name with Parse", "tls-crypt x\n", "builder.text.FileUnavailable"},
		{"an inline block for an option that cannot be one", "<ping>\n10\n</ping>\n", "apply.BadOption"},
		{"a connection block without a remote", "<connection>\nproto tcp\n</connection>\n", "builder.connection.BadOption"},
		{"a port in a connection block that is wrong", "<connection>\nremote a\nport x\n</connection>\n", "builder.hPort.BadOption"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(f.base() + tt.text))
			appErr, ok := errors.FromError(err)
			if !ok || !appErr.HasRoute(tt.route) {
				t.Fatalf("error %v, route %v; want route %s", err, appErr, tt.route)
			}
			if strings.Contains(fmt.Sprint(appErr.Metadata), f.key) {
				t.Error("a key is in the metadata")
			}
		})
	}
	t.Run("two protections", func(t *testing.T) {
		_, err := Parse(strings.NewReader(f.base() + "<tls-crypt>\n" + f.tlsCrypt + "</tls-crypt>\n<tls-auth>\n" + f.tlsAuth + "</tls-auth>\n"))
		wantErr(t, err, TagBadOption, "builder.hWrap.BadOption")
	})
}

func TestMissingAndBadFiles(t *testing.T) {
	f := newFixture(t)
	caOnly := "client\nremote h 1\n<ca>\n" + f.ca + "</ca>\n"
	tests := []struct {
		name, text, tag, route string
	}{
		{"no ca and no fingerprint", "client\nremote h 1\n", TagMissingOption, "finish.MissingOption"},
		{"a cert without a key", caOnly + "<cert>\n" + f.cert + "</cert>\n", TagMissingOption, "finish.MissingOption"},
		{"a key without a cert", caOnly + "<key>\n" + f.key + "</key>\n", TagMissingOption, "finish.MissingOption"},
		{"a ca with no certificate", "client\nremote h 1\n<ca>\nnot a certificate\n</ca>\n", TagBadFile, "builder.rootPool.BadProfileFile"},
		{"a cert and a key that do not make a pair", caOnly + "<cert>\n" + f.cert + "</cert>\n<key>\n" + strings.Replace(f.key, "A", "B", 3) + "</key>\n", TagBadFile, "finish.BadProfileFile"},
		{"an encrypted key", caOnly + "<cert>\n" + f.cert + "</cert>\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nxx\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n", TagBadFile, "finish.BadProfileFile"},
		{"an old encrypted key", caOnly + "<cert>\n" + f.cert + "</cert>\n<key>\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nxx\n-----END RSA PRIVATE KEY-----\n</key>\n", TagBadFile, "finish.BadProfileFile"},
		{"a tls-crypt that is not a key", f.base() + "<tls-crypt>\nnothing\n</tls-crypt>\n", TagBadFile, "builder.makeWrap.BadProfileFile"},
		{"a tls-auth that is not a key", f.base() + "<tls-auth>\nnothing\n</tls-auth>\n", TagBadFile, "builder.makeWrap.BadProfileFile"},
		{"a tls-crypt-v2 that is not a key", f.base() + "<tls-crypt-v2>\nnothing\n</tls-crypt-v2>\n", TagBadFile, "builder.makeWrap.BadProfileFile"},
		{"credentials with no password", f.base() + "<auth-user-pass>\nalice\n</auth-user-pass>\n", TagBadFile, "builder.hAuthUserPass.BadProfileFile"},
		{"credentials with no user name", f.base() + "<auth-user-pass>\n\nsecret\n</auth-user-pass>\n", TagBadFile, "builder.hAuthUserPass.BadProfileFile"},
		{"a file name with Parse", f.base() + "tls-crypt ta.key\n", TagFileUnavailable, "builder.text.FileUnavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.text))
			appErr := errMeta(t, err, tt.tag, tt.route)
			for _, secret := range []string{"secret", f.key} {
				if strings.Contains(fmt.Sprint(appErr.Metadata, appErr.Message), secret) {
					t.Errorf("a secret is in the error: %v", appErr.Metadata)
				}
			}
		})
	}
}

func TestSyntaxErrorsPassThrough(t *testing.T) {
	_, err := Parse(strings.NewReader("client\nremote \"h\n"))
	appErr := errMeta(t, err, TagSyntax, "words.ProfileSyntax")
	if appErr.Metadata["line"] != 2 {
		t.Errorf("metadata %v", appErr.Metadata)
	}
}

func TestRemotes(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name, text string
		want       []Remote
	}{
		{"the defaults", "remote a\n", []Remote{{"udp", "a:1194"}}},
		{"the defaults of the profile", "proto tcp\nport 443\nremote a\nremote b 8443\nremote c 1194 udp6\n", []Remote{{"tcp", "a:443"}, {"tcp", "b:8443"}, {"udp6", "c:1194"}}},
		{"defaults that come after the remote", "remote a\nproto tcp-client\nport 4443\n", []Remote{{"tcp", "a:4443"}}},
		{"every protocol", "remote a 1 udp\nremote a 1 udp4\nremote a 1 udp6\nremote a 1 tcp\nremote a 1 tcp4\nremote a 1 tcp6\nremote a 1 tcp-client\nremote a 1 tcp4-client\nremote a 1 tcp6-client\n",
			[]Remote{{"udp", "a:1"}, {"udp4", "a:1"}, {"udp6", "a:1"}, {"tcp", "a:1"}, {"tcp4", "a:1"}, {"tcp6", "a:1"}, {"tcp", "a:1"}, {"tcp4", "a:1"}, {"tcp6", "a:1"}}},
		{"an IPv6 address", "remote 2001:db8::1\nremote ::1 2000\n", []Remote{{"udp", "[2001:db8::1]:1194"}, {"udp", "[::1]:2000"}}},
		{"connection blocks", "<connection>\nremote a 7000\nproto tcp\n</connection>\n<connection>\nremote b\nport 9000\n</connection>\nremote c\nport 1111\nproto udp\n",
			[]Remote{{"tcp", "a:7000"}, {"udp", "b:9000"}, {"udp", "c:1111"}}},
		{"a connection block does not change the defaults of the others", "<connection>\nremote a\nproto tcp\nport 7\n</connection>\nremote b\n", []Remote{{"tcp", "a:7"}, {"udp", "b:1194"}}},
		{"two remotes in a block", "<connection>\nremote a\nremote b\nproto tcp\n</connection>\n", []Remote{{"tcp", "a:1194"}, {"tcp", "b:1194"}}},
		{"ignored options in a connection block", "<connection>\nremote a\nnobind\nconnect-retry 5\n</connection>\n", []Remote{{"udp", "a:1194"}}},
		{"no remote at all", "", nil},
	}
	body := "<ca>\n" + f.ca + "</ca>\n"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := parseText(t, body+tt.text)
			if !slices.Equal(p.Remotes, tt.want) {
				t.Errorf("Remotes = %v, want %v", p.Remotes, tt.want)
			}
		})
	}
	// An error in a connection block says the line of the file.
	_, err := Parse(strings.NewReader(body + "client\n<connection>\nremote a\nport x\n</connection>\n"))
	appErr := errMeta(t, err, TagBadOption, "builder.hPort.BadOption")
	if want := strings.Count(body, "\n") + 4; appErr.Metadata["line"] != want {
		t.Errorf("line %v, want %d", appErr.Metadata["line"], want)
	}
}

func TestProfileDefaults(t *testing.T) {
	f := newFixture(t)
	p := parseText(t, f.base())
	if p.ConnectTimeout != DefaultConnectTimeout || p.RemoteRandom || p.NeedsCredentials || len(p.Ignored) != 0 {
		t.Errorf("Profile = %+v", p)
	}
	c := p.Config
	if c.RenegotiateAfter != 0 || c.HandshakeTimeout != 0 || c.PingInterval != 0 || c.PingTimeout != 0 || c.MTU != 0 || c.DataCiphers != nil || c.ControlWrap != nil || c.Credentials != nil {
		t.Errorf("Config = %+v: what the profile does not say is the default of the library", c)
	}
}

func TestRenegSecZeroTurnsItOff(t *testing.T) {
	f := newFixture(t)
	if p := parseText(t, f.base()+"reneg-sec 0\n"); p.Config.RenegotiateAfter >= 0 {
		t.Errorf("RenegotiateAfter = %v, want negative", p.Config.RenegotiateAfter)
	}
}

func TestAuthUserPass(t *testing.T) {
	f := newFixture(t)
	p := parseText(t, f.base()+"auth-user-pass\n")
	if !p.NeedsCredentials || p.Config.Credentials != nil {
		t.Errorf("NeedsCredentials %v, Credentials set %v", p.NeedsCredentials, p.Config.Credentials != nil)
	}
	p = parseText(t, f.base()+"<auth-user-pass>\r\nalice \r\n pass word\r\n</auth-user-pass>\r\n")
	c, err := p.Config.Credentials(t.Context())
	if err != nil || c.Username != "alice " || c.Password != " pass word" {
		t.Errorf("credentials %q %q, error %v: the lines are kept as they are, without their line ends", c.Username, c.Password, err)
	}
	// An auth-user-pass with no file, and then a file or an inline one, is not a request for the caller.
	p = parseText(t, f.base()+"auth-user-pass\n<auth-user-pass>\na\nb\n</auth-user-pass>\n")
	if p.NeedsCredentials || p.Config.Credentials == nil {
		t.Error("the credentials of the profile were not taken")
	}
}

func TestCiphers(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name, text string
		want       []string
	}{
		{"none", "", nil},
		{"data-ciphers only", "data-ciphers CHACHA20-POLY1305:AES-128-GCM\n", []string{"CHACHA20-POLY1305", "AES-128-GCM"}},
		{"a repeated cipher", "data-ciphers AES-128-GCM:aes-128-gcm\n", []string{"AES-128-GCM"}},
		{"the cipher is the last offer", "data-ciphers AES-128-GCM\ncipher AES-256-GCM\n", []string{"AES-128-GCM", "AES-256-GCM"}},
		{"the cipher is already there", "data-ciphers AES-256-GCM:AES-128-GCM\ncipher AES-256-GCM\n", []string{"AES-256-GCM", "AES-128-GCM"}},
		{"a cipher that is not AEAD next to data-ciphers", "data-ciphers AES-128-GCM\ncipher AES-256-CBC\n", []string{"AES-128-GCM"}},
		{"the cipher is one of the defaults", "cipher chacha20-poly1305\n", []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := parseText(t, f.base()+tt.text)
			if !slices.Equal(p.Config.DataCiphers, tt.want) {
				t.Errorf("DataCiphers = %v, want %v", p.Config.DataCiphers, tt.want)
			}
		})
	}
}

func TestFingerprintsInABlock(t *testing.T) {
	f := newFixture(t)
	a, b := strings.Repeat("11", 32), strings.TrimSuffix(strings.Repeat("22:", 32), ":")
	p := parseText(t, "<ca>\n"+f.ca+"</ca>\nremote h\n<peer-fingerprint>\n"+a+"\n"+b+"\n</peer-fingerprint>\n")
	if p.Config.TLS == nil {
		t.Fatal("no TLS configuration")
	}
	// A profile with a fingerprint and no ca is complete.
	if _, err := Parse(strings.NewReader("remote h\npeer-fingerprint " + a + "\n")); err != nil {
		t.Errorf("a fingerprint and no ca: %v", err)
	}
	_, err := Parse(strings.NewReader("remote h\n<peer-fingerprint>\n</peer-fingerprint>\n"))
	wantErr(t, err, TagBadOption, "builder.hFingerprint.BadOption")
}

func TestConfigOfAProfileIsValid(t *testing.T) {
	f := newFixture(t)
	// A value out of range is found when the profile is read, with the error of the Config.
	_, err := Parse(strings.NewReader(f.base() + "tun-mtu 100\n"))
	appErr, ok := errors.FromError(err)
	if !ok || appErr.Tag != "InvalidConfig" || appErr.Metadata["field"] != "MTU" {
		t.Errorf("error %v", err)
	}
}

func TestParseFS(t *testing.T) {
	f := newFixture(t)
	profile := "client\nremote vpn.example.com 1194\nca ca.crt\ncert certs/client.crt\nkey \"certs/client.key\"\ntls-crypt ta.key\nauth-user-pass login.txt\n"
	fsys := fstest.MapFS{
		"vpn/client.ovpn":       {Data: []byte(profile)},
		"vpn/ca.crt":            {Data: []byte(f.ca)},
		"vpn/certs/client.crt":  {Data: []byte(f.cert)},
		"vpn/certs/client.key":  {Data: []byte(f.key)},
		"vpn/ta.key":            {Data: []byte(f.tlsCrypt)},
		"vpn/login.txt":         {Data: []byte("alice\nsecret\n")},
		"secret.txt":            {Data: []byte("outside the directory of the profile\n")},
		"vpn/certs/other/x.key": {Data: []byte("x")},
	}
	p, err := ParseFS(fsys, "vpn/client.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.ControlWrap == nil || len(p.Config.TLS.Certificates) != 1 || p.Config.Credentials == nil {
		t.Errorf("Config = %+v", p.Config)
	}
	if c, _ := p.Config.Credentials(t.Context()); c.Username != "alice" || c.Password != "secret" {
		t.Errorf("credentials %q", c.Username)
	}

	// A profile in the root of the file system.
	root := fstest.MapFS{"c.ovpn": {Data: []byte("remote h\nca ca.crt\n")}, "ca.crt": {Data: []byte(f.ca)}}
	if _, err := ParseFS(root, "c.ovpn"); err != nil {
		t.Errorf("a profile in the root: %v", err)
	}

	refusals := []struct {
		name, option string
	}{
		{"an absolute name", "ca /etc/openvpn/ca.crt"},
		{"a name that climbs out of the directory", "ca ../secret.txt"},
		{"a name that climbs out and comes back", "ca certs/../../secret.txt"},
		{"a name of Windows with backslashes", `ca C:\\vpn\\ca.crt`},
		{"a name with a backslash path", `ca certs\\client.crt`},
		{"a file that is not there", "ca missing.crt"},
		{"a directory", "ca certs"},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			fsys["vpn/bad.ovpn"] = &fstest.MapFile{Data: []byte("remote h\n" + tt.option + "\n")}
			_, err := ParseFS(fsys, "vpn/bad.ovpn")
			appErr := errMeta(t, err, TagFileUnavailable, "FileUnavailable")
			if appErr.Metadata["option"] != "ca" || appErr.Metadata["line"] != 2 {
				t.Errorf("metadata %v", appErr.Metadata)
			}
		})
	}
	// A file system that records what is opened shows that nothing else is read.
	rec := &recordingFS{files: fsys}
	if _, err := ParseFS(rec, "vpn/client.ovpn"); err != nil {
		t.Fatal(err)
	}
	for _, name := range rec.opened {
		if !strings.HasPrefix(name, "vpn/") {
			t.Errorf("%q was opened: only the directory of the profile is read", name)
		}
	}
	if len(rec.opened) != 6 {
		t.Errorf("opened %v, want the profile and its 5 files", rec.opened)
	}
	// The profile that is not there, and one that cannot be read.
	_, err = ParseFS(fsys, "vpn/none.ovpn")
	wantErr(t, err, TagReadFailed, "ParseFS.ProfileReadFailed")
}

// recordingFS is a file system that remembers the names that are opened in it.
type recordingFS struct {
	files  fstest.MapFS
	opened []string
}

func (r *recordingFS) Open(name string) (fs.File, error) {
	r.opened = append(r.opened, name)
	return r.files.Open(name)
}

func TestInlineFilesAreNotLookedForOnDisk(t *testing.T) {
	// Parse never touches the disk: a file name that exists in the current directory is
	// still refused.
	_, err := Parse(strings.NewReader("remote h\nca profile.go\n"))
	wantErr(t, err, TagFileUnavailable, "builder.text.FileUnavailable")
}

func TestSecretsAreNotInTheErrors(t *testing.T) {
	f := newFixture(t)
	secret := "hunter2-secret-password"
	_, err := Parse(strings.NewReader(f.base() + "<auth-user-pass>\nalice\n" + secret + "\n</auth-user-pass>\nping x\n"))
	appErr, ok := errors.FromError(err)
	if !ok || strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprint(appErr.Metadata), secret) {
		t.Errorf("error %v", err)
	}
}

func FuzzParse(f *testing.F) {
	fx := newFixture(f)
	base := fx.base()
	for _, s := range []string{
		base,
		base + "tls-auth ta.key 1\n",
		base + "<tls-crypt>\n" + fx.tlsCrypt + "</tls-crypt>\nkeepalive 10 60\nreneg-sec 0\npull-filter ignore \"route \"\n",
		base + "<tls-crypt-v2>\n" + fx.v2 + "</tls-crypt-v2>\n<auth-user-pass>\na\nb\n</auth-user-pass>\n",
		base + "<connection>\nremote a 1 tcp\n</connection>\npeer-fingerprint " + strings.Repeat("ab:", 31) + "ab\n",
		"remote h\npeer-fingerprint " + strings.Repeat("00", 32) + "\nverify-x509-name n name-prefix\ntls-groups X25519\n",
		"setenv opt unknown 1\nsetenv UV_A b\nignore-unknown-option x\nx\n",
		"<connection>\n<ca>\n</connection>",
		"remote \"\nport 0\n",
	} {
		f.Add(s)
	}
	known := []string{
		TagSyntax, TagProfileTooLarge, TagReadFailed, TagUnsupportedOption, TagBadOption, TagMissingOption,
		TagFileUnavailable, TagBadFile, "InvalidConfig",
	}
	f.Fuzz(func(t *testing.T, in string) {
		p, err := Parse(strings.NewReader(in))
		if err != nil {
			appErr, ok := errors.FromError(err)
			if !ok || !slices.Contains(known, appErr.Tag) {
				t.Fatalf("an error with no tag of the parser: %v", err)
			}
			return
		}
		if p.Config == nil || p.Config.Validate() != nil || p.ConnectTimeout <= 0 {
			t.Fatalf("a profile that is not usable: %+v", p)
		}
		for _, r := range p.Remotes {
			if r.Address == "" || networkName(r.Network) == "" {
				t.Fatalf("a remote that cannot be dialed: %+v", r)
			}
		}
	})
}

func networkName(n string) string {
	switch n {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		return n
	}
	return ""
}

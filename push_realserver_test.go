// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package openvpn

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

func dialPush(t *testing.T, proto string, extra ...string) (*Conn, *servertest.Server, error) {
	t.Helper()
	srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: append([]string{"--verb", "4"}, extra...)})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := Dial(ctx, proto, srv.Addr(), &Config{TLS: tlsConfigFor(srv.PKI)})
	if conn != nil {
		t.Cleanup(func() {
			if err := conn.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
	return conn, srv, err
}

// TestPushWithRealServer: ConnectionState has what a real server pushes, over UDP
// and TCP, with IPv4 and IPv6.
func TestPushWithRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			conn, srv, err := dialPush(t, proto,
				"--push", "route 192.168.50.0 255.255.255.0",
				"--push", "dhcp-option DNS 10.8.0.1",
				"--push", "dhcp-option DOMAIN corp.example",
				"--keepalive", "10", "60",
				"--server-ipv6", "fd00::/64",
			)
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			st := conn.ConnectionState()
			if !st.HandshakeComplete {
				t.Fatal("the handshake is not complete")
			}
			t.Logf("pushed options: %q", st.PushedOptions)
			if want := netip.MustParsePrefix("10.8.0.2/24"); len(st.Addrs) == 0 || st.Addrs[0] != want {
				t.Errorf("addrs = %v, want %v first", st.Addrs, want)
			}
			if !slices.ContainsFunc(st.Addrs, func(p netip.Prefix) bool { return p.Addr().Is6() && p.Bits() == 64 }) {
				t.Errorf("addrs = %v: no IPv6 address", st.Addrs)
			}
			if st.Gateway != netip.MustParseAddr("10.8.0.1") {
				t.Errorf("gateway = %v", st.Gateway)
			}
			if !slices.ContainsFunc(st.Routes, func(r Route) bool { return r.Prefix == netip.MustParsePrefix("192.168.50.0/24") }) {
				t.Errorf("routes = %+v", st.Routes)
			}
			if !slices.Contains(st.DNSServers, netip.MustParseAddr("10.8.0.1")) || !slices.Contains(st.SearchDomains, "corp.example") {
				t.Errorf("DNS %v, domains %v", st.DNSServers, st.SearchDomains)
			}
			if st.PingInterval != 10*time.Second || st.PingTimeout != 60*time.Second {
				t.Errorf("ping %v, timeout %v", st.PingInterval, st.PingTimeout)
			}
			if st.Cipher != "AES-256-GCM" || st.MTU == 0 || st.PeerID == undefinedPeerID {
				t.Errorf("cipher %q, MTU %d, peer id %d", st.Cipher, st.MTU, st.PeerID)
			}
			if !slices.Contains(st.PushedOptions, "route 192.168.50.0 255.255.255.0") {
				t.Errorf("the pushed options lack the route: %q", st.PushedOptions)
			}
		})
	}
}

// TestPushInPartsWithRealServer: a reply that is longer than one control message
// comes in parts, and all of them are taken.
func TestPushInPartsWithRealServer(t *testing.T) {
	const routes = 120
	var extra []string
	for i := 0; i < routes; i++ {
		extra = append(extra, "--push", fmt.Sprintf("route 10.%d.0.0 255.255.0.0", 100+i))
	}
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			conn, srv, err := dialPush(t, proto, extra...)
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			st := conn.ConnectionState()
			if len(st.Routes) != routes {
				t.Errorf("%d routes, want %d", len(st.Routes), routes)
			}
			srv.WaitLog(t, "push-continuation 2", 2*time.Second)
			if st.Cipher == "" || len(st.Addrs) == 0 {
				t.Errorf("the options of the last part are lost: cipher %q, addrs %v", st.Cipher, st.Addrs)
			}
		})
	}
}

// TestPushedCompressionIsRefused: a server that pushes compression ends the
// handshake with TagUnsupportedPushedOption.
func TestPushedCompressionIsRefused(t *testing.T) {
	_, srv, err := dialPush(t, "udp", "--push", "compress lz4")
	appErr, ok := errors.FromError(err)
	if !ok || appErr.Tag != TagUnsupportedPushedOption || appErr.Metadata["option"] != "compress" {
		t.Fatalf("Dial = %v, want %s\nserver log:\n%s", err, TagUnsupportedPushedOption, srv.Log())
	}
}

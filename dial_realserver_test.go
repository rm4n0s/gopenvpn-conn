// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package openvpn

import (
	"context"
	"crypto"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

func readKeyFile(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// serverSetup is one protection of the control channel, on the server and in
// the client's Config.
type serverSetup struct {
	name string
	// make returns the options of the server and the ControlWrap of the client.
	make func(t *testing.T) (extra []string, wrap ControlWrap)
	// v2 is true for tls-crypt-v2: over UDP the third packet is a CONTROL_WKC_V1.
	v2 bool
}

func serverSetups() []serverSetup {
	return []serverSetup{
		{name: "no protection", make: func(t *testing.T) ([]string, ControlWrap) { return nil, nil }},
		{name: "tls-auth SHA-1", make: func(t *testing.T) ([]string, ControlWrap) {
			file := servertest.GenKey(t, "tls-auth")
			wrap, err := NewTLSAuth(readKeyFile(t, file), KeyDirection1, crypto.SHA1)
			if err != nil {
				t.Fatal(err)
			}
			return []string{"--tls-auth", file, "0"}, wrap
		}},
		{name: "tls-auth SHA-256", make: func(t *testing.T) ([]string, ControlWrap) {
			file := servertest.GenKey(t, "tls-auth")
			wrap, err := NewTLSAuth(readKeyFile(t, file), KeyDirection1, crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			return []string{"--auth", "SHA256", "--tls-auth", file, "0"}, wrap
		}},
		{name: "tls-crypt", make: func(t *testing.T) ([]string, ControlWrap) {
			file := servertest.GenKey(t, "tls-crypt")
			wrap, err := NewTLSCrypt(readKeyFile(t, file))
			if err != nil {
				t.Fatal(err)
			}
			return []string{"--tls-crypt", file}, wrap
		}},
		{name: "tls-crypt-v2", v2: true, make: func(t *testing.T) ([]string, ControlWrap) {
			server := servertest.GenKey(t, "tls-crypt-v2-server")
			client := servertest.GenTLSCryptV2ClientKey(t, server)
			wrap, err := NewTLSCryptV2(readKeyFile(t, client))
			if err != nil {
				t.Fatal(err)
			}
			return []string{"--tls-crypt-v2", server}, wrap
		}},
	}
}

// TestDialWithRealServer gets past the exchange of resets with a real server,
// over UDP and TCP, with every protection of the control channel. The server's
// log (verb 7) shows what it made of our third packet.
func TestDialWithRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		for _, setup := range serverSetups() {
			t.Run(proto+"/"+setup.name, func(t *testing.T) {
				extra, wrap := setup.make(t)
				srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: append([]string{"--verb", "7"}, extra...)})
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				conn, err := Dial(ctx, proto, srv.Addr(), &Config{ControlWrap: wrap, resetOnly: true})
				if err != nil {
					t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
				}
				defer func() {
					if err := conn.Close(); err != nil {
						t.Errorf("Close: %v", err)
					}
				}()
				if conn.RemoteAddr().String() != srv.Addr() {
					t.Errorf("RemoteAddr = %v, want %v", conn.RemoteAddr(), srv.Addr())
				}
				switch {
				case proto == "tcp":
					// The server keeps a connection per client and starts the
					// session at the reset.
					srv.WaitLog(t, "TLS: Initial packet from", 3*time.Second)
					srv.WaitLog(t, "P_ACK_V1 kid=0", 3*time.Second)
				case setup.v2:
					// The server asked for the wrapped key again: our third
					// packet is a CONTROL_WKC_V1.
					srv.WaitLog(t, "Valid packet (P_CONTROL_WKC_V1) with HMAC challenge", 3*time.Second)
				default:
					srv.WaitLog(t, "Valid packet (P_ACK_V1) with HMAC challenge", 3*time.Second)
					srv.WaitLog(t, "P_ACK_V1 kid=0", 3*time.Second)
				}
			})
		}
	}
}

// TestDialWithTheWrongKey: a client with another tls-crypt key gets no answer,
// and the server says why.
func TestDialWithTheWrongKey(t *testing.T) {
	serverKey := servertest.GenKey(t, "tls-crypt")
	clientKey := servertest.GenKey(t, "tls-crypt")
	wrap, err := NewTLSCrypt(readKeyFile(t, clientKey))
	if err != nil {
		t.Fatal(err)
	}
	srv := servertest.Start(t, servertest.Options{Extra: []string{"--verb", "7", "--tls-crypt", serverKey}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := Dial(ctx, "udp", srv.Addr(), &Config{ControlWrap: wrap, HandshakeTimeout: 3 * time.Second, resetOnly: true})
	if conn != nil {
		t.Fatal("Dial returned a connection with the wrong key")
	}
	appErr, ok := errors.FromError(err)
	if !ok || appErr.Tag != TagHandshakeTimeout {
		t.Fatalf("Dial = %v, want %s", err, TagHandshakeTimeout)
	}
	if elapsed := time.Since(start); elapsed < 3*time.Second || elapsed > 6*time.Second {
		t.Errorf("Dial failed after %v, want about 3s", elapsed)
	}
	srv.WaitLog(t, "tls-crypt unwrap error: packet authentication failed", 2*time.Second)
	if strings.Contains(srv.Log(), "sending HMAC based reset challenge") {
		t.Error("the server took our reset for a valid one")
	}
}

// TestDialRefused: nobody listens on the port of a TCP server that is gone.
func TestDialRefused(t *testing.T) {
	srv := servertest.Start(t, servertest.Options{Proto: "tcp"})
	addr := srv.Addr()
	srv.Stop(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Dial(ctx, "tcp", addr, nil)
	appErr, ok := errors.FromError(err)
	if !ok || appErr.Tag != TagDialFailed || !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("Dial = %v, want %s with ECONNREFUSED", err, TagDialFailed)
	}
}

// TestDialNextAddressWithRealServer dials a name over UDP whose first two addresses
// have no server: 127.0.0.3, where the port is closed (the kernel answers the first
// packet with an ICMP error, which ends the attempt), and 192.0.2.1, where nothing
// answers at all (the namespace has no route to it, or the packet is lost: the
// attempt ends by the dial or by ServerPollTimeout). The server is at the third.
func TestDialNextAddressWithRealServer(t *testing.T) {
	srv := servertest.Start(t, servertest.Options{Proto: "udp"})
	_, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	d := &Dialer{
		Config: &Config{TLS: tlsConfigFor(srv.PKI), ServerPollTimeout: 2 * time.Second},
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")}, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := d.Dial(ctx, "udp", net.JoinHostPort("vpn.test", port))
	if err != nil {
		t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	if got := conn.RemoteAddr().String(); got != srv.Addr() {
		t.Errorf("connected to %s, want the third address, %s", got, srv.Addr())
	}
	t.Logf("the third address answered after %v", time.Since(start).Round(time.Millisecond))
}

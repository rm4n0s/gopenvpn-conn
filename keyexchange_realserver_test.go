// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package openvpn

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// authScript writes a script for --auth-user-pass-verify (via-file) that
// accepts one user name and password, and returns the server options that run it
// with /bin/sh (the file need not be executable).
func authScript(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.sh")
	script := "#!/bin/sh\n# $1 is a file: the user name on the first line, the password on the second.\n" +
		"[ \"$(sed -n 1p \"$1\")\" = alice ] && [ \"$(sed -n 2p \"$1\")\" = s3cret ]\n"
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"--verb", "7", "--script-security", "2", "--auth-user-pass-verify", "/bin/sh " + path, "via-file", "--username-as-common-name"}
}

// TestKeyExchangeWithRealServer sends the key exchange message to a real server
// that checks a user name and password, and shows what the server read.
func TestKeyExchangeWithRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto+"/the right password", func(t *testing.T) {
			srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: authScript(t)})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := Dial(ctx, proto, srv.Addr(), &Config{
				TLS: tlsConfigFor(srv.PKI),
				Credentials: func(context.Context) (Credentials, error) {
					return Credentials{Username: "alice", Password: "s3cret"}, nil
				},
				PeerInfo: map[string]string{"UV_FROM": "gopenvpn-conn tests"},
			})
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			}()
			if kx := conn.s.ServerKeyExchange(); kx == nil || kx.Options == "" {
				t.Errorf("the server's message was not read: %+v", kx)
			}
			// What the server read, and what it decided.
			srv.WaitLog(t, "peer info: IV_VER=gopenvpn-conn_0.2.0", 3*time.Second)
			srv.WaitLog(t, "IV_PROTO=286", 3*time.Second)
			srv.WaitLog(t, "IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", 3*time.Second)
			srv.WaitLog(t, "UV_FROM=gopenvpn-conn_tests", 3*time.Second)
			srv.WaitLog(t, "authentication succeeded for username 'alice'", 3*time.Second)
		})
		t.Run(proto+"/a wrong password", func(t *testing.T) {
			srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: authScript(t)})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := Dial(ctx, proto, srv.Addr(), &Config{
				TLS: tlsConfigFor(srv.PKI),
				Credentials: func(context.Context) (Credentials, error) {
					return Credentials{Username: "alice", Password: "wrong"}, nil
				},
			})
			if err == nil {
				if cerr := conn.Close(); cerr != nil {
					t.Errorf("Close: %v", cerr)
				}
				t.Fatalf("Dial with a wrong password succeeded\nserver log:\n%s", srv.Log())
			}
			appErr, ok := errors.FromError(err)
			if !ok || appErr.Tag != TagAuthFailed {
				t.Fatalf("Dial = %v, want %s\nserver log:\n%s", err, TagAuthFailed, srv.Log())
			}
			if !strings.HasSuffix(appErr.Route(), "control.AuthFailed") {
				t.Errorf("route = %s", appErr.Route())
			}
			t.Logf("the server's reason: %q", appErr.Metadata["reason"])
			srv.WaitLog(t, "verification failed", 3*time.Second)
			for _, line := range strings.Split(srv.Log(), "\n") {
				if strings.Contains(line, "verification failed") {
					t.Log(line) // the evidence for the entry of IMPLEMENTED.md
				}
			}
		})
	}
}

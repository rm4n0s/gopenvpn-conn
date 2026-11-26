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

// authScriptEnv is authScript for a user name and a password of letters and digits
// of any length: the script gets them in its environment, because the file of
// via-file takes lines of 512 bytes at most, and the user name is not made the
// common name, which has 64.
func authScriptEnv(t *testing.T, user, pass string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.sh")
	script := "#!/bin/sh\n[ \"$username\" = " + user + " ] && [ \"$password\" = " + pass + " ]\n"
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"--verb", "7", "--script-security", "3", "--auth-user-pass-verify", "/bin/sh " + path, "via-env"}
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
			srv.WaitLog(t, "peer info: IV_VER=gopenvpn-conn_"+libraryVersion, 3*time.Second)
			srv.WaitLog(t, "IV_PROTO=1950", 3*time.Second)
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
			// The TLS goroutine of the Conn read the server's AUTH_FAILED; the route begins
			// at the Dial that started the Conn.
			if !appErr.HasRoute("Dial->Dialer.Dial->Conn.HandshakeContext->Session.Handshake->Session.start->Session.startTLS->Session.startTLS.func1->Session.tlsMain->Session.controlLoop->Session.control.AuthFailed") {
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

// TestLongCredentialsWithRealServer logs in with a user name and a password that
// are longer than 127 bytes (the limit of an OpenVPN that is built without PKCS#11),
// and long enough for crypto/tls to cut the message in two records if it were let
// to: the server reads one record of the key exchange message.
func TestLongCredentialsWithRealServer(t *testing.T) {
	user, pass := strings.Repeat("u", 200), strings.Repeat("p", 1100)
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: authScriptEnv(t, user, pass)})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := Dial(ctx, proto, srv.Addr(), &Config{
				TLS: tlsConfigFor(srv.PKI),
				Credentials: func(context.Context) (Credentials, error) {
					return Credentials{Username: user, Password: pass}, nil
				},
				PeerInfo: map[string]string{"UV_FROM": "the long login"},
			})
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			}()
			srv.WaitLog(t, "authentication succeeded for username '"+user+"'", 3*time.Second)
			srv.WaitLog(t, "UV_FROM=the_long_login", 3*time.Second) // the peer info comes after the password
		})
	}
}

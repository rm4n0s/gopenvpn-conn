// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// TestPingForWindowsUnderWine builds the example for Windows and runs it under Wine
// against a real OpenVPN server (started here, on the loopback of the namespace), over
// UDP and TCP with tls-crypt: the client library, for Windows, in a real tunnel. Wine
// uses the network of the namespace, so the Windows program reaches the server. The
// output of the program is in the test log.
func TestPingForWindowsUnderWine(t *testing.T) {
	if _, err := exec.LookPath("wine"); err != nil {
		t.Skip("wine is not installed")
	}
	bin := filepath.Join(t.TempDir(), "ping.exe")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(build.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build for windows: %v\n%s", err, out)
	}
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			key := servertest.GenKey(t, "tls-crypt")
			srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: []string{"--tls-crypt", key}})
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			out, err := servertest.RunWine(ctx, t, bin,
				"-server", srv.Addr(), "-proto", proto, "-ca", srv.PKI.CAFile,
				"-cert", srv.PKI.ClientCertFile, "-key", srv.PKI.ClientKeyFile, "-tls-crypt", key, "-count", "3")
			t.Logf("output of ping.exe over %s under Wine:\n%s", proto, out)
			if err != nil {
				t.Fatalf("ping.exe failed: %v\nserver log:\n%s", err, srv.Log())
			}
			if n := strings.Count(string(out), " bytes from "); n != 3 {
				t.Errorf("%d replies, want 3", n)
			}
		})
	}
}

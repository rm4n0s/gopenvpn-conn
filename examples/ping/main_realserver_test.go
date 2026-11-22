// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package main

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// TestPingWithRealServer starts a real OpenVPN server, builds the example and runs it
// against the server with the files of the server's certificates and a tls-crypt key,
// over UDP and TCP, as a user would. The output of the program is in the test log.
func TestPingWithRealServer(t *testing.T) {
	bin := t.TempDir() + "/ping"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			key := servertest.GenKey(t, "tls-crypt")
			srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: []string{"--tls-crypt", key}})
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin,
				"-server", srv.Addr(), "-proto", proto, "-ca", srv.PKI.CAFile,
				"-cert", srv.PKI.ClientCertFile, "-key", srv.PKI.ClientKeyFile, "-tls-crypt", key, "-count", "3")
			cmd.WaitDelay = 5 * time.Second
			out, err := cmd.CombinedOutput()
			t.Logf("output of the example over %s:\n%s", proto, out)
			if err != nil {
				t.Fatalf("the example failed: %v\nserver log:\n%s", err, srv.Log())
			}
			if n := strings.Count(string(out), " bytes from "); n != 3 {
				t.Errorf("%d replies, want 3", n)
			}
		})
	}
}

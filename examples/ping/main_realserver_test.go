// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

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

// TestPingInterruptedWithRealServer stops the example with an interrupt signal (what
// Ctrl-C sends) in the middle of its pings: it exits with the status of an
// interrupted program, and the server has the client's goodbye, so the tunnel was
// closed and not dropped.
func TestPingInterruptedWithRealServer(t *testing.T) {
	bin := t.TempDir() + "/ping"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	srv := servertest.Start(t, servertest.Options{Proto: "udp", Extra: []string{"--verb", "4", "--keepalive", "60", "120"}})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-server", srv.Addr(), "-proto", "udp", "-ca", srv.PKI.CAFile,
		"-cert", srv.PKI.ClientCertFile, "-key", srv.PKI.ClientKeyFile, "-count", "1000")
	cmd.WaitDelay = 5 * time.Second
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(out.String(), " bytes from ") {
		if time.Now().After(deadline) {
			t.Fatalf("no reply in time; output:\n%s\nserver log:\n%s", out.String(), srv.Log())
		}
		time.Sleep(50 * time.Millisecond)
	}
	start := time.Now()
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	t.Logf("the example exited %v after the signal; its output:\n%s", time.Since(start).Round(time.Millisecond), out.String())
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 130 {
		t.Errorf("the example ended with %v, want the exit status 130", err)
	}
	if !strings.Contains(out.String(), "interrupted") {
		t.Error("the example did not say that it was interrupted")
	}
	srv.WaitLog(t, "CC-EEN exit message received by peer", 3*time.Second)
}

// syncBuffer is a buffer that the program writes and the test reads at the same time.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

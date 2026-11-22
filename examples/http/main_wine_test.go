// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// TestHTTPForWindowsUnderWine is TestHTTPWithRealServer for the Windows build of the
// example, run under Wine: the profile parser, the tunnel and the userspace network
// (gVisor's stack) on Windows, against a real server.
func TestHTTPForWindowsUnderWine(t *testing.T) {
	if _, err := exec.LookPath("wine"); err != nil {
		t.Skip("wine is not installed")
	}
	bin := filepath.Join(t.TempDir(), "http.exe")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(build.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build for windows: %v\n%s", err, out)
	}
	key := servertest.GenKey(t, "tls-crypt")
	srv := servertest.Start(t, servertest.Options{Extra: []string{"--tls-crypt", key}})

	web, err := net.Listen("tcp4", net.JoinHostPort(srv.TunnelIP().String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(strings.Repeat("0123456789", 100_000))); err != nil {
			t.Logf("write: %v", err)
		}
	})}
	go func() {
		if err := server.Serve(web); err != nil && err != http.ErrServerClosed {
			t.Logf("Serve: %v", err)
		}
	}()
	defer func() {
		if err := server.Close(); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	}()

	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	host, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	profile := "client\nnobind\nremote-cert-tls server\nremote " + host + " " + port + " udp\n" +
		"<ca>\n" + read(srv.PKI.CAFile) + "</ca>\n<cert>\n" + read(srv.PKI.ClientCertFile) + "</cert>\n" +
		"<key>\n" + read(srv.PKI.ClientKeyFile) + "</key>\n<tls-crypt>\n" + read(key) + "</tls-crypt>\n"
	profilePath := filepath.Join(t.TempDir(), "client.ovpn")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	url := "http://" + web.Addr().String() + "/"
	out, err := servertest.RunWine(ctx, t, bin, "-profile", profilePath, "-url", url)
	t.Logf("output of http.exe under Wine:\n%s", out)
	if err != nil {
		t.Fatalf("http.exe failed: %v\nserver log:\n%s", err, srv.Log())
	}
	if want := url + ": 200 OK, 1000000 bytes"; !strings.Contains(string(out), want) {
		t.Errorf("the output has no %q", want)
	}
}

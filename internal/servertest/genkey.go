// SPDX-License-Identifier: GPL-2.0-only

//go:build linux

package servertest

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// GenKey makes a key file with `openvpn --genkey kind` in the directory of the
// test and returns its path. kind is "tls-auth", "tls-crypt" or
// "tls-crypt-v2-server". It skips the test when openvpn is not installed; it
// needs no namespace.
func GenKey(t testing.TB, kind string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), kind+".key")
	runOpenVPN(t, "--genkey", kind, path)
	return path
}

// GenTLSCryptV2ClientKey makes a tls-crypt-v2 client key for the server key in
// serverKeyFile, and returns its path.
func GenTLSCryptV2ClientKey(t testing.TB, serverKeyFile string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tls-crypt-v2-client.key")
	runOpenVPN(t, "--tls-crypt-v2", serverKeyFile, "--genkey", "tls-crypt-v2-client", path)
	return path
}

func runOpenVPN(t testing.TB, args ...string) {
	t.Helper()
	if _, err := exec.LookPath("openvpn"); err != nil {
		t.Skip("servertest: openvpn is not installed")
	}
	if out, err := exec.Command("openvpn", args...).CombinedOutput(); err != nil {
		t.Fatalf("servertest: openvpn %v: %v\n%s", args, err, out)
	}
}

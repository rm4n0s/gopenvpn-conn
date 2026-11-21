// SPDX-License-Identifier: GPL-2.0-only

//go:build linux

package servertest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenKey(t *testing.T) {
	// These run the real openvpn but need no namespace.
	tests := []struct {
		kind  string
		begin string
	}{
		{"tls-auth", "-----BEGIN OpenVPN Static key V1-----"},
		{"tls-crypt", "-----BEGIN OpenVPN Static key V1-----"},
		{"tls-crypt-v2-server", "-----BEGIN OpenVPN tls-crypt-v2 server key-----"},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			path := GenKey(t, tt.kind)
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tt.begin) {
				t.Errorf("the key file has no %q:\n%s", tt.begin, data)
			}
		})
	}
}

func TestGenTLSCryptV2ClientKey(t *testing.T) {
	server := GenKey(t, "tls-crypt-v2-server")
	path := GenTLSCryptV2ClientKey(t, server)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "-----BEGIN OpenVPN tls-crypt-v2 client key-----") {
		t.Errorf("not a client key:\n%s", data)
	}
}

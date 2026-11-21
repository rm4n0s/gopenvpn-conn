// SPDX-License-Identifier: GPL-2.0-only

package servertest

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatalf("%s is not one PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestNewPKI(t *testing.T) {
	p := NewPKI(t)

	ca := readCert(t, p.CAFile)
	server := readCert(t, p.ServerCertFile)
	client := readCert(t, p.ClientCertFile)

	tests := []struct {
		name   string
		cert   *x509.Certificate
		usage  x509.ExtKeyUsage
		cn     string
		dnsFor string
	}{
		{"server", server, x509.ExtKeyUsageServerAuth, "server", "server"},
		{"client", client, x509.ExtKeyUsageClientAuth, "client", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cert.Subject.CommonName != tt.cn {
				t.Errorf("common name = %q, want %q", tt.cert.Subject.CommonName, tt.cn)
			}
			opts := x509.VerifyOptions{Roots: p.CAPool, KeyUsages: []x509.ExtKeyUsage{tt.usage}, DNSName: tt.dnsFor}
			if _, err := tt.cert.Verify(opts); err != nil {
				t.Errorf("does not verify against the CA for %v: %v", tt.usage, err)
			}
			// Each certificate is good for its own use only.
			other := x509.ExtKeyUsageClientAuth
			if tt.usage == x509.ExtKeyUsageClientAuth {
				other = x509.ExtKeyUsageServerAuth
			}
			if _, err := tt.cert.Verify(x509.VerifyOptions{Roots: p.CAPool, KeyUsages: []x509.ExtKeyUsage{other}}); err == nil {
				t.Errorf("also verifies for %v, want it refused", other)
			}
		})
	}
	if !ca.IsCA {
		t.Error("the CA certificate is not a CA")
	}
	if !p.CACert.Equal(ca) {
		t.Error("CACert is not the certificate in CAFile")
	}
}

func TestPKIFilesLoad(t *testing.T) {
	p := NewPKI(t)
	for name, files := range map[string][2]string{
		"server": {p.ServerCertFile, p.ServerKeyFile},
		"client": {p.ClientCertFile, p.ClientKeyFile},
	} {
		if _, err := tls.LoadX509KeyPair(files[0], files[1]); err != nil {
			t.Errorf("%s certificate and key do not make a pair: %v", name, err)
		}
	}
	if len(p.ClientCert.Certificate) != 1 || p.ClientCert.PrivateKey == nil {
		t.Errorf("ClientCert is not a certificate with its key: %+v", p.ClientCert)
	}
	if len(p.ServerCert.Certificate) != 1 || p.ServerCert.PrivateKey == nil {
		t.Errorf("ServerCert is not a certificate with its key: %+v", p.ServerCert)
	}
	// Windows has no file modes of this kind.
	if info, err := os.Stat(p.ServerKeyFile); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Errorf("the server key file must be mode 0600: %v %v", info, err)
	}
}

func TestPKIsAreDifferent(t *testing.T) {
	a, b := NewPKI(t), NewPKI(t)
	if a.CACert.Equal(b.CACert) {
		t.Error("two PKIs have the same CA")
	}
	if _, err := readCert(t, b.ServerCertFile).Verify(x509.VerifyOptions{Roots: a.CAPool}); err == nil {
		t.Error("a server certificate verifies against the CA of another PKI")
	}
}

func TestPKIWithALargeClientCertificate(t *testing.T) {
	small := NewPKI(t)
	large := NewPKIWith(t, PKIOptions{ClientCertNames: 60})
	smallSize, largeSize := len(small.ClientCert.Certificate[0]), len(large.ClientCert.Certificate[0])
	if largeSize < 10000 || largeSize < 10*smallSize {
		t.Errorf("the large certificate is %d bytes (the small one %d), want at least 10000", largeSize, smallSize)
	}
	cert, err := x509.ParseCertificate(large.ClientCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: large.CAPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the large client certificate does not verify: %v", err)
	}
}

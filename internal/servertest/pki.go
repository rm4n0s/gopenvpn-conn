// SPDX-License-Identifier: GPL-2.0-only

//go:build linux

package servertest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// PKI is a certificate authority, a server certificate and a client
// certificate, made for one test with ECDSA P-256 and written as PEM files.
// The keys are made for tests and are never used for anything else.
type PKI struct {
	Dir string // the directory of the files

	CAFile         string
	ServerCertFile string
	ServerKeyFile  string
	ClientCertFile string
	ClientKeyFile  string

	CACert     *x509.Certificate
	CAPool     *x509.CertPool // trusts only CACert
	ClientCert tls.Certificate
}

// NewPKI makes a PKI in a directory that is removed when the test ends. The
// server certificate has the server auth usage, the common name "server", the
// DNS name "server" and the address 127.0.0.1; the client certificate has the
// client auth usage and the common name "client".
func NewPKI(t testing.TB) *PKI {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()

	caKey := newKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: "gopenvpn-conn test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER := sign(t, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("servertest: parse the CA certificate: %v", err)
	}

	serverKey := newKey(t)
	serverDER := sign(t, &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: "server"},
		DNSNames:              []string{"server"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, caCert, &serverKey.PublicKey, caKey)

	clientKey := newKey(t)
	clientDER := sign(t, &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: "client"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, caCert, &clientKey.PublicKey, caKey)

	p := &PKI{
		Dir:            dir,
		CAFile:         filepath.Join(dir, "ca.crt"),
		ServerCertFile: filepath.Join(dir, "server.crt"),
		ServerKeyFile:  filepath.Join(dir, "server.key"),
		ClientCertFile: filepath.Join(dir, "client.crt"),
		ClientKeyFile:  filepath.Join(dir, "client.key"),
		CACert:         caCert,
		CAPool:         x509.NewCertPool(),
	}
	p.CAPool.AddCert(caCert)
	writePEM(t, p.CAFile, "CERTIFICATE", caDER)
	writePEM(t, p.ServerCertFile, "CERTIFICATE", serverDER)
	writePEM(t, p.ServerKeyFile, "PRIVATE KEY", marshalKey(t, serverKey))
	writePEM(t, p.ClientCertFile, "CERTIFICATE", clientDER)
	writePEM(t, p.ClientKeyFile, "PRIVATE KEY", marshalKey(t, clientKey))
	p.ClientCert = tls.Certificate{
		Certificate: [][]byte{clientDER},
		PrivateKey:  clientKey,
	}
	return p
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("servertest: make a key: %v", err)
	}
	return key
}

func newSerial(t testing.TB) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("servertest: make a serial number: %v", err)
	}
	return serial
}

func sign(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("servertest: make a certificate: %v", err)
	}
	return der
}

func marshalKey(t testing.TB, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("servertest: encode a key: %v", err)
	}
	return der
}

func writePEM(t testing.TB, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("servertest: write %s: %v", filepath.Base(path), err)
	}
}

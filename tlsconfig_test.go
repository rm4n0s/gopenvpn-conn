// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// selfSigned makes a certificate with the subject and the usages, valid from
// notBefore for a day, and returns it as a connection state shows it.
func selfSigned(t *testing.T, subject pkix.Name, usages []x509.ExtKeyUsage, notBefore time.Time) (tls.ConnectionState, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: subject, NotBefore: notBefore, NotAfter: notBefore.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, cert
}

func fingerprint(c *x509.Certificate) [sha256.Size]byte { return sha256.Sum256(c.Raw) }

func wantTLSRoute(t *testing.T, err error, tag, route string) {
	t.Helper()
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not an *errors.Error", err, err)
	}
	if appErr.Tag != tag || !appErr.HasRoute(route) {
		t.Fatalf("tag %s, route %s; want tag %s, route %s", appErr.Tag, appErr.Route(), tag, route)
	}
}

func TestVerifyServerName(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	name := pkix.Name{Country: []string{"KG"}, Province: []string{"NA"}, Locality: []string{"Bishkek"}, CommonName: "Server-1"}
	cs, cert := selfSigned(t, name, nil, now)
	pin := [][sha256.Size]byte{fingerprint(cert)}
	tests := []struct {
		name  string
		opts  TLSOptions
		match bool
	}{
		{"the whole subject", TLSOptions{VerifyName: "C=KG, ST=NA, L=Bishkek, CN=Server-1"}, true},
		{"another subject", TLSOptions{VerifyName: "C=KG, ST=NA, L=Bishkek, CN=Server-2"}, false},
		{"a part of the subject is not the subject", TLSOptions{VerifyName: "CN=Server-1"}, false},
		{"the common name", TLSOptions{VerifyName: "Server-1", VerifyNameMatch: MatchCommonName}, true},
		{"another common name", TLSOptions{VerifyName: "Server-", VerifyNameMatch: MatchCommonName}, false},
		{"a prefix of the common name", TLSOptions{VerifyName: "Server-", VerifyNameMatch: MatchCommonNamePrefix}, true},
		{"the whole common name as a prefix", TLSOptions{VerifyName: "Server-1", VerifyNameMatch: MatchCommonNamePrefix}, true},
		{"not a prefix", TLSOptions{VerifyName: "erver", VerifyNameMatch: MatchCommonNamePrefix}, false},
		{"a prefix longer than the name", TLSOptions{VerifyName: "Server-10", VerifyNameMatch: MatchCommonNamePrefix}, false},
		{"no name asked for", TLSOptions{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.PeerFingerprints = pin // a certificate that is trusted by its fingerprint, to test the name alone
			err := verifyServer(&tt.opts, cs)
			if tt.match {
				if err != nil {
					t.Fatalf("verifyServer = %v", err)
				}
				return
			}
			wantTLSRoute(t, err, TagServerNameMismatch, "verifyServer->checkName.ServerNameMismatch")
		})
	}
}

func TestVerifyServerNameWritesTheSubjectLikeOpenSSL(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	tests := []struct {
		name   string
		in     pkix.Name
		want   string
		common string
	}{
		{"the usual attributes", pkix.Name{Country: []string{"US"}, Organization: []string{"Example"}, OrganizationalUnit: []string{"VPN"}, CommonName: "vpn.example.com"},
			"C=US, O=Example, OU=VPN, CN=vpn.example.com", "vpn.example.com"},
		{"control characters are escaped", pkix.Name{CommonName: "a\tb\x7f"}, `CN=a\09b\7F`, "a\tb\x7f"},
		{"two common names: the last one counts", pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: oidCommonName, Value: "first"}, {Type: oidCommonName, Value: "second"}}}, "CN=first, CN=second", "second"},
		{"an attribute with no short name", pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{Type: []int{1, 2, 3, 4}, Value: "x"}}, CommonName: "c"},
			"CN=c, 1.2.3.4=x", "c"},
		{"an email address", pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{Type: []int{1, 2, 840, 113549, 1, 9, 1}, Value: "me@example.com"}}, CommonName: "c"},
			"CN=c, emailAddress=me@example.com", "c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cert := selfSigned(t, tt.in, nil, now)
			subject, common, err := subjectNames(cert)
			if err != nil {
				t.Fatal(err)
			}
			// pkix.Name writes ExtraNames after the fixed attributes.
			if subject != tt.want || common != tt.common {
				t.Errorf("subject %q, common name %q; want %q and %q", subject, common, tt.want, tt.common)
			}
		})
	}
}

func TestVerifyServerNameRefusals(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	_, cert := selfSigned(t, pkix.Name{CommonName: "a\x00b"}, nil, now)
	_, _, err := subjectNames(cert)
	wantTLSRoute(t, err, TagServerNameUnreadable, "subjectNames.ServerNameUnreadable")
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	o := &TLSOptions{VerifyName: "a", PeerFingerprints: [][sha256.Size]byte{fingerprint(cert)}}
	wantTLSRoute(t, verifyServer(o, cs), TagServerNameUnreadable, "verifyServer->checkName->subjectNames.ServerNameUnreadable")

	broken := &x509.Certificate{RawSubject: []byte{0x30, 0x03, 0x01}} // a sequence that is cut
	_, _, err = subjectNames(broken)
	wantTLSRoute(t, err, TagServerNameUnreadable, "subjectNames.ServerNameUnreadable")
}

func TestVerifyServerFingerprints(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	cs, cert := selfSigned(t, pkix.Name{CommonName: "server"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now)
	_, other := selfSigned(t, pkix.Name{CommonName: "other"}, nil, now)
	pool := x509.NewCertPool()
	pool.AddCert(cert) // it is its own authority

	t.Run("the fingerprint of the certificate is enough with no CA", func(t *testing.T) {
		if err := verifyServer(&TLSOptions{PeerFingerprints: [][sha256.Size]byte{fingerprint(cert)}}, cs); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("one of several", func(t *testing.T) {
		if err := verifyServer(&TLSOptions{PeerFingerprints: [][sha256.Size]byte{fingerprint(other), fingerprint(cert)}}, cs); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("another fingerprint", func(t *testing.T) {
		err := verifyServer(&TLSOptions{PeerFingerprints: [][sha256.Size]byte{fingerprint(other)}}, cs)
		wantTLSRoute(t, err, TagServerFingerprintMismatch, "verifyServer.ServerFingerprintMismatch")
	})
	t.Run("the CA is checked too when there is one", func(t *testing.T) {
		o := &TLSOptions{PeerFingerprints: [][sha256.Size]byte{fingerprint(cert)}, RootCAs: pool}
		if err := verifyServer(o, cs); err != nil {
			t.Fatal(err)
		}
		o.RootCAs = x509.NewCertPool() // another authority
		if err := verifyServer(o, cs); err == nil {
			t.Error("a certificate that no authority signed was accepted because of its fingerprint")
		}
	})
	t.Run("no fingerprint and no CA means the system's roots, which do not know the certificate", func(t *testing.T) {
		if err := verifyServer(&TLSOptions{}, cs); err == nil {
			t.Error("a self-signed certificate was accepted with no authority")
		}
	})
	t.Run("a pinned certificate must be valid now", func(t *testing.T) {
		old, oldCert := selfSigned(t, pkix.Name{CommonName: "old"}, nil, time.Now().Add(-72*time.Hour))
		if err := verifyServer(&TLSOptions{PeerFingerprints: [][sha256.Size]byte{fingerprint(oldCert)}}, old); err == nil {
			t.Error("an expired pinned certificate was accepted")
		}
		future, futureCert := selfSigned(t, pkix.Name{CommonName: "future"}, nil, time.Now().Add(72*time.Hour))
		if err := verifyServer(&TLSOptions{PeerFingerprints: [][sha256.Size]byte{fingerprint(futureCert)}}, future); err == nil {
			t.Error("a pinned certificate that is not valid yet was accepted")
		}
	})
	t.Run("a pinned certificate must be for a server when the profile says so", func(t *testing.T) {
		client, clientCert := selfSigned(t, pkix.Name{CommonName: "client"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now)
		o := &TLSOptions{PeerFingerprints: [][sha256.Size]byte{fingerprint(clientCert)}}
		if err := verifyServer(o, client); err != nil {
			t.Errorf("without remote-cert-tls: %v", err)
		}
		o.RemoteCertTLSServer = true
		if err := verifyServer(o, client); err == nil {
			t.Error("a client certificate was taken for a server's")
		}
		// No extended key usage at all, and any usage, pass as they do in crypto/x509.
		none, noneCert := selfSigned(t, pkix.Name{CommonName: "none"}, nil, now)
		if err := verifyServer(&TLSOptions{PeerFingerprints: [][sha256.Size]byte{fingerprint(noneCert)}, RemoteCertTLSServer: true}, none); err != nil {
			t.Errorf("no extended key usage: %v", err)
		}
		anyUse, anyCert := selfSigned(t, pkix.Name{CommonName: "any"}, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, now)
		if err := verifyServer(&TLSOptions{PeerFingerprints: [][sha256.Size]byte{fingerprint(anyCert)}, RemoteCertTLSServer: true}, anyUse); err != nil {
			t.Errorf("any usage: %v", err)
		}
	})
	t.Run("no certificate at all", func(t *testing.T) {
		if err := verifyServer(&TLSOptions{}, tls.ConnectionState{}); err == nil {
			t.Error("a server with no certificate was accepted")
		}
	})
}

func TestVerifyServerWithTheChainOfAnAuthority(t *testing.T) {
	pki := servertest.NewPKI(t)
	server := tls.ConnectionState{PeerCertificates: []*x509.Certificate{mustParse(t, pki.ServerCert.Certificate[0])}}
	client := tls.ConnectionState{PeerCertificates: []*x509.Certificate{mustParse(t, pki.ClientCert.Certificate[0])}}
	if err := verifyServer(&TLSOptions{RootCAs: pki.CAPool, RemoteCertTLSServer: true, VerifyName: "server", VerifyNameMatch: MatchCommonName}, server); err != nil {
		t.Fatal(err)
	}
	if err := verifyServer(&TLSOptions{RootCAs: pki.CAPool, RemoteCertTLSServer: true}, client); err == nil {
		t.Error("a certificate for clients was taken as a server's")
	}
	if err := verifyServer(&TLSOptions{RootCAs: pki.CAPool}, client); err != nil {
		t.Errorf("without remote-cert-tls the usage is not checked: %v", err)
	}
	// The name is checked after the chain and does not stand in for it.
	other := servertest.NewPKI(t)
	if err := verifyServer(&TLSOptions{RootCAs: other.CAPool, VerifyName: "server", VerifyNameMatch: MatchCommonName}, server); err == nil {
		t.Error("the name of a certificate that no authority signed was enough")
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewTLSConfigGroups(t *testing.T) {
	cfg := NewTLSConfig(TLSOptions{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
	if len(cfg.CurvePreferences) != 2 || cfg.CurvePreferences[0] != tls.X25519 {
		t.Errorf("CurvePreferences = %v", cfg.CurvePreferences)
	}
	if NewTLSConfig(TLSOptions{}).CurvePreferences != nil {
		t.Error("groups that nobody asked for")
	}
}

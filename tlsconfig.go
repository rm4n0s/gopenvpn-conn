// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl_verify.c and doc/man-sections/tls-options.rst (--remote-cert-tls, --ca) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package openvpn

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rm4n0s/errors"
)

// NameMatch is how TLSOptions.VerifyName is compared with the server's certificate
// (the type of verify-x509-name).
type NameMatch int

const (
	// MatchSubject compares the whole subject, written as OpenVPN writes it: the
	// attributes in the order of the certificate as short-name=value, separated by a
	// comma and a space (for example "C=KG, ST=NA, L=Bishkek, CN=Server-1").
	MatchSubject NameMatch = iota
	// MatchCommonName compares the common name (type name).
	MatchCommonName
	// MatchCommonNamePrefix takes a common name that starts with the name (type
	// name-prefix).
	MatchCommonNamePrefix
)

// TLSOptions say how NewTLSConfig builds the TLS configuration of a client, in
// the terms of the options of an OpenVPN profile.
type TLSOptions struct {
	// RootCAs are the authorities that sign the server's certificate (the
	// profile's ca). Nil means the roots of the system.
	RootCAs *x509.CertPool
	// Certificates is the client's certificate and key (the profile's cert and
	// key). The servers that are set up as usual refuse a client without one.
	Certificates []tls.Certificate
	// RemoteCertTLSServer requires the server's certificate to be one for a TLS
	// server, as --remote-cert-tls server does: it must have a key usage
	// extension and the extended key usage "TLS Web Server Authentication". A
	// certificate with no extended key usage is refused. Without it a client's
	// certificate of the same authority can pass for the server's.
	RemoteCertTLSServer bool
	// MinVersion is the lowest TLS version, tls.VersionTLS12 or
	// tls.VersionTLS13; zero means TLS 1.2, which is also the lowest that the
	// library accepts.
	MinVersion uint16
	// VerifyName, when it is not empty, must match the server's certificate in the
	// way that VerifyNameMatch says (--verify-x509-name). It is checked after the
	// chain and the usage, and only for the server's own certificate.
	VerifyName string
	// VerifyNameMatch is how VerifyName is compared; the zero value compares the whole
	// subject.
	VerifyNameMatch NameMatch
	// PeerFingerprints are the SHA-256 fingerprints of the certificates that are
	// accepted as the server's (--peer-fingerprint); the server's certificate must be
	// one of them. When RootCAs is nil as well the chain is not verified, as OpenVPN
	// does for a profile that has a fingerprint and no ca: the fingerprint is the trust,
	// and the dates of the certificate are still checked. With RootCAs both are
	// checked.
	PeerFingerprints [][sha256.Size]byte
	// CurvePreferences are the key exchange groups of TLS, best first (--tls-groups);
	// nil means those of crypto/tls.
	CurvePreferences []tls.CurveID
}

// NewTLSConfig builds a tls.Config for Config.TLS that verifies the server the
// way OpenVPN does: the certificate chain must lead to RootCAs, and the name in
// the certificate is not compared with the address that was dialed (a profile
// asks for a check of the name with verify-x509-name: VerifyName). Nothing is left
// unverified: crypto/tls would check the name, so it is told to skip only its own
// check, and the chain is verified in VerifyConnection.
//
// OpenVPN: ssl_verify.c verify_callback, verify_cert; doc: tls-options.rst
// --remote-cert-tls, --verify-x509-name, --peer-fingerprint, --tls-groups.
func NewTLSConfig(o TLSOptions) *tls.Config {
	return &tls.Config{
		Certificates:     o.Certificates,
		MinVersion:       o.MinVersion,
		CurvePreferences: o.CurvePreferences,
		// The name check of crypto/tls is the only thing this turns off (an
		// OpenVPN server's certificate is not for the address it is dialed
		// at); VerifyConnection below checks the chain, and runs on every
		// handshake, resumed ones included.
		InsecureSkipVerify: true,
		VerifyConnection:   func(cs tls.ConnectionState) error { return verifyServer(&o, cs) },
	}
}

// verifyServer is the verification of the server's certificate that NewTLSConfig
// asks crypto/tls to run on every handshake.
func verifyServer(o *TLSOptions, cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign, Detail: "the server sent no certificate"}
	}
	leaf := cs.PeerCertificates[0]
	if len(o.PeerFingerprints) > 0 {
		sum := sha256.Sum256(leaf.Raw)
		found := false
		for _, f := range o.PeerFingerprints {
			found = found || f == sum
		}
		if !found {
			return errors.New(TagServerFingerprintMismatch, "the server's certificate is not one of the fingerprints of the profile", "fingerprint", hex.EncodeToString(sum[:]))
		}
	}
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	if o.RemoteCertTLSServer {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if err := checkServerUsage(leaf); err != nil {
			return err
		}
	}
	if len(o.PeerFingerprints) > 0 && o.RootCAs == nil {
		// Pinned: no chain to verify, but the certificate must still be good now, and for
		// a server when the profile says so.
		if err := checkPinned(leaf); err != nil {
			return err
		}
	} else {
		intermediates := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: o.RootCAs, Intermediates: intermediates, KeyUsages: usages}); err != nil {
			return err
		}
	}
	if o.VerifyName != "" {
		return checkName(o, leaf)
	}
	return nil
}

// checkServerUsage is the check of --remote-cert-tls server: the certificate has a
// key usage extension, and its extended key usage names "TLS Web Server
// Authentication". A certificate with no extended key usage, or with "any", does not
// pass, though crypto/x509 reads those as good for every use: a client's certificate
// of an authority that puts no usage in its certificates would else pass for the
// server's, which is the attack that the option is there to stop.
//
// OpenVPN: options.c remote-cert-tls (remote_cert_ku[0] = OPENVPN_KU_REQUIRED,
// remote_cert_eku = "TLS Web Server Authentication"), ssl_verify_openssl.c
// x509_verify_cert_ku, x509_verify_cert_eku.
func checkServerUsage(leaf *x509.Certificate) error {
	if leaf.KeyUsage == 0 {
		return errors.New(TagServerCertificateUsage, "the server's certificate has no key usage extension, which remote-cert-tls server requires", "missing", "key usage")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New(TagServerCertificateUsage, "the server's certificate does not have the extended key usage of a TLS server, which remote-cert-tls server requires", "missing", "extended key usage serverAuth")
	}
	return nil
}

// checkPinned checks what is left to check of a certificate that is trusted by its
// fingerprint: that it is valid now.
func checkPinned(leaf *x509.Certificate) error {
	now := time.Now()
	switch {
	case now.Before(leaf.NotBefore):
		return x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired, Detail: "the certificate is not valid yet"}
	case now.After(leaf.NotAfter):
		return x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired, Detail: "the certificate has expired"}
	}
	return nil
}

// checkName compares the name of the profile with the server's certificate.
//
// OpenVPN: ssl_verify.c verify_cert (verify_x509_type), ssl_verify_openssl.c
// x509_get_subject.
func checkName(o *TLSOptions, leaf *x509.Certificate) error {
	subject, common, err := subjectNames(leaf)
	if err != nil {
		return err
	}
	var ok bool
	switch o.VerifyNameMatch {
	case MatchSubject:
		ok = subject == o.VerifyName
	case MatchCommonName:
		ok = common == o.VerifyName
	case MatchCommonNamePrefix:
		ok = strings.HasPrefix(common, o.VerifyName)
	}
	if !ok {
		return errors.New(TagServerNameMismatch, "the server's certificate has another name than the profile wants",
			"subject", subject, "want", o.VerifyName)
	}
	return nil
}

// subjectNames writes the subject of a certificate as OpenVPN does and returns it with
// the common name (the last one, if there are several). A subject with a NUL byte is
// refused: its text would be cut short by the programs that compare it.
func subjectNames(c *x509.Certificate) (subject, common string, err error) {
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(c.RawSubject, &rdns); err != nil || len(rest) != 0 {
		return "", "", errors.New(TagServerNameUnreadable, "the subject of the server's certificate cannot be read")
	}
	var parts []string
	for _, rdn := range rdns {
		var atvs []string
		for _, atv := range rdn {
			v, ok := atv.Value.(string)
			if !ok {
				v = fmt.Sprintf("#%x", atv.Value) // a value that is not text: in hexadecimal, as OpenSSL does
			}
			if strings.IndexByte(v, 0) >= 0 {
				return "", "", errors.New(TagServerNameUnreadable, "the subject of the server's certificate has a NUL byte")
			}
			if atv.Type.Equal(oidCommonName) {
				common = v
			}
			atvs = append(atvs, shortName(atv.Type)+"="+escapeControls(v))
		}
		parts = append(parts, strings.Join(atvs, " + "))
	}
	return strings.Join(parts, ", "), common, nil
}

// escapeControls writes the control characters of a name as \XX in hexadecimal, as
// OpenSSL does for OpenVPN (ASN1_STRFLGS_ESC_CTRL).
func escapeControls(s string) string {
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			b.WriteString(`\`)
			b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

var (
	oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}
	// shortNames are the names that OpenSSL prints for the attributes of a subject.
	shortNames = map[string]string{
		"2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L",
		"2.5.4.8": "ST", "2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title",
		"2.5.4.42": "GN", "2.5.4.43": "initials", "2.5.4.46": "dnQualifier", "2.5.4.65": "pseudonym",
		"0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
		"1.2.840.113549.1.9.1": "emailAddress",
	}
)

// shortName is the short name of an attribute type, or its dotted number.
func shortName(oid asn1.ObjectIdentifier) string {
	if n, ok := shortNames[oid.String()]; ok {
		return n
	}
	return oid.String()
}

const (
	// TagServerFingerprintMismatch: the server's certificate is not one of the
	// fingerprints of TLSOptions.PeerFingerprints. Metadata: "fingerprint" (the
	// server's, in hexadecimal).
	TagServerFingerprintMismatch = "ServerFingerprintMismatch"
	// TagServerCertificateUsage: TLSOptions.RemoteCertTLSServer is set and the
	// server's certificate has no key usage extension, or its extended key usage
	// does not name a TLS server. Metadata: "missing".
	TagServerCertificateUsage = "ServerCertificateUsage"
	// TagServerNameMismatch: the server's certificate does not have the name that
	// TLSOptions.VerifyName asks for. Metadata: "subject", "want".
	TagServerNameMismatch = "ServerNameMismatch"
	// TagServerNameUnreadable: the subject of the server's certificate cannot be
	// compared with a name (it does not parse, or it has a NUL byte).
	TagServerNameUnreadable = "ServerNameUnreadable"
)

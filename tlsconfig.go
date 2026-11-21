// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/ssl_verify.c and doc/man-sections/tls-options.rst (--remote-cert-tls, --ca) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package openvpn

import (
	"crypto/tls"
	"crypto/x509"
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
	// RemoteCertTLSServer requires the server's certificate to be good for a
	// TLS server: the extended key usage "TLS Web Server Authentication"
	// (--remote-cert-tls server).
	RemoteCertTLSServer bool
	// MinVersion is the lowest TLS version, tls.VersionTLS12 or
	// tls.VersionTLS13; zero means TLS 1.2, which is also the lowest that the
	// library accepts.
	MinVersion uint16
}

// NewTLSConfig builds a tls.Config for Config.TLS that verifies the server the
// way OpenVPN does: the certificate chain must lead to RootCAs, and the name in
// the certificate is not compared with the address that was dialed (a profile
// asks for that with verify-x509-name, which a later version of the library
// supports). Nothing is left unverified: crypto/tls would check the name, so it
// is told to skip only its own check, and the chain is verified in
// VerifyConnection.
//
// OpenVPN: ssl_verify.c verify_callback; doc: tls-options.rst --remote-cert-tls.
func NewTLSConfig(o TLSOptions) *tls.Config {
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	if o.RemoteCertTLSServer {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	return &tls.Config{
		Certificates: o.Certificates,
		MinVersion:   o.MinVersion,
		// The name check of crypto/tls is the only thing this turns off (an
		// OpenVPN server's certificate is not for the address it is dialed
		// at); VerifyConnection below checks the chain, and runs on every
		// handshake, resumed ones included.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign, Detail: "the server sent no certificate"}
			}
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         o.RootCAs,
				Intermediates: intermediates,
				KeyUsages:     usages,
			})
			return err
		},
	}
}

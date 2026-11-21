// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package openvpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// tlsConfigFor is the configuration of a client that trusts the CA of the
// server's PKI and has the PKI's client certificate.
func tlsConfigFor(pki *servertest.PKI) *tls.Config {
	return NewTLSConfig(TLSOptions{
		RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}, RemoteCertTLSServer: true,
	})
}

// TestTLSWithRealServer completes the TLS handshake with a real server over UDP
// and TCP, with every protection of the control channel. The ClientHello of
// TLS 1.3 is the packet that carries the wrapped key of tls-crypt-v2.
func TestTLSWithRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		for _, setup := range serverSetups() {
			t.Run(proto+"/"+setup.name, func(t *testing.T) {
				extra, wrap := setup.make(t)
				srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: append([]string{"--verb", "4"}, extra...)})
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				conn, err := Dial(ctx, proto, srv.Addr(), &Config{ControlWrap: wrap, TLS: tlsConfigFor(srv.PKI)})
				if err != nil {
					t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
				}
				defer func() {
					if err := conn.Close(); err != nil {
						t.Errorf("Close: %v", err)
					}
				}()
				// The server has verified our certificate. ("Control Channel: TLSv1.3"
				// is logged when the key exchange is done, a later step.)
				srv.WaitLog(t, "VERIFY OK: depth=0, CN=client", 3*time.Second)
				if got := conn.s.TLS().ConnectionState().Version; got != tls.VersionTLS13 {
					t.Errorf("TLS version %#x, want TLS 1.3", got)
				}
			})
		}
	}
}

func TestTLS12WithRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: []string{"--verb", "4", "--tls-version-max", "1.2"}})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := Dial(ctx, proto, srv.Addr(), &Config{TLS: tlsConfigFor(srv.PKI)})
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			}()
			srv.WaitLog(t, "VERIFY OK: depth=0, CN=client", 3*time.Second)
			if got := conn.s.TLS().ConnectionState().Version; got != tls.VersionTLS12 {
				t.Errorf("TLS version %#x, want TLS 1.2", got)
			}
		})
	}
}

// TestTLSWithALargeClientCertificate sends a client certificate that fills a
// dozen control packets, past the send window of 6: the real server has to
// acknowledge them and put them back together.
func TestTLSWithALargeClientCertificate(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		for _, setup := range serverSetups() {
			if !setup.v2 && setup.name != "tls-crypt" {
				continue
			}
			t.Run(proto+"/"+setup.name, func(t *testing.T) {
				pki := servertest.NewPKIWith(t, servertest.PKIOptions{ClientCertNames: 60})
				extra, wrap := setup.make(t)
				srv := servertest.Start(t, servertest.Options{Proto: proto, PKI: pki, Extra: append([]string{"--verb", "4"}, extra...)})
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				conn, err := Dial(ctx, proto, srv.Addr(), &Config{ControlWrap: wrap, TLS: tlsConfigFor(pki)})
				if err != nil {
					t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
				}
				defer func() {
					if err := conn.Close(); err != nil {
						t.Errorf("Close: %v", err)
					}
				}()
				srv.WaitLog(t, "VERIFY OK: depth=0, CN=client", 3*time.Second)
			})
		}
	}
}

func TestTLSWithRealServerFailures(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto+"/a client that trusts another authority", func(t *testing.T) {
			srv := servertest.Start(t, servertest.Options{Proto: proto})
			other := servertest.NewPKI(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, err := Dial(ctx, proto, srv.Addr(), &Config{TLS: NewTLSConfig(TLSOptions{
				RootCAs: other.CAPool, Certificates: []tls.Certificate{srv.PKI.ClientCert},
			})})
			appErr, ok := errors.FromError(err)
			if !ok || appErr.Tag != TagTLSHandshakeFailed {
				t.Fatalf("Dial = %v, want %s", err, TagTLSHandshakeFailed)
			}
			var unknown x509.UnknownAuthorityError
			if !errors.As(err, &unknown) {
				t.Errorf("the cause is not an unknown authority: %v", err)
			}
		})
		t.Run(proto+"/a client with no certificate", func(t *testing.T) {
			srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: []string{"--verb", "4"}})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cfg := tlsConfigFor(srv.PKI)
			cfg.Certificates = nil
			cfg.MaxVersion = tls.VersionTLS12 // with 1.3 the client is done before the server refuses
			_, err := Dial(ctx, proto, srv.Addr(), &Config{TLS: cfg, HandshakeTimeout: 6 * time.Second})
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("Dial = %v\nserver log:\n%s", err, srv.Log())
			}
			// Over TCP the server closes the connection: the client's TLS fails,
			// or its reader of the link sees the end first, and either error
			// can come first. Over UDP the server says nothing, and the handshake
			// times out.
			ok = appErr.Tag == TagHandshakeTimeout
			if proto == "tcp" {
				ok = appErr.Tag == TagTLSHandshakeFailed || (appErr.Tag == TagLinkFailed && errors.Is(err, io.EOF))
			}
			if !ok {
				t.Fatalf("Dial = %v (tag %s)\nserver log:\n%s", err, appErr.Tag, srv.Log())
			}
		})
	}
}

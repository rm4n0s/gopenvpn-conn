// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"testing/synctest"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// serverTLS is the configuration of a TLS server that asks for a client
// certificate, as an OpenVPN server does.
func serverTLS(pki *servertest.PKI, cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.CAPool,
	}
}

// tlsPair is pair with a server that runs TLS.
func tlsPair(t *testing.T, k kind, p protection, server *tls.Config) (net.Conn, *vpntest.Server) {
	t.Helper()
	var client, peer net.Conn
	if k.stream {
		client, peer = vpntest.NewStreamPair()
	} else {
		client, peer = vpntest.NewDatagramPair(vpntest.LinkOptions{})
	}
	wkc := 0
	if p.v3 {
		wkc = len(v2Key(t).WKc)
	}
	srv := vpntest.NewServer(t, peer, vpntest.ServerOptions{
		Stream: k.stream, Wrapper: p.server(t), WKcLen: wkc, AskForWKc: p.v3, TLS: server,
	})
	return client, srv
}

func TestHandshakeWithTLS(t *testing.T) {
	for _, k := range kinds {
		for _, p := range protections() {
			for _, ver := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
				t.Run(k.name+"/"+p.name+"/"+tls.VersionName(ver), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						pki := servertest.NewPKI(t)
						srvCfg := serverTLS(pki, pki.ServerCert)
						srvCfg.MaxVersion = ver
						link, srv := tlsPair(t, k, p, srvCfg)
						cfg := &Config{
							ControlWrap: p.wrap(t),
							TLS: NewTLSConfig(TLSOptions{
								RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}, RemoteCertTLSServer: true,
							}),
						}
						conn := newClient(k, link, cfg)
						closeAtEnd(t, conn)
						if err := conn.HandshakeContext(t.Context()); err != nil {
							t.Fatal(err)
						}
						<-srv.TLSDone()
						state, err := srv.TLSResult()
						if err != nil {
							t.Fatalf("the server's handshake failed: %v", err)
						}
						if state.Version != ver {
							t.Errorf("TLS version %#x, want %#x", state.Version, ver)
						}
						if got := state.PeerCertificates[0].Subject.CommonName; got != "client" {
							t.Errorf("the server saw the certificate of %q", got)
						}
					})
				})
			}
		}
	}
}

func TestHandshakeWithTLSFailsForACertificateOfAnotherAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki, other := servertest.NewPKI(t), servertest.NewPKI(t)
		link, _ := tlsPair(t, kinds[0], protections()[3], serverTLS(pki, other.ServerCert))
		conn := PacketClient(link, &Config{
			ControlWrap: protections()[3].wrap(t),
			TLS:         NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}}),
		})
		closeAtEnd(t, conn)
		err := conn.HandshakeContext(t.Context())
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != TagTLSHandshakeFailed {
			t.Fatalf("HandshakeContext = %v, want %s", err, TagTLSHandshakeFailed)
		}
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) {
			t.Errorf("the cause is not an unknown authority: %v", err)
		}
	})
}

func TestNewTLSConfig(t *testing.T) {
	pki, other := servertest.NewPKI(t), servertest.NewPKI(t)
	parse := func(der []byte) *x509.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	server, client := parse(pki.ServerCert.Certificate[0]), parse(pki.ClientCert.Certificate[0])

	tests := []struct {
		name  string
		opts  TLSOptions
		peers []*x509.Certificate
		ok    bool
	}{
		{"a server of the authority", TLSOptions{RootCAs: pki.CAPool}, []*x509.Certificate{server}, true},
		{"the same, asking for a TLS server", TLSOptions{RootCAs: pki.CAPool, RemoteCertTLSServer: true}, []*x509.Certificate{server}, true},
		{"another authority", TLSOptions{RootCAs: other.CAPool}, []*x509.Certificate{server}, false},
		{"another authority, asking for a TLS server", TLSOptions{RootCAs: other.CAPool, RemoteCertTLSServer: true}, []*x509.Certificate{server}, false},
		{"a client certificate in place of a server's", TLSOptions{RootCAs: pki.CAPool}, []*x509.Certificate{client}, true},
		{"a client certificate, asking for a TLS server", TLSOptions{RootCAs: pki.CAPool, RemoteCertTLSServer: true}, []*x509.Certificate{client}, false},
		{"no certificate", TLSOptions{RootCAs: pki.CAPool}, nil, false},
		{"the certificate of the authority only", TLSOptions{RootCAs: pki.CAPool}, []*x509.Certificate{pki.CACert}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewTLSConfig(tt.opts)
			err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: tt.peers})
			if (err == nil) != tt.ok {
				t.Errorf("VerifyConnection = %v, want ok = %v", err, tt.ok)
			}
			// What is verified is the chain: the name in the certificate is
			// not compared with anything, as OpenVPN does not.
			if !cfg.InsecureSkipVerify {
				t.Error("crypto/tls would check the name of the server too")
			}
		})
	}
}

func TestNewTLSConfigPassesTheOptionsOn(t *testing.T) {
	pki := servertest.NewPKI(t)
	cfg := NewTLSConfig(TLSOptions{
		RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}, MinVersion: tls.VersionTLS13,
	})
	if len(cfg.Certificates) != 1 || cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("the config has %d certificates and MinVersion %#x", len(cfg.Certificates), cfg.MinVersion)
	}
	if cfg.VerifyConnection == nil {
		t.Error("nothing verifies the server")
	}
	if got := NewTLSConfig(TLSOptions{}).MinVersion; got != 0 {
		t.Errorf("MinVersion = %#x for none, want the default 0 (which the library raises to TLS 1.2)", got)
	}
}

func TestTLSConfigOfTheCallerIsNotChanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, _ := tlsPair(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert))
		tlsCfg := &tls.Config{RootCAs: pki.CAPool, ServerName: "server", Certificates: []tls.Certificate{pki.ClientCert}, MinVersion: tls.VersionTLS10}
		conn := PacketClient(link, &Config{TLS: tlsCfg})
		closeAtEnd(t, conn)
		if err := conn.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if tlsCfg.MinVersion != tls.VersionTLS10 {
			t.Errorf("the caller's MinVersion was changed to %#x", tlsCfg.MinVersion)
		}
	})
}

func TestTLS10IsNotAccepted(t *testing.T) {
	// A MinVersion below TLS 1.2 is raised to it: a server that offers nothing
	// better does not get a handshake.
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		srvCfg := serverTLS(pki, pki.ServerCert)
		srvCfg.MinVersion, srvCfg.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
		link, _ := tlsPair(t, kinds[0], protections()[0], srvCfg)
		conn := PacketClient(link, &Config{TLS: &tls.Config{
			RootCAs: pki.CAPool, ServerName: "server", Certificates: []tls.Certificate{pki.ClientCert}, MinVersion: tls.VersionTLS10,
		}})
		closeAtEnd(t, conn)
		err := conn.HandshakeContext(t.Context())
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagTLSHandshakeFailed {
			t.Fatalf("HandshakeContext = %v, want %s", err, TagTLSHandshakeFailed)
		}
	})
}

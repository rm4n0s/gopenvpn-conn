// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// tlsRig is a Session that runs TLS, and a server that does.
type tlsRig struct {
	*rig
	pki *servertest.PKI
}

type tlsOptions struct {
	rigOptions
	pki          *servertest.PKI // the client's; the server uses its own unless serverPKI is set
	serverPKI    *servertest.PKI
	serverTLS    func(*tls.Config)
	clientTLS    func(*tls.Config)
	pkiOptions   servertest.PKIOptions
	askForWKc    bool
	noClientCert bool
}

func newTLSRig(t *testing.T, o tlsOptions) *tlsRig {
	t.Helper()
	pki := o.pki
	if pki == nil {
		pki = servertest.NewPKIWith(t, o.pkiOptions)
	}
	serverPKI := o.serverPKI
	if serverPKI == nil {
		serverPKI = pki
	}
	server := &tls.Config{
		Certificates: []tls.Certificate{serverPKI.ServerCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.CAPool,
	}
	if o.serverTLS != nil {
		o.serverTLS(server)
	}
	client := &tls.Config{RootCAs: pki.CAPool, ServerName: "server"}
	if !o.noClientCert {
		client.Certificates = []tls.Certificate{pki.ClientCert}
	}
	if o.clientTLS != nil {
		o.clientTLS(client)
	}

	var link, peer net.Conn
	if o.transport.stream {
		link, peer = vpntest.NewStreamPair()
	} else {
		link, peer = vpntest.NewDatagramPair(o.link)
	}
	o.server.Stream = o.transport.stream
	o.server.Wrapper = o.wrap.server(t)
	if o.wrap.v3 {
		o.server.WKcLen = len(readV2Key(t).WKc)
		o.server.AskForWKc = o.askForWKc
	}
	o.server.TLS = server
	timeout := o.timeout
	if timeout == 0 {
		timeout = handshakeTimeout
	}
	srv := vpntest.NewServer(t, peer, o.server)
	s := New(Options{
		Link: link, Stream: o.transport.stream, Wrapper: o.wrap.client(t),
		HandshakeTimeout: timeout, TLS: client,
	})
	closeAtEnd(t, s)
	return &tlsRig{rig: &rig{session: s, server: srv, client: link, peer: peer}, pki: pki}
}

// serverResult waits for the TLS handshake of the server to end.
func serverResult(t *testing.T, r *tlsRig) (tls.ConnectionState, error) {
	t.Helper()
	select {
	case <-r.server.TLSDone():
	case <-time.After(10 * time.Minute):
		t.Fatal("the TLS handshake of the server did not end")
	}
	return r.server.TLSResult()
}

func TestTLSHandshake(t *testing.T) {
	versions := []struct {
		name string
		v    uint16
	}{{"TLS 1.3", tls.VersionTLS13}, {"TLS 1.2", tls.VersionTLS12}}
	for _, tr := range transports {
		for _, wk := range wrapKinds {
			for _, ask := range []bool{false, true} {
				if ask && !wk.v3 {
					continue
				}
				for _, ver := range versions {
					name := tr.name + "/" + wk.name + "/" + ver.name
					if ask {
						name += "/server asks for the wrapped key"
					}
					t.Run(name, func(t *testing.T) {
						synctest.Test(t, func(t *testing.T) {
							r := newTLSRig(t, tlsOptions{
								rigOptions: rigOptions{transport: tr, wrap: wk},
								askForWKc:  ask,
								serverTLS:  func(c *tls.Config) { c.MaxVersion = ver.v },
								clientTLS:  func(c *tls.Config) { c.MaxVersion = ver.v },
							})
							if err := r.session.Handshake(t.Context()); err != nil {
								t.Fatal(err)
							}
							conn := r.session.TLS()
							if conn == nil {
								t.Fatal("TLS() is nil after the handshake")
							}
							if got := conn.ConnectionState().Version; got != ver.v {
								t.Errorf("TLS version %#x, want %#x", got, ver.v)
							}
							state, err := serverResult(t, r)
							if err != nil {
								t.Fatalf("the server's handshake failed: %v", err)
							}
							if len(state.PeerCertificates) != 1 || state.PeerCertificates[0].Subject.CommonName != "client" {
								t.Errorf("the server saw the client certificate %v", state.PeerCertificates)
							}
							// The first packet with TLS bytes is the one that carries the
							// wrapped key, when the server asked for it. A packet that only
							// acknowledges the reset may come before it: the TLS side
							// can be a moment behind the server's answer.
							got := r.server.Received()
							var first *wire.Control
							for i := range got[1:] {
								if p := &got[1+i]; p.Opcode != wire.AckV1 {
									first = p
									break
								}
							}
							if first == nil {
								t.Fatalf("the server got no packet with TLS bytes: %v", ops(got))
							}
							wantFirst := wire.ControlV1
							if ask {
								wantFirst = wire.ControlWKCV1
							}
							if first.Opcode != wantFirst || first.PacketID != 1 || len(first.Payload) == 0 {
								t.Errorf("the first TLS packet is %v with id %d and %d bytes, want %v with id 1 and a ClientHello",
									first.Opcode, first.PacketID, len(first.Payload), wantFirst)
							}
							if !contains(first.Acks, 0) {
								t.Errorf("the first TLS packet does not acknowledge the reset: %+v", first.Acks)
							}
							for _, p := range got {
								if p.Opcode == wire.ControlWKCV1 && p.PacketID != 1 {
									t.Errorf("a CONTROL_WKC_V1 with id %d: only the first packet carries the wrapped key", p.PacketID)
								}
							}
						})
					})
				}
			}
		}
	}
}

func contains(ids []uint32, id uint32) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestTLSHandshakeWithLoss(t *testing.T) {
	links := []struct {
		name string
		link vpntest.LinkOptions
	}{
		{"30% loss", vpntest.LinkOptions{Loss: 0.3}},
		{"duplicates and delays", vpntest.LinkOptions{Duplicate: 0.5, MaxDelay: 3 * time.Second}},
		{"all of it", vpntest.LinkOptions{Loss: 0.3, Duplicate: 0.2, MaxDelay: 4 * time.Second}},
	}
	for _, lk := range links {
		for _, ver := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
			for _, wk := range []wrapKind{wrapKinds[0], wrapKinds[2], wrapKinds[3]} {
				for seed := int64(1); seed <= 5; seed++ {
					t.Run(lk.name+"/"+wk.name+"/"+tls.VersionName(ver), func(t *testing.T) {
						synctest.Test(t, func(t *testing.T) {
							link := lk.link
							link.Seed = seed
							r := newTLSRig(t, tlsOptions{
								rigOptions: rigOptions{transport: transports[0], wrap: wk, link: link, timeout: 20 * time.Minute},
								askForWKc:  true,
								serverTLS:  func(c *tls.Config) { c.MaxVersion = ver },
								clientTLS:  func(c *tls.Config) { c.MaxVersion = ver },
								pkiOptions: servertest.PKIOptions{ClientCertNames: 20},
							})
							if err := r.session.Handshake(t.Context()); err != nil {
								t.Fatalf("seed %d: %v", seed, err)
							}
							if _, err := serverResult(t, r); err != nil {
								t.Fatalf("seed %d: the server's handshake failed: %v", seed, err)
							}
						})
					})
				}
			}
		}
	}
}

func TestLargeClientCertificateIsCutIntoPackets(t *testing.T) {
	// A client certificate of about 12 KB is more than the send window of 6
	// packets holds: the bytes wait for acknowledgements, and no packet is
	// larger than the 1250 bytes that OpenVPN's servers allow.
	for _, wk := range wrapKinds {
		t.Run(wk.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newTLSRig(t, tlsOptions{
					rigOptions: rigOptions{transport: transports[0], wrap: wk, link: vpntest.LinkOptions{Seed: 4, Loss: 0.1}},
					askForWKc:  true,
					pkiOptions: servertest.PKIOptions{ClientCertNames: 60},
				})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				if _, err := serverResult(t, r); err != nil {
					t.Fatalf("the server's handshake failed: %v", err)
				}
				if got := r.server.LargestPacket(); got > tlsMTU || got < 1000 {
					t.Errorf("the largest packet is %d bytes, want between 1000 and %d", got, tlsMTU)
				}
				seen := map[uint32]bool{}
				total := 0
				for _, p := range r.server.Received() {
					if p.Opcode != wire.AckV1 && !seen[p.PacketID] {
						seen[p.PacketID] = true
						total += len(p.Payload)
					}
				}
				if total < len(r.pki.ClientCert.Certificate[0]) || len(seen) < 12 {
					t.Errorf("%d packets and %d bytes arrived, the certificate alone is %d bytes", len(seen), total, len(r.pki.ClientCert.Certificate[0]))
				}
			})
		})
	}
}

func TestPayloadBudget(t *testing.T) {
	tests := []struct {
		name string
		w    func(testing.TB) ctrlwrap.Wrapper
		want int
	}{
		// 1250 - 48 (IPv6 and UDP) - 1 - 8 - 41 (8 acks) - 4 - the protection.
		{"no protection", wrapKinds[0].client, 1148},
		{"tls-auth SHA-256", wrapKinds[1].client, 1148 - 32 - 8},
		{"tls-crypt", wrapKinds[2].client, 1148 - 8 - 32},
		{"tls-crypt-v2", wrapKinds[3].client, 1148 - 8 - 32},
	}
	for _, tt := range tests {
		if got := payloadBudget(tt.w(t)); got != tt.want {
			t.Errorf("%s: budget = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestTLSFailures(t *testing.T) {
	tests := []struct {
		name string
		opts func(t *testing.T) tlsOptions
		// as is a check of the cause of the error
		as func(err error) bool
	}{
		{
			name: "a server certificate of another authority",
			opts: func(t *testing.T) tlsOptions {
				return tlsOptions{serverPKI: servertest.NewPKI(t)}
			},
			as: func(err error) bool {
				var target x509.UnknownAuthorityError
				return errors.As(err, &target)
			},
		},
		{
			name: "no TLS version in common",
			opts: func(t *testing.T) tlsOptions {
				return tlsOptions{
					serverTLS: func(c *tls.Config) { c.MinVersion = tls.VersionTLS10; c.MaxVersion = tls.VersionTLS11 },
					// The client would go lower if the library let it.
					clientTLS: func(c *tls.Config) { c.MinVersion = tls.VersionTLS10 },
				}
			},
			as: func(err error) bool { return err != nil },
		},
		{
			name: "a server certificate for another name",
			opts: func(t *testing.T) tlsOptions {
				return tlsOptions{clientTLS: func(c *tls.Config) { c.ServerName = "other.example" }}
			},
			as: func(err error) bool {
				var target x509.HostnameError
				return errors.As(err, &target)
			},
		},
		{
			name: "no client certificate, with TLS 1.2",
			opts: func(t *testing.T) tlsOptions {
				return tlsOptions{
					noClientCert: true,
					serverTLS:    func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 },
					clientTLS:    func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 },
				}
			},
			as: func(err error) bool { return err != nil },
		},
	}
	for _, tt := range tests {
		for _, tr := range transports {
			t.Run(tt.name+"/"+tr.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					o := tt.opts(t)
					o.transport = tr
					o.wrap = wrapKinds[2]
					r := newTLSRig(t, o)
					err := r.session.Handshake(t.Context())
					appErr, ok := errors.FromError(err)
					if !ok || appErr.Tag != TagTLSHandshakeFailed || !appErr.HasRoute("tlsMain.TLSHandshakeFailed") {
						t.Fatalf("Handshake = %v, want a failed TLS handshake", err)
					}
					if !tt.as(err) {
						t.Errorf("the cause is lost or wrong: %v", err)
					}
					if again := r.session.Handshake(t.Context()); again != err {
						t.Errorf("a second Handshake returned %v, want the same error", again)
					}
					// The failure ended the session and everything of it.
					synctest.Wait()
				})
			})
		}
	}
}

func TestTLSClientWithoutCertificateIsRefusedByTheServer(t *testing.T) {
	// With TLS 1.3 the client's handshake is over before the server looks at
	// the certificate; the refusal is the server's.
	synctest.Test(t, func(t *testing.T) {
		r := newTLSRig(t, tlsOptions{
			rigOptions:   rigOptions{transport: transports[0], wrap: wrapKinds[0]},
			noClientCert: true,
		})
		_ = r.session.Handshake(t.Context()) // may or may not complete on the client's side
		if _, err := serverResult(t, r); err == nil {
			t.Fatal("the server completed a handshake with no client certificate")
		}
	})
}

func TestTLSHandshakeTimesOutOnASilentServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{
			transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.Silent},
		}})
		start := time.Now()
		err := r.session.Handshake(t.Context())
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagHandshakeTimeout {
			t.Fatalf("Handshake = %v, want %s", err, TagHandshakeTimeout)
		}
		if elapsed := time.Since(start); elapsed != handshakeTimeout {
			t.Errorf("failed after %v, want %v", elapsed, handshakeTimeout)
		}
		synctest.Wait() // the TLS goroutine has ended too: the bubble would block otherwise
	})
}

func TestTLSHandshakeTimesOutWhenTheServerStopsTalking(t *testing.T) {
	// The server answers the reset and then is silent: the client's ClientHello
	// goes out and is sent again, and the handshake times out.
	synctest.Test(t, func(t *testing.T) {
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0]}})
		// Close the TLS side of the server: it reads and acks, but says nothing.
		if err := r.server.CloseTLS(); err != nil {
			t.Fatal(err)
		}
		err := r.session.Handshake(t.Context())
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagHandshakeTimeout {
			t.Fatalf("Handshake = %v, want %s", err, TagHandshakeTimeout)
		}
	})
}

func TestCloseDuringTheTLSHandshakeStopsEveryGoroutine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		before := vpntest.BubbleGoroutines()
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{
			transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.Silent},
		}})
		result := make(chan error, 1)
		go func() { result <- r.session.Handshake(t.Context()) }()
		synctest.Wait()
		if err := r.session.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != net.ErrClosed {
			t.Errorf("Handshake = %v, want net.ErrClosed", err)
		}
		r.server.Close()
		synctest.Wait()
		if after := vpntest.BubbleGoroutines(); after != before {
			t.Errorf("%d goroutines before, %d after Close", before, after)
		}
	})
}

func TestCloseAfterTheTLSHandshakeStopsEveryGoroutine(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				before := vpntest.BubbleGoroutines()
				r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{transport: tr, wrap: wrapKinds[2]}})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := r.session.Close(); err != nil {
					t.Fatal(err)
				}
				r.server.Close()
				synctest.Wait()
				if after := vpntest.BubbleGoroutines(); after != before {
					t.Errorf("%d goroutines before, %d after Close", before, after)
				}
			})
		})
	}
}

func TestInboundTLSBytesAreBounded(t *testing.T) {
	// A peer that sends faster than TLS reads cannot make the buffer grow: a
	// packet that would pass the limit is not acknowledged, and is accepted
	// when TLS has read what waits.
	client, peer := vpntest.NewDatagramPair(vpntest.LinkOptions{})
	closeAtEnd(t, peer)
	s := New(Options{Link: client, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Minute, TLS: &tls.Config{}})
	closeAtEnd(t, s)
	sid := wire.RandomSessionID()
	s.remote, s.haveRemote, s.serverResetSeen = sid, true, true
	s.receiver.Receive(0, nil) // the reset
	s.receiver.Acks(wire.MaxAcks)

	packet := func(id uint32) []byte {
		raw, err := wire.AppendControl(nil, &wire.Control{Opcode: wire.ControlV1, SessionID: sid, PacketID: id, Payload: []byte("tls bytes")})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	s.adapter.push(make([]byte, inboundLimit))
	s.handle(packet(1))
	if s.receiver.HasPendingAcks() || s.Dropped() != 1 {
		t.Fatalf("a packet was taken with %d bytes waiting (dropped %d)", s.adapter.queued(), s.Dropped())
	}
	// TLS reads: the same packet is taken, and acknowledged.
	buf := make([]byte, inboundLimit)
	if n, err := s.adapter.Read(buf); err != nil || n != inboundLimit {
		t.Fatalf("Read = %d, %v", n, err)
	}
	s.handle(packet(1))
	if !s.receiver.HasPendingAcks() || s.adapter.queued() != len("tls bytes") {
		t.Errorf("the packet was not taken: acks %v, queued %d", s.receiver.HasPendingAcks(), s.adapter.queued())
	}
}

func TestKeyExchangeFailures(t *testing.T) {
	good := func() []byte {
		b := []byte{0, 0, 0, 0, 2}
		b = append(b, make([]byte, 64)...)
		return append(b, 0, 2, 'o', 0, 0, 1, 0, 0, 1, 0, 0, 1, 0)
	}
	badMethod := good()
	badMethod[4] = 1
	tests := []struct {
		name   string
		reply  []byte
		closes bool
		tag    string
		route  string
	}{
		{"a message that is too short", []byte{0, 0, 0, 0, 2, 1, 2, 3}, false, "KeyExchangeTruncated", "keyExchange->ParseServerKeyExchange.KeyExchangeTruncated"},
		{"another key method", badMethod, false, "BadKeyMethod", "keyExchange->ParseServerKeyExchange.BadKeyMethod"},
		{"bytes after the message", append(good(), 7), false, "KeyExchangeTrailing", "keyExchange->ParseServerKeyExchange.KeyExchangeTrailing"},
		{"the session ends before the answer", []byte{}, true, TagKeyExchangeFailed, "keyExchange.KeyExchangeFailed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{
					transport: transports[0], wrap: wrapKinds[0],
					server: vpntest.ServerOptions{KeyExchangeReply: tt.reply, CloseAfterKeyExchange: tt.closes},
				}})
				err := r.session.Handshake(t.Context())
				appErr, ok := errors.FromError(err)
				if !ok || appErr.Tag != tt.tag || !appErr.HasRoute(tt.route) {
					t.Fatalf("Handshake = %v (route %v), want %s with route %s", err, appErr, tt.tag, tt.route)
				}
				if tt.closes && appErr.Metadata["op"] != "read" {
					t.Errorf("metadata = %v, want op read", appErr.Metadata)
				}
				if again := r.session.Handshake(t.Context()); again != err {
					t.Errorf("a second Handshake returned %v, want the same error", again)
				}
				synctest.Wait()
			})
		})
	}
}

func TestKeyExchangeWaitsForTheServer(t *testing.T) {
	// A server that reads the message and never answers: the handshake times out.
	synctest.Test(t, func(t *testing.T) {
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{
			transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{KeyExchangeReply: []byte{}},
		}})
		err := r.session.Handshake(t.Context())
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagHandshakeTimeout {
			t.Fatalf("Handshake = %v, want %s", err, TagHandshakeTimeout)
		}
		<-r.server.KeyExchangeDone()
		if r.server.KeyExchange() == nil {
			t.Error("the server never got the client's message")
		}
	})
}

func TestKeyExchangeRefusesCredentialsThatAreTooLong(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, peer := vpntest.NewDatagramPair(vpntest.LinkOptions{})
		vpntest.NewServer(t, peer, vpntest.ServerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{pki.ServerCert}}})
		s := New(Options{
			Link: link, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Minute,
			TLS:         &tls.Config{RootCAs: pki.CAPool, ServerName: "server"},
			Options:     "o",
			Credentials: func(context.Context) (string, string, error) { return "alice", strings.Repeat("p", 128), nil },
		})
		closeAtEnd(t, s)
		err := s.Handshake(t.Context())
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != "StringTooLong" || !appErr.HasRoute("keyExchange->AppendClientKeyExchange.StringTooLong") {
			t.Fatalf("Handshake = %v, want StringTooLong", err)
		}
		if strings.Contains(appErr.Error(), "ppp") {
			t.Error("the password is in the error")
		}
	})
}

func TestServerKeyExchangeIsKept(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0]}})
		if r.session.ServerKeyExchange() != nil {
			t.Error("a message before the handshake")
		}
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		kx := r.session.ServerKeyExchange()
		if kx == nil || !strings.HasPrefix(kx.Options, "V4,dev-type tun,") || kx.PeerInfo != "IV_VER=vpntest\n" {
			t.Errorf("server key exchange = %+v", kx)
		}
	})
}

func TestKeyExchangeCredentialsFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, peer := vpntest.NewDatagramPair(vpntest.LinkOptions{})
		vpntest.NewServer(t, peer, vpntest.ServerOptions{TLS: &tls.Config{Certificates: []tls.Certificate{pki.ServerCert}}})
		cause := net.ErrClosed // any error will do: it must survive
		s := New(Options{
			Link: link, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Minute,
			TLS:         &tls.Config{RootCAs: pki.CAPool, ServerName: "server"},
			Options:     "o",
			Credentials: func(context.Context) (string, string, error) { return "", "", cause },
		})
		closeAtEnd(t, s)
		err := s.Handshake(t.Context())
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != TagCredentialsFailed || !appErr.HasRoute("tlsMain->Session.keyExchange.CredentialsFailed") || !errors.Is(err, cause) {
			t.Fatalf("Handshake = %v, want %s", err, TagCredentialsFailed)
		}
	})
}

// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"bytes"
	"crypto/tls"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
	"github.com/rm4n0s/gopenvpn-conn/internal/datachan"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// dataCiphers are the ciphers that the data tests go through, with the push reply
// that names each. AES-192-GCM is not in the default offer: the rig offers it.
var dataCiphers = []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"}

var allCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-192-GCM"}

// pushWith is the usual push reply with another cipher, and without the peer id
// when v1 is set.
func pushWith(cipher string, v1 bool) string {
	reply := strings.Replace(vpntest.DefaultPushReply, "cipher AES-256-GCM", "cipher "+cipher, 1)
	if v1 {
		reply = strings.Replace(reply, ",peer-id 0", "", 1)
	}
	return reply
}

// dataRig is a TLS rig whose handshake is done on the first use.
func dataRig(t *testing.T, tr transport, cipher string, v1 bool, server vpntest.ServerOptions) *tlsRig {
	t.Helper()
	server.DataCipher = cipher
	server.DataV1 = v1
	server.PushMessages = []string{pushWith(cipher, v1)}
	return newTLSRig(t, tlsOptions{
		rigOptions: rigOptions{transport: tr, wrap: wrapKinds[0], server: server},
		ciphers:    allCiphers,
	})
}

// waitFor lets the bubble settle and returns the packets the server has opened,
// when there are n of them.
func serverGot(t *testing.T, r *tlsRig, n int) [][]byte {
	t.Helper()
	synctest.Wait()
	got := r.server.DataReceived()
	if len(got) != n {
		t.Fatalf("the server opened %d packets, want %d (it dropped %d)", len(got), n, r.server.DataDropped())
	}
	return got
}

func TestDataGoesBothWays(t *testing.T) {
	payloads := [][]byte{
		{0x45, 1},
		bytes.Repeat([]byte{0x45}, 100),
		bytes.Repeat([]byte{0x60, 7}, 700), // 1400 bytes
		bytes.Repeat([]byte{0x45}, 1500),   // the MTU
	}
	for _, tr := range transports {
		for _, cipher := range dataCiphers {
			for _, v1 := range []bool{false, true} {
				name := tr.name + "/" + cipher + "/DATA_V2"
				if v1 {
					name = tr.name + "/" + cipher + "/DATA_V1"
				}
				t.Run(name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						r := dataRig(t, tr, cipher, v1, vpntest.ServerOptions{EchoData: true})
						// No call of Handshake: the first Write runs it.
						for _, p := range payloads {
							if n, err := r.session.Write(p); err != nil || n != len(p) {
								t.Fatalf("Write(%d bytes) = %d, %v", len(p), n, err)
							}
						}
						got := serverGot(t, r, len(payloads))
						buf := make([]byte, 2000)
						for i, p := range payloads {
							if !bytes.Equal(got[i], p) {
								t.Errorf("the server got packet %d as %d different bytes", i, len(got[i]))
							}
							// The echo comes back as the same packet.
							n, err := r.session.Read(buf)
							if err != nil || !bytes.Equal(buf[:n], p) {
								t.Errorf("Read of echo %d = %d bytes, %v", i, n, err)
							}
						}
						// And a packet the server starts.
						if _, err := r.server.SendData([]byte{0x45, 9, 9}); err != nil {
							t.Fatal(err)
						}
						n, err := r.session.Read(buf)
						if err != nil || !bytes.Equal(buf[:n], []byte{0x45, 9, 9}) {
							t.Errorf("Read = %x, %v", buf[:n], err)
						}
						if r.session.Dropped() != 0 {
							t.Errorf("%d packets dropped", r.session.Dropped())
						}
					})
				})
			}
		}
	}
}

func TestReadWithASmallBufferGetsTheStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := dataRig(t, transports[0], "AES-256-GCM", false, vpntest.ServerOptions{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, p := range [][]byte{{1, 2, 3, 4, 5, 6, 7, 8}, {9, 8, 7}} {
			if _, err := r.server.SendData(p); err != nil {
				t.Fatal(err)
			}
		}
		buf := make([]byte, 3)
		if n, err := r.session.Read(buf); err != nil || n != 3 || !bytes.Equal(buf, []byte{1, 2, 3}) {
			t.Errorf("Read = %d, %v, %x", n, err, buf)
		}
		// The rest of that packet is gone: the next Read is the next packet.
		if n, err := r.session.Read(buf); err != nil || n != 3 || !bytes.Equal(buf, []byte{9, 8, 7}) {
			t.Errorf("second Read = %d, %v, %x", n, err, buf)
		}
	})
}

func TestWriteRefusals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := dataRig(t, transports[0], "AES-256-GCM", false, vpntest.ServerOptions{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, err := r.session.Write(make([]byte, 1501)) // the push reply says tun-mtu 1500
		wantRoute(t, err, TagPacketTooLarge, "Session.Write.PacketTooLarge")
		appErr, _ := errors.FromError(err)
		if appErr.Metadata["len"] != 1501 || appErr.Metadata["mtu"] != 1500 {
			t.Errorf("metadata = %v", appErr.Metadata)
		}
		_, err = r.session.Write(nil)
		wantRoute(t, err, tagEmptyPacket, "Session.Write.EmptyPacket")
		// Neither ended the session.
		if n, err := r.session.Write([]byte{0x45}); err != nil || n != 1 {
			t.Errorf("Write after the refusals = %d, %v", n, err)
		}
		serverGot(t, r, 1)
	})
}

func wantRoute(t *testing.T, err error, tag, route string) {
	t.Helper()
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not an *errors.Error", err, err)
	}
	if appErr.Tag != tag || !appErr.HasRoute(route) {
		t.Fatalf("error has tag %s and route %s, want tag %s and route %s", appErr.Tag, appErr.Route(), tag, route)
	}
}

func TestTheMTUWithoutAPushedOne(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := vpntest.ServerOptions{PushMessages: []string{strings.Replace(vpntest.DefaultPushReply, ",tun-mtu 1500", "", 1)}}
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0], server: server}, mtu: 1200})
		if _, err := r.session.Write(make([]byte, 1201)); err == nil {
			t.Fatal("a packet larger than the MTU of the options was sent")
		} else {
			wantRoute(t, err, TagPacketTooLarge, "Session.Write.PacketTooLarge")
		}
		if _, err := r.session.Write(make([]byte, 1200)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestReadAndWriteAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := dataRig(t, transports[0], "AES-256-GCM", false, vpntest.ServerOptions{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		// A Read that waits is released by Close.
		result := make(chan error, 1)
		go func() {
			_, err := r.session.Read(make([]byte, 10))
			result <- err
		}()
		synctest.Wait()
		if err := r.session.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != net.ErrClosed {
			t.Errorf("Read in progress returned %v, want net.ErrClosed", err)
		}
		if _, err := r.session.Read(make([]byte, 10)); err != net.ErrClosed {
			t.Errorf("Read after Close = %v", err)
		}
		if _, err := r.session.Write([]byte{0x45}); err != net.ErrClosed {
			t.Errorf("Write after Close = %v", err)
		}
	})
}

func TestReadAndWriteReturnTheErrorThatEndedTheSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := dataRig(t, transports[0], "AES-256-GCM", false, vpntest.ServerOptions{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		r.server.SendControl("HALT,maintenance")
		synctest.Wait()
		_, errRead := r.session.Read(make([]byte, 10))
		_, errWrite := r.session.Write([]byte{0x45})
		appErr, ok := errors.FromError(errRead)
		if !ok || appErr.Tag != TagServerHalt || errRead != errWrite {
			t.Errorf("Read = %v, Write = %v: want the same %s error", errRead, errWrite, TagServerHalt)
		}
	})
}

func TestReadWithAHandshakeThatFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := vpntest.ServerOptions{PushMessages: []string{"AUTH_FAILED"}}
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0], server: server}})
		_, errRead := r.session.Read(make([]byte, 10))
		if appErr, ok := errors.FromError(errRead); !ok || appErr.Tag != TagAuthFailed {
			t.Fatalf("Read = %v, want %s", errRead, TagAuthFailed)
		}
		if _, errWrite := r.session.Write([]byte{0x45}); errWrite != errRead {
			t.Errorf("Write = %v, want the error of Read", errWrite)
		}
	})
}

func TestReplayedAndForgedDataPacketsAreDropped(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := dataRig(t, tr, "AES-256-GCM", false, vpntest.ServerOptions{})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				first, err := r.server.SendData([]byte{0x45, 1})
				if err != nil {
					t.Fatal(err)
				}
				forged := bytes.Clone(first)
				forged[len(forged)-1] ^= 1
				short := first[:10]
				for _, p := range [][]byte{first, forged, short, first, nil} {
					if err := r.server.SendPacket(p); err != nil && p != nil {
						t.Fatal(err)
					}
				}
				second, err := r.server.SendData([]byte{0x45, 2})
				if err != nil || second == nil {
					t.Fatal(err)
				}
				synctest.Wait()
				buf := make([]byte, 10)
				for _, want := range [][]byte{{0x45, 1}, {0x45, 2}} {
					n, err := r.session.Read(buf)
					if err != nil || !bytes.Equal(buf[:n], want) {
						t.Fatalf("Read = %x, %v, want %x", buf[:n], err, want)
					}
				}
				// first twice more than once sent: the replay, the forgery and the short packet.
				if got := r.session.Dropped(); got < 3 {
					t.Errorf("%d packets dropped, want at least 3", got)
				}
				// None of that touched the session.
				if _, err := r.session.Write([]byte{0x45}); err != nil {
					t.Errorf("Write: %v", err)
				}
			})
		})
	}
}

func TestPingPacketsAreNotGivenToRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := dataRig(t, transports[0], "AES-256-GCM", false, vpntest.ServerOptions{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, p := range [][]byte{pingString, {0x45, 5}} {
			if _, err := r.server.SendData(p); err != nil {
				t.Fatal(err)
			}
		}
		buf := make([]byte, 100)
		if n, err := r.session.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte{0x45, 5}) {
			t.Errorf("Read = %x, %v: the ping came through", buf[:n], err)
		}
	})
}

func TestPacketsThatNobodyReadsAreDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := dataRig(t, transports[0], "AES-256-GCM", false, vpntest.ServerOptions{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		const sent = recvQueue + 40
		for i := range sent {
			if _, err := r.server.SendData([]byte{0x45, byte(i), byte(i >> 8)}); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if got := r.session.Dropped(); got == 0 || got > sent-recvQueue {
			t.Errorf("%d packets dropped, want between 1 and %d", got, sent-recvQueue)
		}
		// The control channel went on working all that time: the session is alive.
		buf := make([]byte, 10)
		n, err := r.session.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], []byte{0x45, 0, 0}) {
			t.Errorf("Read = %x, %v", buf[:n], err)
		}
	})
}

func TestManyWritersSendEveryPacketOnce(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := dataRig(t, tr, "CHACHA20-POLY1305", false, vpntest.ServerOptions{})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				const writers, each = 8, 50
				var wg sync.WaitGroup
				for w := range writers {
					wg.Go(func() {
						for i := range each {
							if _, err := r.session.Write([]byte{0x45, byte(w & 0xff), byte(i & 0xff)}); err != nil {
								t.Errorf("Write: %v", err)
								return
							}
						}
					})
				}
				wg.Wait()
				got := serverGot(t, r, writers*each)
				seen := map[[2]byte]bool{}
				for _, p := range got {
					seen[[2]byte{p[1], p[2]}] = true
				}
				if len(seen) != writers*each {
					t.Errorf("%d different packets arrived, want %d", len(seen), writers*each)
				}
			})
		})
	}
}

func TestCloseAfterDataStopsEveryGoroutine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		before := vpntest.BubbleGoroutines()
		r := dataRig(t, transports[0], "AES-256-GCM", false, vpntest.ServerOptions{EchoData: true})
		for range 10 {
			if _, err := r.session.Write([]byte{0x45}); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if err := r.session.Close(); err != nil {
			t.Fatal(err)
		}
		r.server.Close()
		synctest.Wait()
		if after := vpntest.BubbleGoroutines(); after != before {
			t.Errorf("%d goroutines before, %d after Close", before, after)
		}
	})
}

// fakeExporter gives the material of the test, or fails.
type fakeExporter struct {
	material []byte
	err      error
}

func (f fakeExporter) ExportKeyingMaterial(string, []byte, int) ([]byte, error) {
	return bytes.Clone(f.material), f.err
}

func TestSetupDataRefusals(t *testing.T) {
	good := fakeExporter{material: make([]byte, 256)}
	base := func() *ctrlmsg.Pushed {
		return &ctrlmsg.Pushed{Cipher: "AES-256-GCM", KeyDerivation: "tls-ekm", HasPeerID: true, PeerID: 5}
	}
	tests := []struct {
		name   string
		pushed func() *ctrlmsg.Pushed
		x      exporter
		tag    string
		route  string
	}{
		{"no key derivation", func() *ctrlmsg.Pushed { p := base(); p.KeyDerivation = ""; return p }, good,
			TagKeyDerivationUnsupported, "Session.setupData.KeyDerivationUnsupported"},
		{"the old key derivation", func() *ctrlmsg.Pushed { p := base(); p.KeyDerivation = "tls1-prf"; return p }, good,
			TagKeyDerivationUnsupported, "Session.setupData.KeyDerivationUnsupported"},
		{"no cipher", func() *ctrlmsg.Pushed { p := base(); p.Cipher = ""; return p }, good,
			ctrlmsg.TagCipherNegotiationFailed, "Session.setupData.CipherNegotiationFailed"},
		{"a cipher that is not here", func() *ctrlmsg.Pushed { p := base(); p.Cipher = "AES-256-CBC"; return p }, good,
			ctrlmsg.TagCipherNegotiationFailed, "Session.setupData.CipherNegotiationFailed"},
		{"the export fails", base, fakeExporter{err: net.ErrClosed},
			TagKeyExportFailed, "Session.setupData.KeyExportFailed"},
		{"too little material", base, fakeExporter{material: make([]byte, 255)},
			"BadDataKeys", "Session.setupData->SplitDataKeys.BadDataKeys"},
		{"a peer id that is too big", func() *ctrlmsg.Pushed { p := base(); p.PeerID = 1 << 24; return p }, good,
			"DataHeaderInvalid", "Session.setupData->NewSender->Header.validate.DataHeaderInvalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Options{Link: &net.UDPConn{}, Wrapper: nil, Err: errors.New(tagNeverStarts, "a session that never starts")})
			err := s.setupData(tt.pushed(), tt.x)
			wantRoute(t, err, tt.tag, tt.route)
			if s.data.Load() != nil {
				t.Error("a data channel was made")
			}
		})
	}
	// The protocol flags are another way to ask for the exporter.
	p := base()
	p.KeyDerivation, p.ProtocolFlags = "", []string{"cc-exit", "tls-ekm"}
	s := New(Options{Link: &net.UDPConn{}, Err: errors.New(tagNeverStarts, "a session that never starts")})
	if err := s.setupData(p, good); err != nil {
		t.Errorf("setupData with protocol-flags tls-ekm: %v", err)
	}
	if s.data.Load() == nil {
		t.Error("no data channel")
	}
}

func TestPushWithoutTheExporterEndsTheHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reply := strings.Replace(vpntest.DefaultPushReply, ",key-derivation tls-ekm", "", 1)
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0],
			server: vpntest.ServerOptions{PushMessages: []string{reply}}}})
		err := r.session.Handshake(t.Context())
		wantRoute(t, err, TagKeyDerivationUnsupported, "control->Session.setupData.KeyDerivationUnsupported")
		if r.session.Pushed() != nil {
			t.Error("Pushed() is not nil after a failure")
		}
	})
}

// With TLS 1.2 the exporter needs the extended master secret, which crypto/tls
// uses on both ends: the data keys are the same.
func TestDataWithTLS12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cap12 := func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }
		server := vpntest.ServerOptions{EchoData: true}
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0], server: server},
			serverTLS: cap12, clientTLS: cap12})
		if _, err := r.session.Write([]byte{0x45, 3}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 10)
		if n, err := r.session.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte{0x45, 3}) {
			t.Errorf("Read = %x, %v", buf[:n], err)
		}
		if v := r.session.TLS().ConnectionState().Version; v != tls.VersionTLS12 {
			t.Errorf("TLS version %#x", v)
		}
	})
}

func TestHandleDataBeforeTheKeys(t *testing.T) {
	s := New(Options{Link: &net.UDPConn{}, Err: errors.New(tagNeverStarts, "a session that never starts")})
	s.handleData([]byte{9 << 3, 1, 2, 3})
	if s.Dropped() != 1 || len(s.recv) != 0 {
		t.Errorf("dropped %d, queued %d", s.Dropped(), len(s.recv))
	}
}

// When every packet id of the key has been used, Write ends the session rather than
// repeat a nonce, and says why to every later call.
func TestWriteEndsTheSessionWhenThePacketIDsEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := dataRig(t, transports[0], "AES-256-GCM", false, vpntest.ServerOptions{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		r.session.data.Load().sender.SetNextID(math.MaxUint32)
		if _, err := r.session.Write([]byte{0x45, 1}); err != nil { // the last id
			t.Fatal(err)
		}
		_, err := r.session.Write([]byte{0x45, 2})
		wantRoute(t, err, datachan.TagPacketIDExhausted, "Session.Write->Sender.Seal.DataPacketIDExhausted")
		if _, again := r.session.Read(make([]byte, 10)); again != err {
			t.Errorf("Read = %v, want the same error", again)
		}
		serverGot(t, r, 1)
	})
}

// tagNeverStarts is the tag of the error of the sessions that these tests make only to call a method of.
const tagNeverStarts = "NeverStarts"

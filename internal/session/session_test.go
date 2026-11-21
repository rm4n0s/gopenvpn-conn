// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

const handshakeTimeout = 30 * time.Second

func testKey(seed byte) *keys.StaticKey {
	var k keys.StaticKey
	b := seed
	for i := range k {
		k[i] = b
		b++
	}
	return &k
}

func readV2Key(t testing.TB) *keys.TLSCryptV2ClientKey {
	t.Helper()
	f, err := os.Open("../keys/testdata/tls-crypt-v2-client.key")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	key, err := keys.ParseTLSCryptV2ClientKey(f)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// wrapKind is one control channel protection, with both of its ends.
type wrapKind struct {
	name   string
	client func(t testing.TB) ctrlwrap.Wrapper
	server func(t testing.TB) ctrlwrap.Wrapper
	v3     bool
}

func mustWrapper(t testing.TB, w ctrlwrap.Wrapper, err error) ctrlwrap.Wrapper {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return w
}

var wrapKinds = []wrapKind{
	{
		name:   "no protection",
		client: func(testing.TB) ctrlwrap.Wrapper { return ctrlwrap.NewPlain() },
		server: func(testing.TB) ctrlwrap.Wrapper { return ctrlwrap.NewPlain() },
	},
	{
		name: "tls-auth",
		client: func(t testing.TB) ctrlwrap.Wrapper {
			w, err := ctrlwrap.NewTLSAuth(testKey(1), keys.Inverse, sha256.New, time.Now)
			return mustWrapper(t, w, err)
		},
		server: func(t testing.TB) ctrlwrap.Wrapper {
			w, err := ctrlwrap.NewTLSAuth(testKey(1), keys.Normal, sha256.New, time.Now)
			return mustWrapper(t, w, err)
		},
	},
	{
		name: "tls-crypt",
		client: func(t testing.TB) ctrlwrap.Wrapper {
			w, err := ctrlwrap.NewTLSCrypt(testKey(2), time.Now)
			return mustWrapper(t, w, err)
		},
		server: func(t testing.TB) ctrlwrap.Wrapper {
			w, err := ctrlwrap.NewTLSCryptServer(testKey(2), time.Now)
			return mustWrapper(t, w, err)
		},
	},
	{
		name: "tls-crypt-v2",
		client: func(t testing.TB) ctrlwrap.Wrapper {
			w, err := ctrlwrap.NewTLSCryptV2(readV2Key(t), time.Now)
			return mustWrapper(t, w, err)
		},
		server: func(t testing.TB) ctrlwrap.Wrapper {
			w, err := ctrlwrap.NewTLSCryptServer(&readV2Key(t).Kc, time.Now)
			return mustWrapper(t, w, err)
		},
		v3: true,
	},
}

type transport struct {
	name   string
	stream bool
}

var transports = []transport{{"datagrams", false}, {"stream", true}}

// rig is a Session and a server in one process.
type rig struct {
	session *Session
	server  *vpntest.Server
	client  net.Conn // the client's end of the link
	peer    net.Conn // the server's end
}

type rigOptions struct {
	transport transport
	wrap      wrapKind
	link      vpntest.LinkOptions
	server    vpntest.ServerOptions
	timeout   time.Duration
}

func newRig(t *testing.T, o rigOptions) *rig {
	t.Helper()
	var client, peer net.Conn
	if o.transport.stream {
		client, peer = vpntest.NewStreamPair()
	} else {
		client, peer = vpntest.NewDatagramPair(o.link)
	}
	o.server.Stream = o.transport.stream
	o.server.Wrapper = o.wrap.server(t)
	if o.wrap.v3 {
		o.server.WKcLen = len(readV2Key(t).WKc)
	}
	if o.timeout == 0 {
		o.timeout = handshakeTimeout
	}
	server := vpntest.NewServer(t, peer, o.server)
	s := New(Options{
		Link: client, Stream: o.transport.stream, Wrapper: o.wrap.client(t),
		HandshakeTimeout: o.timeout,
	})
	t.Cleanup(func() {
		if err := s.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Close: %v", err)
		}
	})
	return &rig{session: s, server: server, client: client, peer: peer}
}

func ops(packets []wire.Control) []wire.Opcode {
	var r []wire.Opcode
	for _, p := range packets {
		r = append(r, p.Opcode)
	}
	return r
}

func TestHandshake(t *testing.T) {
	for _, tr := range transports {
		for _, wk := range wrapKinds {
			for _, ask := range []bool{false, true} {
				if ask && !wk.v3 {
					continue
				}
				name := tr.name + "/" + wk.name
				if ask {
					name += "/server asks for the wrapped key"
				}
				t.Run(name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						r := newRig(t, rigOptions{transport: tr, wrap: wk, server: vpntest.ServerOptions{AskForWKc: ask}})
						if err := r.session.Handshake(t.Context()); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
						got := r.server.Received()
						resetOp := wire.HardResetClientV2
						if wk.v3 {
							resetOp = wire.HardResetClientV3
						}
						if len(got) < 2 {
							t.Fatalf("the server got %v, want a reset and a third packet", ops(got))
						}
						first := got[0]
						if first.Opcode != resetOp || first.KeyID != 0 || first.PacketID != 0 || len(first.Acks) != 0 || len(first.Payload) != 0 {
							t.Errorf("the first packet is %+v, want a %v with id 0, no acks, no payload", first, resetOp)
						}
						third := got[1]
						wantThird := wire.AckV1
						if ask {
							wantThird = wire.ControlWKCV1
						}
						if third.Opcode != wantThird {
							t.Errorf("the third packet is %v, want %v", third.Opcode, wantThird)
						}
						if !slices.Contains(third.Acks, 0) || third.RemoteSessionID != r.server.SessionID() {
							t.Errorf("the third packet does not ack the server's reset: %+v", third)
						}
						if ask && third.PacketID != 1 {
							t.Errorf("the wrapped key packet has id %d, want 1", third.PacketID)
						}
						if again := r.session.Handshake(t.Context()); again != nil {
							t.Errorf("a second Handshake: %v", again)
						}
					})
				})
			}
		}
	}
}

func TestHandshakeWithLoss(t *testing.T) {
	tests := []struct {
		name string
		link vpntest.LinkOptions
	}{
		{"30% loss", vpntest.LinkOptions{Loss: 0.3}},
		{"duplicates and delays", vpntest.LinkOptions{Duplicate: 0.5, MaxDelay: 3 * time.Second}},
		{"all of it", vpntest.LinkOptions{Loss: 0.3, Duplicate: 0.2, MaxDelay: 4 * time.Second}},
	}
	for _, tt := range tests {
		for _, wk := range wrapKinds {
			for seed := int64(1); seed <= 8; seed++ {
				t.Run(tt.name+"/"+wk.name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						link := tt.link
						link.Seed = seed
						r := newRig(t, rigOptions{
							transport: transports[0], wrap: wk, link: link, timeout: 10 * time.Minute,
							server: vpntest.ServerOptions{AskForWKc: wk.v3},
						})
						if err := r.session.Handshake(t.Context()); err != nil {
							t.Fatalf("seed %d: %v", seed, err)
						}
					})
				})
			}
		}
	}
}

func TestResetIsSentAgainWithBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRig(t, rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.Silent}, timeout: time.Hour})
		go func() { _ = r.session.Handshake(t.Context()) }()
		start := time.Now()
		// The reset goes out at 0, 2, 6, 14, 30 seconds.
		for _, step := range []struct {
			at   time.Duration
			want int
		}{{time.Second, 1}, {3 * time.Second, 2}, {7 * time.Second, 3}, {15 * time.Second, 4}, {31 * time.Second, 5}} {
			time.Sleep(time.Until(start.Add(step.at)))
			synctest.Wait()
			got := r.server.Received()
			if len(got) != step.want {
				t.Fatalf("at %v the server has %d packets, want %d", step.at, len(got), step.want)
			}
			if last := got[len(got)-1]; last.Opcode != wire.HardResetClientV2 || last.PacketID != 0 {
				t.Fatalf("the packet is %+v, want the reset again", last)
			}
		}
	})
}

func TestHandshakeTimeout(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newRig(t, rigOptions{transport: tr, wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.Silent}})
				start := time.Now()
				err := r.session.Handshake(t.Context())
				appErr, ok := errors.FromError(err)
				if !ok {
					t.Fatalf("expected *errors.Error, got %T: %v", err, err)
				}
				if appErr.Tag != TagHandshakeTimeout || !appErr.HasRoute("loop.HandshakeTimeout") {
					t.Errorf("unexpected failure path: %s", appErr.Route())
				}
				if elapsed := time.Since(start); elapsed != handshakeTimeout {
					t.Errorf("failed after %v, want %v", elapsed, handshakeTimeout)
				}
				// The error that ended the session is the one every call returns.
				if again := r.session.Handshake(t.Context()); again != err {
					t.Errorf("a second Handshake returned %v, want the same error", again)
				}
				// And nothing of the session runs any more, even before Close.
				synctest.Wait()
			})
		})
	}
}

func TestHandshakeFailsWhenTheServerAcksAnotherSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRig(t, rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.WrongAckSessionID}, timeout: 20 * time.Second})
		err := r.session.Handshake(t.Context())
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != TagHandshakeTimeout {
			t.Fatalf("Handshake = %v, want %s", err, TagHandshakeTimeout)
		}
		if r.session.Dropped() == 0 {
			t.Error("the packets that ack another session were not counted as dropped")
		}
	})
}

func TestHandshakeFailsWithAnotherKey(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		other := wrapKinds[2]
		other.server = func(t testing.TB) ctrlwrap.Wrapper {
			w, err := ctrlwrap.NewTLSCryptServer(testKey(99), time.Now)
			return mustWrapper(t, w, err)
		}
		r := newRig(t, rigOptions{transport: transports[0], wrap: other, timeout: 20 * time.Second})
		err := r.session.Handshake(t.Context())
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagHandshakeTimeout {
			t.Fatalf("Handshake = %v, want %s", err, TagHandshakeTimeout)
		}
		if r.server.Dropped() == 0 || len(r.server.Received()) != 0 {
			t.Errorf("the server dropped %d and took %d packets", r.server.Dropped(), len(r.server.Received()))
		}
	})
}

func TestHandshakeCanceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRig(t, rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.Silent}})
		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			time.Sleep(5 * time.Second)
			cancel()
		}()
		start := time.Now()
		err := r.session.Handshake(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Handshake = %v, want context.Canceled", err)
		}
		appErr, ok := errors.FromError(err)
		if !ok || !appErr.HasRoute("Handshake.HandshakeCanceled") {
			t.Errorf("unexpected failure path: %v", err)
		}
		if elapsed := time.Since(start); elapsed != 5*time.Second {
			t.Errorf("returned after %v, want 5s", elapsed)
		}
		// The context ended the session; the error stays.
		if again := r.session.Handshake(t.Context()); again != err {
			t.Errorf("a second Handshake returned %v, want the same error", again)
		}
		synctest.Wait()
	})

	t.Run("deadline", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newRig(t, rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.Silent}})
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			if err := r.session.Handshake(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Handshake = %v, want context.DeadlineExceeded", err)
			}
		})
	})
}

func TestAPacketFromAnotherSessionChangesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRig(t, rigOptions{transport: transports[0], wrap: wrapKinds[2]})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		before, dropped := len(r.server.Received()), r.session.Dropped()
		stranger := wire.RandomSessionID()
		// Protected the right way, but from another session: a control packet,
		// an ack, and a reset.
		for _, c := range []wire.Control{
			{Opcode: wire.ControlV1, SessionID: stranger, PacketID: 1, Payload: []byte("x")},
			{Opcode: wire.AckV1, SessionID: stranger, Acks: []uint32{0}, RemoteSessionID: r.server.SessionID()},
			{Opcode: wire.HardResetServerV2, SessionID: stranger, PacketID: 0},
		} {
			if err := r.server.Inject(c); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if got := r.session.Dropped() - dropped; got != 3 {
			t.Errorf("%d packets were dropped, want 3", got)
		}
		// Nothing was acknowledged or sent in answer.
		if got := len(r.server.Received()); got != before {
			t.Errorf("the client sent %d packets after the strangers' packets", got-before)
		}
	})
}

func TestPacketsThatDoNotBelongAreDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRig(t, rigOptions{transport: transports[0], wrap: wrapKinds[2], server: vpntest.ServerOptions{Fault: vpntest.Silent}})
		go func() { _ = r.session.Handshake(t.Context()) }()
		synctest.Wait()
		garbage := [][]byte{
			nil,
			{0x00},
			make([]byte, 8),
			make([]byte, 9),
			make([]byte, 200),
			append([]byte{wire.FirstByte(wire.HardResetServerV2, 0)}, make([]byte, 100)...), // right opcode, wrong protection
			append([]byte{wire.FirstByte(wire.DataV2, 0)}, make([]byte, 100)...),
			append([]byte{wire.FirstByte(wire.ControlV1, 5)}, make([]byte, 100)...), // key id 5
		}
		for _, g := range garbage {
			if _, err := r.peer.Write(g); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if got := r.session.Dropped(); got != uint64(len(garbage)) {
			t.Errorf("%d packets dropped, want %d", got, len(garbage))
		}
	})
}

func TestCloseStopsEveryGoroutine(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				before := runtime.NumGoroutine()
				var client, peer net.Conn
				if tr.stream {
					client, peer = vpntest.NewStreamPair()
				} else {
					client, peer = vpntest.NewDatagramPair(vpntest.LinkOptions{})
				}
				server := vpntest.NewServer(t, peer, vpntest.ServerOptions{Stream: tr.stream})
				s := New(Options{Link: client, Stream: tr.stream, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Minute})
				if err := s.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				if runtime.NumGoroutine() <= before {
					t.Fatal("the session runs no goroutine after the handshake?")
				}
				if err := s.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				// Close has returned: the session's goroutines are done. The
				// server's are not part of the session; stop them to count.
				server.Close()
				synctest.Wait()
				if after := runtime.NumGoroutine(); after != before {
					t.Errorf("%d goroutines before, %d after Close", before, after)
				}
				if err := s.Handshake(t.Context()); err != net.ErrClosed {
					t.Errorf("Handshake after Close = %v, want net.ErrClosed", err)
				}
				if err := s.Close(); err != net.ErrClosed {
					t.Errorf("a second Close = %v, want net.ErrClosed", err)
				}
			})
		})
	}
}

func TestCloseBeforeTheHandshakeClosesTheLink(t *testing.T) {
	client, peer := vpntest.NewDatagramPair(vpntest.LinkOptions{})
	closeAtEnd(t, peer)
	s := New(Options{Link: client, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Minute})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("x")); err != net.ErrClosed {
		t.Errorf("the link is not closed: Write = %v", err)
	}
	if err := s.Handshake(t.Context()); err != net.ErrClosed {
		t.Errorf("Handshake = %v, want net.ErrClosed", err)
	}
}

func TestCloseWhileTheHandshakeWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRig(t, rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.Silent}})
		result := make(chan error, 1)
		go func() { result <- r.session.Handshake(t.Context()) }()
		synctest.Wait()
		if err := r.session.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != net.ErrClosed {
			t.Errorf("Handshake = %v, want net.ErrClosed", err)
		}
	})
}

// brokenConn is a link whose operations fail on demand.
type brokenConn struct {
	net.Conn
	writeErr error
	closeErr error
}

func (b *brokenConn) Write(p []byte) (int, error) {
	if b.writeErr != nil {
		return 0, b.writeErr
	}
	return b.Conn.Write(p)
}

func (b *brokenConn) Close() error {
	err := b.Conn.Close()
	if b.closeErr != nil {
		return b.closeErr
	}
	return err
}

func TestLinkFailures(t *testing.T) {
	boom := os.ErrInvalid
	t.Run("write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			client, peer := vpntest.NewStreamPair()
			closeAtEnd(t, peer)
			s := New(Options{Link: &brokenConn{Conn: client, writeErr: os.ErrPermission}, Stream: true, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Minute})
			closeAtEnd(t, s)
			err := s.Handshake(t.Context())
			appErr, ok := errors.FromError(err)
			if !ok || appErr.Tag != TagLinkFailed || !appErr.HasRoute("send.LinkFailed") {
				t.Fatalf("Handshake = %v, want a failed write", err)
			}
			if !errors.Is(err, os.ErrPermission) {
				t.Errorf("the cause is lost: %v", err)
			}
		})
	})
	t.Run("read of a stream that ends", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			client, peer := vpntest.NewStreamPair()
			go drain(peer) // a pipe has no buffer: someone reads what the session writes
			s := New(Options{Link: client, Stream: true, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Minute})
			closeAtEnd(t, s)
			result := make(chan error, 1)
			go func() { result <- s.Handshake(t.Context()) }()
			synctest.Wait()
			if err := peer.Close(); err != nil {
				t.Fatal(err)
			}
			err := <-result
			appErr, ok := errors.FromError(err)
			if !ok || appErr.Tag != TagLinkFailed || !appErr.HasRoute("readLoop.LinkFailed") {
				t.Fatalf("Handshake = %v, want a failed read (tag %s, route %s)", err, appErr.Tag, appErr.Route())
			}
		})
	})
	t.Run("read of a frame that is cut", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			client, peer := vpntest.NewStreamPair()
			go drain(peer) // a pipe has no buffer: someone reads what the session writes
			s := New(Options{Link: client, Stream: true, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Minute})
			closeAtEnd(t, s)
			result := make(chan error, 1)
			go func() { result <- s.Handshake(t.Context()) }()
			synctest.Wait()
			go func() {
				// A frame of 50 bytes, and 3 of them, and the end.
				_, _ = peer.Write([]byte{0, 50, 1, 2, 3})
				_ = peer.Close()
			}()
			err := <-result
			if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagLinkFailed || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("Handshake = %v (%v), want a failed read with an unexpected EOF", err, appErr)
			}
		})
	})
	t.Run("close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			client, peer := vpntest.NewDatagramPair(vpntest.LinkOptions{})
			closeAtEnd(t, peer)
			s := New(Options{Link: &brokenConn{Conn: client, closeErr: boom}, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Second})
			_ = s.Handshake(t.Context()) // times out: the loop closes the link
			err := s.Close()
			appErr, ok := errors.FromError(err)
			if !ok || appErr.Tag != tagLinkCloseFailed || !appErr.HasRoute("closeLink.LinkCloseFailed") {
				t.Fatalf("Close = %v, want a failed close of the link", err)
			}
		})
	})
	t.Run("close before the start", func(t *testing.T) {
		client, peer := vpntest.NewDatagramPair(vpntest.LinkOptions{})
		closeAtEnd(t, peer)
		s := New(Options{Link: &brokenConn{Conn: client, closeErr: boom}, Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Second})
		err := s.Close()
		if appErr, ok := errors.FromError(err); !ok || !appErr.HasRoute("Close.LinkCloseFailed") {
			t.Fatalf("Close = %v, want a failed close of the link", err)
		}
	})
}

func TestNewPanicsWithoutRequiredOptions(t *testing.T) {
	client, peer := vpntest.NewDatagramPair(vpntest.LinkOptions{})
	closeAtEnd(t, client)
	closeAtEnd(t, peer)
	for name, o := range map[string]Options{
		"no link":    {Wrapper: ctrlwrap.NewPlain(), HandshakeTimeout: time.Second},
		"no wrapper": {Link: client, HandshakeTimeout: time.Second},
		"no timeout": {Link: client, Wrapper: ctrlwrap.NewPlain()},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: New did not panic", name)
				}
			}()
			New(o)
		}()
	}
}

// drain reads and throws away what comes to c, until c ends.
func drain(c net.Conn) {
	if _, err := io.Copy(io.Discard, c); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		panic(err)
	}
}

func TestSessionThatCannotStart(t *testing.T) {
	client, peer := vpntest.NewDatagramPair(vpntest.LinkOptions{})
	closeAtEnd(t, peer)
	cause := os.ErrInvalid
	s := New(Options{Link: client, Err: cause})
	if err := s.Handshake(t.Context()); err != cause {
		t.Errorf("Handshake = %v, want the error it was given", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	if _, err := client.Write([]byte("x")); err != net.ErrClosed {
		t.Errorf("the link is not closed: Write = %v", err)
	}
}

// closeAtEnd closes c when the test ends; a connection that is closed already is fine.
func closeAtEnd(t testing.TB, c io.Closer) {
	t.Helper()
	t.Cleanup(func() {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Close: %v", err)
		}
	})
}

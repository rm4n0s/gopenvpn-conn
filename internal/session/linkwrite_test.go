// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"context"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// faultConn is a link whose writes fail, or do not return, on demand. A write that
// is stuck returns when the link is closed or its write deadline passes, as the
// write of a TCP connection whose peer does not read does.
type faultConn struct {
	net.Conn
	mu       sync.Mutex
	writeErr error // what every Write returns while it is set
	stuck    bool
	wd       time.Time
	changed  chan struct{} // closed, and replaced, by every change
	closed   chan struct{}
	once     sync.Once
}

func newFaultConn(c net.Conn) *faultConn {
	return &faultConn{Conn: c, changed: make(chan struct{}), closed: make(chan struct{})}
}

func (c *faultConn) set(f func(*faultConn)) {
	c.mu.Lock()
	f(c)
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
}

func (c *faultConn) SetWriteDeadline(t time.Time) error {
	c.set(func(c *faultConn) { c.wd = t })
	return c.Conn.SetWriteDeadline(t)
}

func (c *faultConn) Write(p []byte) (int, error) {
	for {
		c.mu.Lock()
		err, stuck, wd, changed := c.writeErr, c.stuck, c.wd, c.changed
		c.mu.Unlock()
		if err != nil {
			return 0, err
		}
		if !stuck {
			return c.Conn.Write(p)
		}
		timer, expired := timerFor(wd)
		select {
		case <-changed:
			stopTimer(timer)
		case <-c.closed:
			stopTimer(timer)
			return 0, net.ErrClosed
		case <-expired:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *faultConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// faultRig is a session over a faultConn, whose server pushes push.
func faultRig(t *testing.T, tr transport, push string, ping [2]time.Duration) (*tlsRig, *faultConn) {
	t.Helper()
	var link *faultConn
	r := newTLSRig(t, tlsOptions{
		rigOptions: rigOptions{transport: tr, wrap: wrapKinds[0], server: vpntest.ServerOptions{PushMessages: []string{push}}},
		ping:       ping,
		wrapLink: func(c net.Conn) net.Conn {
			link = newFaultConn(c)
			return link
		},
	})
	return r, link
}

// TestOverduePingIsDueNow: a ping whose time has passed is due at once. It used to
// wait for the timeout of the keepalive (the time left of ping-restart), so that a
// loop that woke just after the ping was due sent none until the application wrote,
// and the server gave the client up.
func TestOverduePingIsDueNow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Session{base: time.Now(), kaOn: true, kaInterval: 10 * time.Second, kaTimeout: 60 * time.Second, lastRecv: time.Now()}
		s.touchSent()
		time.Sleep(4 * time.Second)
		if wait, ok := s.keepaliveWait(); !ok || wait != 6*time.Second {
			t.Errorf("4 s after a packet went out the wait is %v, %v; want 6s", wait, ok)
		}
		time.Sleep(7 * time.Second) // the ping is 1 s overdue
		if wait, ok := s.keepaliveWait(); !ok || wait != 0 {
			t.Errorf("with the ping overdue the wait is %v, %v; want 0", wait, ok)
		}
		// Only a timeout.
		s.kaInterval = 0
		if wait, ok := s.keepaliveWait(); !ok || wait != 49*time.Second {
			t.Errorf("with only a timeout the wait is %v, %v; want 49s", wait, ok)
		}
	})
}

// TestPingsGoOnWhenTheLoopWakesLate: packets that arrive just after a ping is due do
// not stop the pings. The server's packets come 1 ms after each time that the
// client's ping is due, for two minutes; the client pings all the same.
func TestPingsGoOnWhenTheLoopWakesLate(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := keepaliveRig(t, tr, ",ping 10", ",ping-restart 60", Options{})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Millisecond)
				for range 12 {
					time.Sleep(10 * time.Second)
					if err := r.server.SendPing(); err != nil {
						t.Fatal(err)
					}
				}
				synctest.Wait()
				if err := r.session.Err(); err != nil {
					t.Fatalf("the session ended: %v", err)
				}
				if got := r.server.Pings(); got < 11 {
					t.Errorf("the client sent %d pings in two minutes, want one every 10 s", got)
				}
			})
		})
	}
}

// TestDatagramWriteErrorsDoNotEndTheSession: a write of a datagram link that fails
// loses its packet and nothing more, as OpenVPN logs it and goes on; the keepalive
// decides whether the server is gone.
func TestDatagramWriteErrorsDoNotEndTheSession(t *testing.T) {
	t.Run("the packets are lost and the session goes on", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, link := faultRig(t, transports[0], vpntest.DefaultPushReply, [2]time.Duration{})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			synctest.Wait() // the writes of the handshake are out
			for _, cause := range []error{syscall.ENETUNREACH, syscall.ECONNREFUSED, syscall.ENOBUFS, syscall.EPERM} {
				link.set(func(c *faultConn) { c.writeErr = &net.OpError{Op: "write", Net: "udp", Err: cause} })
				if n, err := r.session.Write([]byte{0x45, 1}); err != nil || n != 2 {
					t.Fatalf("Write with %v on the link = %d, %v; want the packet taken and lost", cause, n, err)
				}
			}
			// The pings of 25 seconds fail too, and the server's keep the session alive.
			serverKeepsAlive(t, r, 5*time.Second, 25*time.Second)
			if err := r.session.Err(); err != nil {
				t.Fatalf("the session ended: %v", err)
			}
			if got := len(r.server.DataReceived()); got != 0 {
				t.Fatalf("the server got %d packets through a link that fails", got)
			}
			link.set(func(c *faultConn) { c.writeErr = nil })
			if _, err := r.session.Write([]byte{0x45, 2}); err != nil {
				t.Fatalf("Write after the link came back: %v", err)
			}
			if got := serverGot(t, r, 1); got[0][1] != 2 {
				t.Errorf("the server got %x", got[0])
			}
		})
	})
	t.Run("silence still ends it, with the keepalive's error", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, link := faultRig(t, transports[0], vpntest.DefaultPushReply, [2]time.Duration{})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			// The writes of the handshake are out. An acknowledgement that the fault took
			// would make the server send its packet again and again, and the client would
			// hear the server for a minute more.
			synctest.Wait()
			link.set(func(c *faultConn) { c.writeErr = syscall.ENETUNREACH })
			_, err := r.session.Read(make([]byte, 10))
			wantRoute(t, err, TagPingTimeout, routeStart+"Session.loop->Session.keepaliveTick.PingTimeout")
		})
	})
	t.Run("with no keepalive timeout, writes that fail for two minutes end it", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := keepaliveRig(t, transports[0], "", "", Options{})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			// The link of this rig cannot fail, so the state of the writers is set as a
			// failing link would: the first failure was writeFailLimit ago.
			synctest.Wait() // the writes of the handshake are done
			r.session.wfailSince.Store(1)
			time.Sleep(writeFailLimit + time.Second)
			if got := r.session.classifyWrite(syscall.ENETUNREACH, 0, false); got != writeFatal {
				t.Errorf("after %v of failures classifyWrite = %d, want fatal", writeFailLimit, got)
			}
			r.session.wfailSince.Store(0)
			if got := r.session.classifyWrite(syscall.ENETUNREACH, 0, false); got != writeDropped {
				t.Errorf("a first failure is %d, want dropped", got)
			}
			if got := r.session.classifyWrite(net.ErrClosed, 0, false); got != writeFatal {
				t.Errorf("a closed link is %d, want fatal", got)
			}
		})
	})
	t.Run("before the server has answered a failed write ends the handshake at once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, link := faultRig(t, transports[0], vpntest.DefaultPushReply, [2]time.Duration{})
			link.set(func(c *faultConn) { c.writeErr = syscall.ENETUNREACH })
			start := time.Now()
			err := r.session.Handshake(t.Context())
			wantRoute(t, err, TagLinkFailed, routeStart+"Session.writeLoop->Session.writeLink.LinkFailed")
			if !errors.Is(err, syscall.ENETUNREACH) || time.Since(start) != 0 {
				t.Errorf("Handshake = %v after %v", err, time.Since(start))
			}
		})
	})
}

// TestStuckStreamLink: a stream link that takes no more bytes (a TCP connection
// whose path died during an upload) does not stop the session's timers.
func TestStuckStreamLink(t *testing.T) {
	t.Run("the keepalive ends the session and the stuck Write returns", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, link := faultRig(t, transports[1], vpntest.DefaultPushReply, [2]time.Duration{})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			// The writes of the handshake are out. An acknowledgement that the fault took
			// would make the server send its packet again and again, and the client would
			// hear the server for a minute more.
			synctest.Wait()
			link.set(func(c *faultConn) { c.stuck = true })
			start := time.Now()
			wrote := make(chan error, 1)
			go func() { _, err := r.session.Write([]byte{0x45, 1}); wrote <- err }()
			_, err := r.session.Read(make([]byte, 10))
			wantRoute(t, err, TagPingTimeout, routeStart+"Session.loop->Session.keepaliveTick.PingTimeout")
			if elapsed := time.Since(start); elapsed < 59*time.Second || elapsed > 61*time.Second {
				t.Errorf("the session ended after %v, want the ping-restart of 60 s", elapsed)
			}
			if werr := <-wrote; werr != err {
				t.Errorf("the stuck Write returned %v, want the error of the session", werr)
			}
		})
	})
	t.Run("Close returns, with EXIT to send and a Write stuck", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			before := vpntest.BubbleGoroutines()
			r, link := faultRig(t, transports[1], ccExitPush, [2]time.Duration{})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			// The writes of the handshake are out. An acknowledgement that the fault took
			// would make the server send its packet again and again, and the client would
			// hear the server for a minute more.
			synctest.Wait()
			link.set(func(c *faultConn) { c.stuck = true })
			wrote := make(chan error, 1)
			go func() { _, err := r.session.Write([]byte{0x45, 1}); wrote <- err }()
			synctest.Wait()
			start := time.Now()
			if err := r.session.Close(); err != nil {
				t.Errorf("Close = %v", err)
			}
			if elapsed := time.Since(start); elapsed > 3*exitWait {
				t.Errorf("Close took %v", elapsed)
			}
			if werr := <-wrote; werr != net.ErrClosed {
				t.Errorf("the stuck Write returned %v, want net.ErrClosed", werr)
			}
			r.server.Close()
			synctest.Wait()
			if after := vpntest.BubbleGoroutines(); after > before {
				t.Errorf("%d goroutines before, %d after Close", before, after)
			}
		})
	})
	t.Run("a write deadline that is set later wakes the stuck Write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, link := faultRig(t, transports[1], vpntest.DefaultPushReply, [2]time.Duration{})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			// The writes of the handshake are out. An acknowledgement that the fault took
			// would make the server send its packet again and again, and the client would
			// hear the server for a minute more.
			synctest.Wait()
			link.set(func(c *faultConn) { c.stuck = true })
			wrote := make(chan error, 1)
			go func() { _, err := r.session.Write([]byte{0x45, 1}); wrote <- err }()
			time.Sleep(3 * time.Second)
			start := time.Now()
			if err := r.session.SetWriteDeadline(start.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := <-wrote; err != os.ErrDeadlineExceeded {
				t.Fatalf("the stuck Write returned %v, want os.ErrDeadlineExceeded", err)
			}
			if elapsed := time.Since(start); elapsed != time.Second {
				t.Errorf("the Write returned %v after the deadline was set", elapsed)
			}
			// No byte of the frame was out: the session goes on, and the deadline is not
			// left on the link, where it would cut a control packet.
			link.set(func(c *faultConn) { c.stuck = false })
			if err := r.session.SetWriteDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if _, err := r.session.Write([]byte{0x45, 2}); err != nil {
				t.Fatalf("Write after the timeout = %v", err)
			}
			link.mu.Lock()
			wd := link.wd
			link.mu.Unlock()
			if !wd.IsZero() {
				t.Errorf("the link is left with the write deadline %v", wd)
			}
			if err := r.session.Err(); err != nil {
				t.Errorf("the session ended: %v", err)
			}
		})
	})
	t.Run("packets still come in while the link takes none", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, link := faultRig(t, transports[1], vpntest.DefaultPushReply, [2]time.Duration{})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			// The writes of the handshake are out. An acknowledgement that the fault took
			// would make the server send its packet again and again, and the client would
			// hear the server for a minute more.
			synctest.Wait()
			link.set(func(c *faultConn) { c.stuck = true })
			wrote := make(chan error, 1)
			go func() { _, err := r.session.Write([]byte{0x45, 1}); wrote <- err }()
			time.Sleep(15 * time.Second) // a ping was due: the loop must not wait for the link
			if _, err := r.server.SendData([]byte{0x45, 9}); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 10)
			if n, err := r.session.Read(buf); err != nil || n != 2 || buf[1] != 9 {
				t.Fatalf("Read = %d, %v: the packet of the server did not arrive", n, err)
			}
			link.set(func(c *faultConn) { c.stuck = false })
			if err := <-wrote; err != nil {
				t.Errorf("the Write returned %v when the link took bytes again", err)
			}
		})
	})
}

// TestHandshakeAgainWithADoneContext: Handshake on a session that is up is a no-op,
// also with a context that is done. It used to end the session half of the time (the
// select took the context's branch) and still return nil.
func TestHandshakeAgainWithADoneContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := dataRig(t, transports[0], "AES-256-GCM", false, vpntest.ServerOptions{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		for i := range 200 {
			if err := r.session.Handshake(ctx); err != nil {
				t.Fatalf("call %d: Handshake = %v", i, err)
			}
			if err := r.session.Err(); err != nil {
				t.Fatalf("call %d ended the session: %v", i, err)
			}
		}
		if _, err := r.session.Write([]byte{0x45, 1}); err != nil {
			t.Fatalf("Write after the calls: %v", err)
		}
		serverGot(t, r, 1)
	})
}

// TestServerPollTimeout: ServerPollTimeout ends the wait for a server that does not
// answer, and bounds nothing once it has answered (OpenVPN's connect-timeout: a
// handshake with a slow login is not cut by it).
func TestServerPollTimeout(t *testing.T) {
	t.Run("a server that does not answer", func(t *testing.T) {
		for _, tr := range transports {
			synctest.Test(t, func(t *testing.T) {
				r := newTLSRig(t, tlsOptions{
					rigOptions: rigOptions{transport: tr, wrap: wrapKinds[0], server: vpntest.ServerOptions{Fault: vpntest.Silent}},
					tweak:      func(o *Options) { o.ServerPollTimeout = 4 * time.Second },
				})
				start := time.Now()
				err := r.session.Handshake(t.Context())
				wantRoute(t, err, TagServerPollTimeout, routeStart+"Session.loop.ServerPollTimeout")
				if elapsed := time.Since(start); elapsed != 4*time.Second {
					t.Errorf("%s: failed after %v, want 4s", tr.name, elapsed)
				}
				if appErr, _ := errors.FromError(err); appErr.Metadata["timeout"] != "4s" {
					t.Errorf("metadata = %v", appErr.Metadata)
				}
			})
		}
	})
	t.Run("a server that has answered has the time of the handshake", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newTLSRig(t, tlsOptions{
				rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{PushMessages: []string{vpntest.DefaultPushReply}}},
				tweak: func(o *Options) {
					o.ServerPollTimeout = 4 * time.Second
					o.Credentials = func(context.Context) (string, string, error) {
						time.Sleep(10 * time.Second) // someone types a password
						return "alice", "secret", nil
					}
				},
			})
			start := time.Now()
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatalf("Handshake = %v", err)
			}
			if elapsed := time.Since(start); elapsed < 10*time.Second {
				t.Errorf("the handshake took %v: the test did not go past the poll timeout", elapsed)
			}
		})
	})
}

// TestAPushedOptionThatCannotBeReadDoesNotEndTheHandshake: the route to the server
// itself, past the VPN, which real servers push; the client used to refuse to connect.
func TestAPushedOptionThatCannotBeReadDoesNotEndTheHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		push := vpntest.DefaultPushReply + ",route remote_host 255.255.255.255 net_gateway,route 10.9.0.0 255.255.255.0,dhcp-option DNS nope"
		r := newTLSRig(t, tlsOptions{
			rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{PushMessages: []string{push}}},
		})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatalf("Handshake = %v", err)
		}
		p := r.session.Pushed()
		if len(p.Skipped) != 2 || p.Skipped[0].Option != "route" || p.Skipped[1].Option != "dhcp-option" {
			t.Errorf("Skipped = %+v", p.Skipped)
		}
		if len(p.Routes) != 1 {
			t.Errorf("routes = %v, want the one that can be read", p.Routes)
		}
	})
}

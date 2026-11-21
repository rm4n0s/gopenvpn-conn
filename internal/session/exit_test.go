// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// ccExitPush is the usual push reply, with the flags of a server that takes the exit
// message of the control channel.
var ccExitPush = vpntest.DefaultPushReply + ",protocol-flags cc-exit tls-ekm"

// muteConn is a link whose writes can be made to vanish (the server then never
// hears from the client), or to block until the write deadline, as a full TCP buffer
// does.
type muteConn struct {
	net.Conn
	mu     sync.Mutex
	mute   bool
	block  bool
	part   int // with block: how many bytes of the write are out when the deadline passes
	wd     time.Time
	writes int
}

func (c *muteConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wd = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *muteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	mute, block, part, wd := c.mute, c.block, c.part, c.wd
	c.writes++
	c.mu.Unlock()
	switch {
	case block && !wd.IsZero():
		time.Sleep(time.Until(wd))
		return min(part, len(p)), os.ErrDeadlineExceeded
	case mute:
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *muteConn) set(f func(*muteConn)) {
	c.mu.Lock()
	f(c)
	c.mu.Unlock()
}

func exitRig(t *testing.T, tr transport, push string, extra ...func(*tlsOptions)) (*tlsRig, *muteConn) {
	t.Helper()
	var link *muteConn
	o := tlsOptions{
		rigOptions: rigOptions{transport: tr, wrap: wrapKinds[0], server: vpntest.ServerOptions{PushMessages: []string{push}}},
		wrapLink: func(c net.Conn) net.Conn {
			link = &muteConn{Conn: c}
			return link
		},
	}
	for _, f := range extra {
		f(&o)
	}
	return newTLSRig(t, o), link
}

func TestCloseSaysEXITWhenTheServerTakesIt(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				before := vpntest.BubbleGoroutines()
				r, _ := exitRig(t, tr, ccExitPush)
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				if err := r.session.Close(); err != nil {
					t.Fatal(err)
				}
				if elapsed := time.Since(start); elapsed >= exitWait {
					t.Errorf("Close took %v: it waited for an acknowledgement that came at once", elapsed)
				}
				synctest.Wait()
				if got := r.server.Exits(); got != 1 {
					t.Errorf("the server got %d EXIT messages, want 1", got)
				}
				if got := r.server.OCCExits(); got != 0 {
					t.Errorf("the server got %d data exit packets with cc-exit", got)
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

// When the server does not answer, Close waits one second for it, and no more.
func TestCloseDoesNotWaitLongForAnEXITNobodyAcknowledges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, link := exitRig(t, transports[0], ccExitPush)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		link.set(func(c *muteConn) { c.mute = true })
		start := time.Now()
		if err := r.session.Close(); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed != exitWait {
			t.Errorf("Close took %v, want %v", elapsed, exitWait)
		}
		if got := r.server.Exits(); got != 0 {
			t.Errorf("the server got %d EXIT messages through a mute link", got)
		}
	})
}

func TestCloseWhenTheServerIsGone(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r, _ := exitRig(t, tr, ccExitPush)
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				r.server.Close() // closes its end of the link
				start := time.Now()
				if err := r.session.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("Close = %v", err)
				}
				if elapsed := time.Since(start); elapsed > exitWait {
					t.Errorf("Close took %v with the server gone", elapsed)
				}
			})
		})
	}
}

// Without cc-exit a datagram link carries the exit message of the data channel, once;
// a stream carries none.
func TestCloseWithoutCCExit(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r, _ := exitRig(t, tr, vpntest.DefaultPushReply)
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := r.session.Close(); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				want := 1
				if tr.stream {
					want = 0
				}
				if got := r.server.OCCExits(); got != want {
					t.Errorf("the server got %d data exit packets, want %d", got, want)
				}
				if got := r.server.Exits(); got != 0 {
					t.Errorf("the server got %d EXIT messages without cc-exit", got)
				}
			})
		})
	}
}

func TestCloseBeforeTheHandshakeSaysNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, _ := exitRig(t, transports[0], ccExitPush)
		if err := r.session.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if r.server.Exits() != 0 || r.server.OCCExits() != 0 {
			t.Error("exit messages before the handshake")
		}
	})
}

func TestCloseTwice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, _ := exitRig(t, transports[0], ccExitPush)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := r.session.Close(); err != nil {
			t.Fatal(err)
		}
		if err := r.session.Close(); err != net.ErrClosed {
			t.Errorf("the second Close = %v, want net.ErrClosed", err)
		}
	})
}

// A Close that is still waiting for its acknowledgement is not joined by another.
func TestCloseWhileClosing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, link := exitRig(t, transports[0], ccExitPush)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		link.set(func(c *muteConn) { c.mute = true })
		first := make(chan error, 1)
		go func() { first <- r.session.Close() }()
		synctest.Wait()
		if err := r.session.Close(); err != net.ErrClosed {
			t.Errorf("a Close during the first = %v, want net.ErrClosed", err)
		}
		if err := r.session.SetDeadline(time.Now()); err != net.ErrClosed {
			t.Errorf("SetDeadline during Close = %v, want net.ErrClosed", err)
		}
		if err := <-first; err != nil {
			t.Errorf("the first Close = %v", err)
		}
	})
}

func TestServerEXITEndsTheSessionWithEOF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, _ := exitRig(t, transports[0], ccExitPush)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := r.session.Read(make([]byte, 10)); done <- err }()
		synctest.Wait()
		r.server.SendControl("EXIT")
		if err := <-done; err != io.EOF { // compared with ==, as io.Copy does
			t.Errorf("Read = %v, want io.EOF itself", err)
		}
		if _, err := r.session.Read(make([]byte, 10)); err != io.EOF {
			t.Errorf("a second Read = %v, want io.EOF", err)
		}
		if _, err := r.session.Write([]byte{0x45}); err != io.EOF {
			t.Errorf("Write = %v, want io.EOF", err)
		}
	})
}

func TestServerOCCExitEndsTheSessionWithEOF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, _ := exitRig(t, transports[0], vpntest.DefaultPushReply)
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := r.server.SendOCCExit(); err != nil {
			t.Fatal(err)
		}
		if _, err := r.session.Read(make([]byte, 10)); err != io.EOF {
			t.Errorf("Read = %v, want io.EOF", err)
		}
	})
}

func TestServerEXITBeforeTheHandshakeIsComplete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newTLSRig(t, tlsOptions{rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0],
			server: vpntest.ServerOptions{EarlyMessages: []string{"EXIT"}, PushMessages: []string{}}}})
		err := r.session.Handshake(t.Context())
		wantRoute(t, err, TagServerExit, "Session.serverExited.ServerExit")
	})
}

func TestDeadlines(t *testing.T) {
	t.Run("a Read that waits gives up when the deadline comes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, _ := exitRig(t, transports[0], vpntest.DefaultPushReply)
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if err := r.session.SetReadDeadline(start.Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			_, err := r.session.Read(make([]byte, 10))
			if err != os.ErrDeadlineExceeded { // that value, not a wrapper of it
				t.Fatalf("Read = %v, want os.ErrDeadlineExceeded", err)
			}
			if elapsed := time.Since(start); elapsed != 3*time.Second {
				t.Errorf("Read gave up after %v", elapsed)
			}
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Errorf("the error is no net.Error with Timeout: %v", err)
			}
			// The session is alive: a later deadline and a packet work.
			if err := r.session.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if _, err := r.server.SendData([]byte{0x45, 1}); err != nil {
				t.Fatal(err)
			}
			if n, err := r.session.Read(make([]byte, 10)); err != nil || n != 2 {
				t.Errorf("Read after the timeout = %d, %v", n, err)
			}
		})
	})
	t.Run("a deadline in the past unblocks a Read in progress", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, _ := exitRig(t, transports[0], vpntest.DefaultPushReply)
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := r.session.Read(make([]byte, 10)); done <- err }()
			synctest.Wait()
			if err := r.session.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != os.ErrDeadlineExceeded {
				t.Errorf("Read = %v", err)
			}
		})
	})
	t.Run("an expired deadline wins over a packet that waits", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, _ := exitRig(t, transports[0], vpntest.DefaultPushReply)
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := r.server.SendData([]byte{0x45, 1}); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			if err := r.session.SetReadDeadline(time.Now().Add(-time.Nanosecond)); err != nil {
				t.Fatal(err)
			}
			if _, err := r.session.Read(make([]byte, 10)); err != os.ErrDeadlineExceeded {
				t.Errorf("Read = %v", err)
			}
			if err := r.session.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if n, err := r.session.Read(make([]byte, 10)); err != nil || n != 2 {
				t.Errorf("the packet is still there: %d, %v", n, err)
			}
		})
	})
	t.Run("moving the deadline of a Read that waits", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, _ := exitRig(t, transports[0], vpntest.DefaultPushReply)
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if err := r.session.SetReadDeadline(start.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := r.session.Read(make([]byte, 10)); done <- err }()
			synctest.Wait()
			if err := r.session.SetDeadline(start.Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != os.ErrDeadlineExceeded {
				t.Errorf("Read = %v", err)
			}
			if elapsed := time.Since(start); elapsed != 5*time.Second {
				t.Errorf("Read gave up after %v, want 5s", elapsed)
			}
		})
	})
	t.Run("a Write after its deadline sends nothing", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, _ := exitRig(t, transports[0], vpntest.DefaultPushReply)
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := r.session.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := r.session.Write([]byte{0x45, 1}); err != os.ErrDeadlineExceeded {
				t.Fatalf("Write = %v", err)
			}
			if err := r.session.SetWriteDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if _, err := r.session.Write([]byte{0x45, 2}); err != nil {
				t.Fatal(err)
			}
			got := serverGot(t, r, 1)
			if !bytes.Equal(got[0], []byte{0x45, 2}) {
				t.Errorf("the server got %x", got[0])
			}
		})
	})
	t.Run("a Write that the link does not take, on a datagram link", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, link := exitRig(t, transports[0], vpntest.DefaultPushReply)
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			link.set(func(c *muteConn) { c.block = true })
			start := time.Now()
			if err := r.session.SetWriteDeadline(start.Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := r.session.Write([]byte{0x45, 1}); err != os.ErrDeadlineExceeded {
				t.Fatalf("Write = %v", err)
			}
			if elapsed := time.Since(start); elapsed != 2*time.Second {
				t.Errorf("Write gave up after %v", elapsed)
			}
			// Nothing was out, so the session goes on.
			link.set(func(c *muteConn) { c.block = false })
			if err := r.session.SetWriteDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if _, err := r.session.Write([]byte{0x45, 2}); err != nil {
				t.Errorf("Write after the timeout = %v", err)
			}
		})
	})
	t.Run("a Write that is cut in the middle of a frame ends a stream session", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, link := exitRig(t, transports[1], vpntest.DefaultPushReply)
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			link.set(func(c *muteConn) { c.block, c.part = true, 7 })
			if err := r.session.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := r.session.Write([]byte{0x45, 1}); err == os.ErrDeadlineExceeded {
				t.Fatal("a cut frame was reported as a plain timeout: the stream is broken")
			}
			err := r.session.Err()
			if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagLinkFailed || appErr.Metadata["op"] != "write" || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("the session ended with %v, want %s", err, TagLinkFailed)
			}
		})
	})
	t.Run("a Write that waits for another is released by its deadline", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, link := exitRig(t, transports[0], vpntest.DefaultPushReply)
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			link.set(func(c *muteConn) { c.block = true })
			start := time.Now()
			// The first Write holds the right to write, blocked in the link until its deadline.
			if err := r.session.SetWriteDeadline(start.Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			first := make(chan error, 1)
			go func() { _, err := r.session.Write([]byte{0x45, 1}); first <- err }()
			synctest.Wait()
			second := make(chan error, 1)
			go func() { _, err := r.session.Write([]byte{0x45, 2}); second <- err }()
			synctest.Wait()
			if err := r.session.SetWriteDeadline(start.Add(4 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := <-second; err != os.ErrDeadlineExceeded {
				t.Errorf("the second Write = %v", err)
			}
			if elapsed := time.Since(start); elapsed != 4*time.Second {
				t.Errorf("the second Write gave up after %v, want 4s", elapsed)
			}
			if err := <-first; err != os.ErrDeadlineExceeded {
				t.Errorf("the first Write = %v", err)
			}
		})
	})
	t.Run("after Close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r, _ := exitRig(t, transports[0], vpntest.DefaultPushReply)
			if err := r.session.Close(); err != nil {
				t.Fatal(err)
			}
			for name, f := range map[string]func(time.Time) error{
				"SetDeadline": r.session.SetDeadline, "SetReadDeadline": r.session.SetReadDeadline, "SetWriteDeadline": r.session.SetWriteDeadline,
			} {
				if err := f(time.Now()); err != net.ErrClosed {
					t.Errorf("%s after Close = %v, want net.ErrClosed", name, err)
				}
			}
		})
	})
}

// Read, Write, deadlines and Close from many goroutines at once, under -race, end with
// every call returned and no goroutine left.
func TestManyCallersAndClose(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				before := vpntest.BubbleGoroutines()
				r, _ := exitRig(t, tr, ccExitPush, func(o *tlsOptions) { o.server.EchoData = true })
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				var wg sync.WaitGroup
				for i := range 4 {
					wg.Go(func() {
						buf := make([]byte, 100)
						for {
							if _, err := r.session.Read(buf); err != nil {
								if err != net.ErrClosed && err != os.ErrDeadlineExceeded {
									t.Errorf("Read %d: %v", i, err)
								}
								if err == net.ErrClosed {
									return
								}
							}
						}
					})
					wg.Go(func() {
						for {
							if _, err := r.session.Write([]byte{0x45, byte(i & 0xff)}); err != nil {
								if err != net.ErrClosed {
									t.Errorf("Write %d: %v", i, err)
								}
								return
							}
							time.Sleep(time.Millisecond)
						}
					})
				}
				wg.Go(func() {
					for range 20 {
						time.Sleep(3 * time.Millisecond)
						if err := r.session.SetDeadline(time.Now().Add(time.Millisecond)); err != nil && err != net.ErrClosed {
							t.Errorf("SetDeadline: %v", err)
						}
						if err := r.session.SetDeadline(time.Time{}); err != nil && err != net.ErrClosed {
							t.Errorf("SetDeadline: %v", err)
						}
					}
				})
				time.Sleep(100 * time.Millisecond)
				var closers sync.WaitGroup
				var mu sync.Mutex
				ok := 0
				for range 5 {
					closers.Go(func() {
						if err := r.session.Close(); err == nil {
							mu.Lock()
							ok++
							mu.Unlock()
						} else if err != net.ErrClosed {
							t.Errorf("Close = %v", err)
						}
					})
				}
				closers.Wait()
				wg.Wait()
				if ok != 1 {
					t.Errorf("%d Close calls returned nil, want 1", ok)
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

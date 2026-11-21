// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// keepaliveRig is a session whose server pushes the given ping and ping-restart
// ("" leaves the option out), with options for when it pushes none.
func keepaliveRig(t *testing.T, tr transport, ping, restart string, o Options) *tlsRig {
	t.Helper()
	reply := vpntest.DefaultPushReply
	reply = strings.Replace(reply, ",ping 10", ping, 1)
	reply = strings.Replace(reply, ",ping-restart 60", restart, 1)
	r := newTLSRig(t, tlsOptions{
		rigOptions: rigOptions{transport: tr, wrap: wrapKinds[0], server: vpntest.ServerOptions{PushMessages: []string{reply}}},
		ping:       [2]time.Duration{o.PingInterval, o.PingTimeout},
	})
	return r
}

// serverPings has the server send a keepalive every d, until the test's time is up.
func serverKeepsAlive(t *testing.T, r *tlsRig, every time.Duration, until time.Duration) {
	t.Helper()
	start := time.Now()
	for time.Since(start)+every <= until {
		time.Sleep(every)
		if err := r.server.SendPing(); err != nil {
			t.Fatal(err)
		}
	}
	synctest.Wait()
}

func TestIdleSessionSendsPings(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := keepaliveRig(t, tr, ",ping 10", ",ping-restart 60", Options{})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				time.Sleep(9*time.Second + 900*time.Millisecond)
				synctest.Wait()
				if got := r.server.Pings(); got != 0 {
					t.Fatalf("%d pings before the interval", got)
				}
				serverKeepsAlive(t, r, 10*time.Second, 35*time.Second)
				// At 10, 20 and 30 seconds of idle time, 35 seconds after the handshake.
				if got := r.server.Pings(); got != 3 {
					t.Errorf("%d pings in 35 seconds with ping 10, want 3", got)
				}
				if r.session.Dropped() != 0 {
					t.Errorf("%d packets dropped", r.session.Dropped())
				}
			})
		})
	}
}

// A packet that the client sends is a sign of life, so no ping goes out while data does.
func TestWritesPutOffThePing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := keepaliveRig(t, transports[0], ",ping 10", ",ping-restart 600", Options{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		for range 20 {
			time.Sleep(6 * time.Second)
			if _, err := r.session.Write([]byte{0x45, 1}); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if got := r.server.Pings(); got != 0 {
			t.Errorf("%d pings in 120 seconds of traffic every 6, want 0", got)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if got := r.server.Pings(); got != 1 {
			t.Errorf("%d pings 10 seconds after the last packet, want 1", got)
		}
	})
}

func TestPingsKeepTheSessionAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := keepaliveRig(t, transports[0], ",ping 10", ",ping-restart 60", Options{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		serverKeepsAlive(t, r, 10*time.Second, 10*time.Minute)
		// The pings are not packets for Read, and the session lives.
		select {
		case <-r.session.done:
			t.Fatalf("the session ended: %v", r.session.result())
		default:
		}
		if _, err := r.session.Write([]byte{0x45}); err != nil {
			t.Errorf("Write after 10 minutes of pings: %v", err)
		}
	})
}

func TestSilenceEndsTheSession(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := keepaliveRig(t, tr, ",ping 10", ",ping-restart 60", Options{})
				if err := r.session.Handshake(t.Context()); err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				_, errRead := r.session.Read(make([]byte, 10))
				if elapsed := time.Since(start); elapsed < 59*time.Second || elapsed > 61*time.Second {
					t.Errorf("Read gave up after %v, want about 60s", elapsed)
				}
				wantRoute(t, errRead, TagPingTimeout, "Session.loop->Session.keepaliveTick.PingTimeout")
				appErr, _ := errors.FromError(errRead)
				if appErr.Metadata["timeout"] != "1m0s" {
					t.Errorf("metadata = %v", appErr.Metadata)
				}
				_, errWrite := r.session.Write([]byte{0x45})
				if errWrite != errRead {
					t.Errorf("Write = %v, want the error of Read", errWrite)
				}
				// The client pinged in the meantime (at 10, 20, ... seconds).
				if got := r.server.Pings(); got < 5 {
					t.Errorf("%d pings in a minute of silence", got)
				}
			})
		})
	}
}

// Packets that do not authenticate are not a sign of life.
func TestForgeriesDoNotKeepTheSessionAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := keepaliveRig(t, transports[0], ",ping 10", ",ping-restart 60", Options{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		good, err := r.server.SendData([]byte{0x45, 1})
		if err != nil {
			t.Fatal(err)
		}
		forged := append([]byte(nil), good...)
		forged[len(forged)-1] ^= 1
		done := make(chan error, 1)
		go func() { _, err := r.session.Read(make([]byte, 10)); done <- err }()
		for range 5 {
			time.Sleep(10 * time.Second)
			if err := r.server.SendPacket(forged); err != nil {
				t.Fatal(err)
			}
			if err := r.server.SendPacket(good); err != nil { // a replay
				t.Fatal(err)
			}
		}
		synctest.Wait()
		// The one good packet was read; now the second Read waits and the silence ends it.
		_, err = r.session.Read(make([]byte, 10))
		wantRoute(t, err, TagPingTimeout, "Session.loop->Session.keepaliveTick.PingTimeout")
		if rerr := <-done; rerr != nil {
			t.Errorf("the first Read = %v, want the packet that the server sent", rerr)
		}
	})
}

func TestKeepaliveOfTheOptionsWhenNothingIsPushed(t *testing.T) {
	t.Run("they apply", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := keepaliveRig(t, transports[0], "", "", Options{PingInterval: 5 * time.Second, PingTimeout: 20 * time.Second})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			_, err := r.session.Read(make([]byte, 10))
			wantRoute(t, err, TagPingTimeout, "Session.loop->Session.keepaliveTick.PingTimeout")
			if elapsed := time.Since(start); elapsed < 19*time.Second || elapsed > 21*time.Second {
				t.Errorf("gave up after %v, want about 20s", elapsed)
			}
			if got := r.server.Pings(); got != 3 { // at 5, 10, 15 seconds
				t.Errorf("%d pings, want 3", got)
			}
		})
	})
	t.Run("what is pushed wins", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := keepaliveRig(t, transports[0], ",ping 10", ",ping-restart 60", Options{PingInterval: 2 * time.Second, PingTimeout: 5 * time.Second})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			_, err := r.session.Read(make([]byte, 10))
			wantRoute(t, err, TagPingTimeout, "Session.loop->Session.keepaliveTick.PingTimeout")
			if elapsed := time.Since(start); elapsed < 59*time.Second {
				t.Errorf("gave up after %v: the 5 seconds of the options won over the pushed 60", elapsed)
			}
		})
	})
	t.Run("zero is off", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := keepaliveRig(t, transports[0], "", "", Options{})
			if err := r.session.Handshake(t.Context()); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Hour)
			synctest.Wait()
			if got := r.server.Pings(); got != 0 {
				t.Errorf("%d pings with no keepalive", got)
			}
			select {
			case <-r.session.done:
				t.Fatalf("the session ended: %v", r.session.result())
			default:
			}
		})
	})
}

func TestCloseDuringTheKeepaliveStopsEveryGoroutine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		before := vpntest.BubbleGoroutines()
		r := keepaliveRig(t, transports[0], ",ping 10", ",ping-restart 60", Options{})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Second)
		synctest.Wait()
		if err := r.session.Close(); err != nil {
			t.Fatal(err)
		}
		r.server.Close()
		synctest.Wait()
		if after := vpntest.BubbleGoroutines(); after != before {
			t.Errorf("%d goroutines before, %d after Close", before, after)
		}
		if _, err := r.session.Read(make([]byte, 10)); err != net.ErrClosed {
			t.Errorf("Read after Close = %v", err)
		}
	})
}

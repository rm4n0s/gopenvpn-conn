// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server && gopenvpn_soak

package openvpn

// The soak tests are not part of scripts/check.sh. They are run by hand, in the
// namespace, with both tags (CLAUDE.md, Commands):
//
//	scripts/vpn-ns.sh -- go test -tags 'gopenvpn_server gopenvpn_soak' -run Soak -timeout 3h -v .
//
// GOPENVPN_SOAK_DURATION (a Go duration, default 1h) is the length of TestSoakHour.

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// netemParams are the faults of the soak tests: SPEC §17.
const netemParams = "loss 10% delay 20ms reorder 25% duplicate 5%"

// TestSoakHandshakeUnderNetem: the handshake completes over a loopback that loses a
// tenth of the packets, delays them, reorders a quarter and duplicates a twentieth, over
// UDP and TCP and with every protection of the control channel, three times each.
func TestSoakHandshakeUnderNetem(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		for _, setup := range serverSetups() {
			t.Run(proto+"/"+setup.name, func(t *testing.T) {
				extra, wrap := setup.make(t)
				srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: extra})
				servertest.Netem(t, netemParams)
				for i := range 3 {
					start := time.Now()
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					conn, err := Dial(ctx, proto, srv.Addr(), &Config{TLS: tlsConfigFor(srv.PKI), ControlWrap: wrap})
					cancel()
					if err != nil {
						t.Fatalf("Dial %d: %v\nserver log:\n%s", i, err, srv.Log())
					}
					t.Logf("handshake %d took %v", i, time.Since(start).Round(10*time.Millisecond))
					if err := conn.Close(); err != nil {
						t.Fatalf("Close: %v", err)
					}
				}
			})
		}
	}
}

// echoLossy sends an echo request every 100 ms for d and counts the replies; unlike
// echoStream it allows loss. It returns the numbers sent and answered.
func echoLossy(t *testing.T, conn *Conn, srv *servertest.Server, packets <-chan []byte, d time.Duration) (sent, answered int) {
	t.Helper()
	st := conn.ConnectionState()
	me, server := st.Addrs[0].Addr(), srv.TunnelIP()
	const id = 0x4f52
	seen := map[uint16]bool{}
	collect := func(p []byte) {
		if e, ok := vpntest.ParseEchoReply(p); ok && e.ID == id && !seen[e.Seq] {
			seen[e.Seq] = true
			answered++
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	stop := time.After(d)
	for {
		select {
		case <-ticker.C:
			sent++
			if _, err := conn.Write(vpntest.EchoRequest(me, server, id, uint16(sent&0xffff), []byte("soak"))); err != nil {
				t.Fatalf("Write %d: %v\nserver log:\n%s", sent, err, srv.Log())
			}
		case p := <-packets:
			collect(p)
		case <-stop:
			tail := time.After(5 * time.Second)
			for {
				select {
				case p := <-packets:
					collect(p)
				case <-tail:
					return sent, answered
				}
			}
		}
	}
}

// TestSoakRenegotiationsUnderNetem: with the faults on, the server renegotiates every
// 3 seconds for 40 seconds over TCP and 80 over UDP, where each renegotiation takes
// longer because its packets are lost and sent again (at least ten times), while the
// client sends echo requests.
// The connection must survive all of them. Over UDP the data channel loses packets, as
// the network does (a tenth each way, so about a fifth of the round trips), and most
// requests are still answered; over TCP the link loses nothing. When the faults are
// taken away, every request is answered again.
func TestSoakRenegotiationsUnderNetem(t *testing.T) {
	setups := serverSetups()
	for _, tc := range []struct {
		proto string
		setup serverSetup
		min   float64       // the share of requests that must be answered
		run   time.Duration // how long (a renegotiation under loss takes seconds more than its 3)
	}{{"udp", setups[3], 0.55, 80 * time.Second}, {"tcp", setups[3], 0.9, 40 * time.Second}} {
		t.Run(tc.proto, func(t *testing.T) {
			extra, wrap := tc.setup.make(t)
			srv := servertest.Start(t, servertest.Options{Proto: tc.proto, Extra: append([]string{"--verb", "7", "--reneg-sec", "3"}, extra...)})
			servertest.Netem(t, netemParams)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			conn, err := Dial(ctx, tc.proto, srv.Addr(), &Config{TLS: tlsConfigFor(srv.PKI), ControlWrap: wrap})
			cancel()
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			packets := packetReader(t, conn)
			sent, answered := echoLossy(t, conn, srv, packets, tc.run)
			renegotiations := handshakes(srv) - 1
			t.Logf("%s: %d echo requests, %d answered (%.0f%%), %d renegotiations", tc.proto, sent, answered, 100*float64(answered)/float64(sent), renegotiations)
			if renegotiations < 10 {
				t.Errorf("%d renegotiations, want at least 10\nserver log:\n%s", renegotiations, srv.Log())
			}
			if share := float64(answered) / float64(sent); share < tc.min {
				t.Errorf("%.0f%% of the requests were answered, want at least %.0f%%", 100*share, 100*tc.min)
			}
			select {
			case <-conn.s.Done():
				t.Fatalf("the session ended: %v\nserver log:\n%s", conn.s.Err(), srv.Log())
			default:
			}
			servertest.NetemOff(t)
			echoRequests(t, conn, srv, packets, 5)
		})
	}
}

// TestSoakLeakAfter1000Connections is TestNoLeakAfterManyConnections with 1000.
func TestSoakLeakAfter1000Connections(t *testing.T) {
	noLeak(t, 1000)
}

// TestSoakHour: one hour (GOPENVPN_SOAK_DURATION) against a server with --reneg-sec 5,
// UDP and tls-crypt, 20 echo requests a second, every one answered within 2 seconds,
// and the heap flat: the heap after a collection is taken every minute, and the
// average of the last ten samples must not be more than 4 MiB above the average of the
// ten after the first five minutes.
func TestSoakHour(t *testing.T) {
	duration := time.Hour
	if v := os.Getenv("GOPENVPN_SOAK_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("GOPENVPN_SOAK_DURATION: %v", err)
		}
		duration = d
	}
	extra, wrap := serverSetups()[3].make(t)
	srv := servertest.Start(t, servertest.Options{Extra: append([]string{"--reneg-sec", "5"}, extra...)})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	conn, err := Dial(ctx, "udp", srv.Addr(), &Config{TLS: tlsConfigFor(srv.PKI), ControlWrap: wrap})
	cancel()
	if err != nil {
		t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
	}
	packets := packetReader(t, conn)
	st := conn.ConnectionState()
	me, server := st.Addrs[0].Addr(), srv.TunnelIP()

	const (
		id       = 0x4f53
		interval = 50 * time.Millisecond
		deadline = 2 * time.Second
	)
	pending := map[uint16]time.Time{} // sent, not answered yet
	var sent, answered int
	var heaps []uint64
	begin := time.Now()
	sample := func() {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		heaps = append(heaps, m.HeapAlloc)
		t.Logf("after %v: %d requests, %d answered, %d renegotiations, heap %d KiB, %d goroutines",
			time.Since(begin).Round(time.Second), sent, answered, handshakes(srv)-1, m.HeapAlloc>>10, runtime.NumGoroutine())
	}
	payloadOf := func(seq uint16) []byte { return bytes.Repeat([]byte{byte(seq & 0xff)}, 56) }

	send := time.NewTicker(interval)
	defer send.Stop()
	minute := time.NewTicker(time.Minute)
	defer minute.Stop()
	end := time.After(duration)
	for running := true; running; {
		select {
		case <-send.C:
			sent++
			seq := uint16(sent & 0xffff)
			if _, err := conn.Write(vpntest.EchoRequest(me, server, id, seq, payloadOf(seq))); err != nil {
				t.Fatalf("Write %d: %v\nserver log (tail):\n%s", sent, err, tail(srv.Log(), 4000))
			}
			pending[seq] = time.Now()
			for old, at := range pending { // the map is small: a few dozen entries
				if time.Since(at) > deadline {
					t.Fatalf("request %d got no reply within %v (%d sent, %d answered, %d renegotiations)\nserver log (tail):\n%s",
						old, deadline, sent, answered, handshakes(srv)-1, tail(srv.Log(), 4000))
				}
			}
		case p := <-packets:
			e, ok := vpntest.ParseEchoReply(p)
			if !ok || e.ID != id {
				continue
			}
			if e.Src != server || e.Dst != me || !bytes.Equal(e.Payload, payloadOf(e.Seq)) {
				t.Fatalf("a wrong reply: %+v", e)
			}
			if _, was := pending[e.Seq]; was {
				delete(pending, e.Seq)
				answered++
			}
		case <-minute.C:
			sample()
		case <-end:
			running = false
		}
	}
	// The last requests have the grace period to be answered.
	grace := time.After(deadline)
	for len(pending) > 0 {
		select {
		case p := <-packets:
			if e, ok := vpntest.ParseEchoReply(p); ok && e.ID == id {
				if _, was := pending[e.Seq]; was {
					delete(pending, e.Seq)
					answered++
				}
			}
		case <-grace:
			t.Fatalf("%d of the last requests got no reply", len(pending))
		}
	}
	sample()
	renegotiations := handshakes(srv) - 1
	t.Logf("%v: %d echo requests, %d answered, %d renegotiations", duration, sent, answered, renegotiations)
	if answered != sent {
		t.Errorf("%d requests, %d answered", sent, answered)
	}
	if want := int(duration/(5*time.Second)) * 8 / 10; renegotiations < want {
		t.Errorf("%d renegotiations in %v, want at least %d", renegotiations, duration, want)
	}
	select {
	case <-conn.s.Done():
		t.Fatalf("the session ended: %v", conn.s.Err())
	default:
	}
	if len(heaps) >= 15 {
		mean := func(h []uint64) uint64 {
			var sum uint64
			for _, v := range h {
				sum += v
			}
			return sum / uint64(len(h))
		}
		first, last := mean(heaps[5:15]), mean(heaps[len(heaps)-10:])
		t.Logf("heap: %d KiB at the start (minutes 5 to 15), %d KiB at the end", first>>10, last>>10)
		if last > first && last-first > 4<<20 {
			t.Errorf("the heap grew from %d to %d bytes", first, last)
		}
	}
}

// tail is the last n bytes of s.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

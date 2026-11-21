// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package openvpn

import (
	"context"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// TestKeepaliveWithRealServer: with --keepalive 1 3 the server pushes ping 1 and
// ping-restart 3, an idle Conn is still usable 10 seconds later (its pings, and the
// server's, keep it up), and when the server dies the session ends within 5 seconds:
// with TagPingTimeout over UDP, where nothing else tells the client, and with
// TagLinkFailed over TCP, whose link ends.
func TestKeepaliveWithRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: []string{"--verb", "4", "--keepalive", "1", "3"}})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := Dial(ctx, proto, srv.Addr(), &Config{TLS: tlsConfigFor(srv.PKI)})
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			packets := packetReader(t, conn)
			if st := conn.ConnectionState(); st.PingInterval != time.Second || st.PingTimeout != 3*time.Second {
				t.Fatalf("pushed ping %v, ping-restart %v", st.PingInterval, st.PingTimeout)
			}

			time.Sleep(10 * time.Second) // idle: more than three times the timeout
			select {
			case <-conn.s.Done():
				t.Fatalf("the session ended while idle: %v\nserver log:\n%s", conn.s.Err(), srv.Log())
			default:
			}
			echoRequests(t, conn, srv, packets, 5)

			// The server dies; the client has to notice.
			start := time.Now()
			srv.Stop(t)
			<-conn.s.Done()
			err = conn.s.Err()
			t.Logf("the session ended %v after the server died: %v", time.Since(start), err)
			if time.Since(start) > 5*time.Second {
				t.Errorf("the client took %v to notice", time.Since(start))
			}
			// Over UDP nothing tells the client that the server is gone (the ICMP errors of
			// its pings are ignored): the keepalive does. Over TCP the link ends.
			want := TagPingTimeout
			if proto == "tcp" {
				want = TagLinkFailed
			}
			if appErr, ok := errors.FromError(err); !ok || appErr.Tag != want {
				t.Errorf("the session ended with %v, want %s", err, want)
			}
		})
	}
}

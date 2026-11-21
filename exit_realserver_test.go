// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package openvpn

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// TestCloseWithRealServer: after Close the server's log says that the client left,
// within 2 seconds (not after its ping timeout), by the exit message of the control
// channel (cc-exit) and, over UDP when the client does not announce cc-exit, by the
// older one of the data channel.
func TestCloseWithRealServer(t *testing.T) {
	tests := []struct {
		name, proto string
		noCCExit    bool
		logLine     string // what the server logs when it gets the message
	}{
		{"udp cc-exit", "udp", false, "CC-EEN exit message received by peer"},
		{"tcp cc-exit", "tcp", false, "CC-EEN exit message received by peer"},
		{"udp data channel exit", "udp", true, "OCC exit message received by peer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := servertest.Start(t, servertest.Options{Proto: tt.proto, Extra: []string{"--verb", "4", "--keepalive", "60", "120"}})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := Dial(ctx, tt.proto, srv.Addr(), &Config{TLS: tlsConfigFor(srv.PKI), noCCExit: tt.noCCExit})
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			packets := packetReader(t, conn)
			echoRequests(t, conn, srv, packets, 3)
			start := time.Now()
			if err := conn.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			t.Logf("Close took %v", time.Since(start))
			srv.WaitLog(t, tt.logLine, 2*time.Second)
			for _, line := range strings.Split(srv.Log(), "\n") {
				if strings.Contains(line, "exit message") || strings.Contains(line, "Delayed exit") || strings.Contains(line, "remote-exit") {
					t.Log(line[strings.Index(line, " ")+1:]) // the evidence for IMPLEMENTED.md
				}
			}
		})
	}
}

// TestServerStopWithRealServer: a UDP server with --explicit-exit-notify tells its
// clients RESTART before it stops, and the session ends with TagServerRestart; a TCP
// server has no such message, and the link ends (TagLinkFailed with io.EOF as its
// cause). A server in server mode never sends EXIT (SPEC §21 O23).
func TestServerStopWithRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: []string{"--verb", "4", "--explicit-exit-notify", "1"}})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := Dial(ctx, proto, srv.Addr(), &Config{TLS: tlsConfigFor(srv.PKI)})
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			packetReader(t, conn)
			srv.Stop(t)
			select {
			case <-conn.s.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the session did not end within 5 seconds of the server's stop")
			}
			err = conn.s.Err()
			appErr, ok := errors.FromError(err)
			want := TagServerRestart
			if proto == "tcp" {
				want = TagLinkFailed
			}
			if !ok || appErr.Tag != want {
				t.Fatalf("the session ended with %v, want %s", err, want)
			}
			t.Logf("the session ended with: %v", err)
		})
	}
}

// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package openvpn

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// packetReader reads the packets of a Conn in a goroutine, so that the test can
// wait for one with a time limit (the deadlines of Conn come in a later step).
func packetReader(t *testing.T, conn *Conn) <-chan []byte {
	t.Helper()
	packets := make(chan []byte, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			select {
			case packets <- bytes.Clone(buf[:n]):
			default:
			}
		}
	}()
	// Registered after the Close of the Dial, so it runs first: Close ends the Read.
	t.Cleanup(func() {
		if err := conn.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
			t.Errorf("Close: %v", err)
		}
		<-done
	})
	return packets
}

// echoRequests sends n ICMP echo requests to the tunnel address of a real server
// and fails the test unless each is answered within 2 seconds, with its payload.
func echoRequests(t *testing.T, conn *Conn, srv *servertest.Server, packets <-chan []byte, n int) {
	t.Helper()
	st := conn.ConnectionState()
	if len(st.Addrs) == 0 {
		t.Fatal("no tunnel address")
	}
	me, server := st.Addrs[0].Addr(), srv.TunnelIP()
	for seq := 1; seq <= n; seq++ {
		id, seq16 := uint16(0x4f50), uint16(seq&0xffff)
		payload := bytes.Repeat([]byte{byte(seq & 0xff)}, 56)
		if _, err := conn.Write(vpntest.EchoRequest(me, server, id, seq16, payload)); err != nil {
			t.Fatalf("Write %d: %v", seq, err)
		}
		deadline := time.After(2 * time.Second)
	wait:
		for {
			select {
			case p := <-packets:
				e, ok := vpntest.ParseEchoReply(p)
				if !ok || e.ID != id || e.Seq != seq16 {
					continue // not our reply (yet)
				}
				if e.Src != server || e.Dst != me || !bytes.Equal(e.Payload, payload) {
					t.Fatalf("reply %d: %+v", seq, e)
				}
				break wait
			case <-deadline:
				t.Fatalf("no reply to request %d within 2s\nserver log:\n%s", seq, srv.Log())
			}
		}
	}
}

// TestEchoWithRealServer sends ICMP echo requests to the tunnel address of a real
// server, over UDP and TCP, with each data cipher and each data format (the epoch
// format, and the one with 32-bit packet ids when the client does not announce
// epochs), and gets every reply: the data channel works in both directions. The
// server runs its data channel in its own process (the namespace of the tests
// cannot create a kernel one, SPEC §21 O17).
func TestEchoWithRealServer(t *testing.T) {
	ciphers := []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-192-GCM"}
	for _, proto := range []string{"udp", "tcp"} {
		for _, cipher := range ciphers {
			for _, epoch := range []bool{true, false} {
				format := "epoch"
				if !epoch {
					format = "32-bit"
				}
				t.Run(proto+"/"+cipher+"/"+format, func(t *testing.T) {
					srv := servertest.Start(t, servertest.Options{
						Proto: proto, Extra: []string{"--verb", "4", "--data-ciphers", cipher},
					})
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					conn, err := Dial(ctx, proto, srv.Addr(), &Config{
						TLS: tlsConfigFor(srv.PKI), DataCiphers: []string{cipher}, noEpoch: !epoch,
					})
					if err != nil {
						t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
					}
					packets := packetReader(t, conn)
					st := conn.ConnectionState()
					if st.Cipher != cipher {
						t.Fatalf("cipher %q, want %q", st.Cipher, cipher)
					}
					if has := slices.ContainsFunc(st.PushedOptions, func(o string) bool {
						return strings.HasPrefix(o, "protocol-flags") && strings.Contains(o, "aead-epoch")
					}); has != epoch {
						t.Fatalf("the server pushed aead-epoch = %v, want %v: %q", has, epoch, st.PushedOptions)
					}
					echoRequests(t, conn, srv, packets, 100)
					logDataChannel(t, srv)
				})
			}
		}
	}
}

// logDataChannel logs the lines of the server's log that name the data keys.
func logDataChannel(t *testing.T, srv *servertest.Server) {
	t.Helper()
	var last string
	for _, line := range strings.Split(srv.Log(), "\n") {
		switch {
		case strings.Contains(line, "Data Channel: Cipher") || strings.Contains(line, "Outgoing Epoch Data key 1:") ||
			strings.Contains(line, "Incoming Epoch Data key 1:"):
			t.Log(line[strings.Index(line, " ")+1:]) // the evidence for IMPLEMENTED.md
		case strings.Contains(line, "new epoch"):
			last = line
		}
	}
	if last != "" {
		t.Log(last[strings.Index(last, " ")+1:]) // the last move of the server to a newer epoch
	}
}

// TestEpochsAdvanceWithRealServer makes the client's keys reach a small usage limit
// again and again, so that its packets go through many epochs, with the real
// server in the middle: it must open each, and, following the draft, move its own
// packets to the epochs of ours, which we must open in turn.
func TestEpochsAdvanceWithRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		for _, cipher := range []string{"AES-256-GCM", "CHACHA20-POLY1305"} {
			t.Run(proto+"/"+cipher, func(t *testing.T) {
				srv := servertest.Start(t, servertest.Options{
					Proto: proto, Extra: []string{"--verb", "4", "--data-ciphers", cipher},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				conn, err := Dial(ctx, proto, srv.Addr(), &Config{
					TLS: tlsConfigFor(srv.PKI), DataCiphers: []string{cipher}, epochUsageLimit: 60,
				})
				if err != nil {
					t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
				}
				packets := packetReader(t, conn)
				echoRequests(t, conn, srv, packets, 600) // every packet costs a few of the 60: dozens of epochs
				logDataChannel(t, srv)
				if !strings.Contains(srv.Log(), "new epoch") {
					t.Errorf("the server never logged a move to a new epoch:\n%s", srv.Log())
				}
			})
		}
	}
}

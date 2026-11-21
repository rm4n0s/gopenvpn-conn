// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package openvpn

import (
	"bytes"
	"context"
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

// TestEchoWithRealServer sends ICMP echo requests to the tunnel address of a real
// server, over UDP and TCP, with each data cipher, and gets every reply: the data
// channel works in both directions. The server runs its data channel in its own
// process (the namespace of the tests cannot create a kernel one, SPEC §21 O17).
func TestEchoWithRealServer(t *testing.T) {
	ciphers := []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-192-GCM"}
	for _, proto := range []string{"udp", "tcp"} {
		for _, cipher := range ciphers {
			t.Run(proto+"/"+cipher, func(t *testing.T) {
				srv := servertest.Start(t, servertest.Options{
					Proto: proto, Extra: []string{"--verb", "4", "--data-ciphers", cipher},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				conn, err := Dial(ctx, proto, srv.Addr(), &Config{
					TLS: tlsConfigFor(srv.PKI), DataCiphers: []string{cipher},
				})
				if err != nil {
					t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
				}
				packets := packetReader(t, conn)
				st := conn.ConnectionState()
				if st.Cipher != cipher || len(st.Addrs) == 0 {
					t.Fatalf("state: cipher %q, addrs %v", st.Cipher, st.Addrs)
				}
				me, server := st.Addrs[0].Addr(), srv.TunnelIP()

				for seq := uint16(1); seq <= 100; seq++ {
					payload := bytes.Repeat([]byte{byte(seq)}, 56)
					if _, err := conn.Write(vpntest.EchoRequest(me, server, 0x4f50, seq, payload)); err != nil {
						t.Fatalf("Write %d: %v", seq, err)
					}
					deadline := time.After(2 * time.Second)
				wait:
					for {
						select {
						case p := <-packets:
							e, ok := vpntest.ParseEchoReply(p)
							if !ok || e.ID != 0x4f50 || e.Seq != seq {
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
				for _, line := range strings.Split(srv.Log(), "\n") {
					if strings.Contains(line, "Data Channel: Cipher") {
						t.Log(line[strings.Index(line, " ")+1:]) // the evidence for IMPLEMENTED.md
					}
				}
			})
		}
	}
}

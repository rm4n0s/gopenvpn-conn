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

// echoStream sends an ICMP echo request to the server every 100 ms for d, and fails
// the test unless every one is answered, with its own payload, within 2 seconds of the
// last request. It returns how many it sent.
func echoStream(t *testing.T, conn *Conn, srv *servertest.Server, packets <-chan []byte, d time.Duration) int {
	t.Helper()
	st := conn.ConnectionState()
	if len(st.Addrs) == 0 {
		t.Fatal("no tunnel address")
	}
	me, server := st.Addrs[0].Addr(), srv.TunnelIP()
	const id = 0x4f51
	answered := map[uint16]bool{}
	collect := func(p []byte) {
		e, ok := vpntest.ParseEchoReply(p)
		if !ok || e.ID != id {
			return
		}
		if e.Src != server || e.Dst != me || !bytes.Equal(e.Payload, bytes.Repeat([]byte{byte(e.Seq & 0xff)}, 56)) {
			t.Errorf("a wrong reply: %+v", e)
		}
		answered[e.Seq] = true
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	stop := time.After(d)
	sent := 0
send:
	for {
		select {
		case <-ticker.C:
			sent++
			seq := uint16(sent)
			if _, err := conn.Write(vpntest.EchoRequest(me, server, id, seq, bytes.Repeat([]byte{byte(seq & 0xff)}, 56))); err != nil {
				t.Fatalf("Write %d: %v\nserver log:\n%s", sent, err, srv.Log())
			}
		case p := <-packets:
			collect(p)
		case <-stop:
			break send
		}
	}
	tail := time.After(2 * time.Second)
	for len(answered) < sent {
		select {
		case p := <-packets:
			collect(p)
		case <-tail:
			var lost []uint16
			for seq := 1; seq <= sent; seq++ {
				if !answered[uint16(seq)] {
					lost = append(lost, uint16(seq))
				}
			}
			t.Fatalf("%d of %d echo requests got no reply: %v\nserver log:\n%s", len(lost), sent, lost, srv.Log())
		}
	}
	return sent
}

// handshakes is how many TLS sessions the server has finished: the first one and one for
// each renegotiation.
func handshakes(srv *servertest.Server) int {
	return strings.Count(srv.Log(), "Control Channel: TLS")
}

// TestRenegotiationWithRealServer: with --reneg-sec 3 the server renegotiates every 3
// seconds, with every protection of the control channel over UDP and TCP, while the
// client sends 10 echo requests a second; every request is answered, so no packet
// is lost across the change of keys, and the log of the server shows its renegotiations.
func TestRenegotiationWithRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		for _, setup := range serverSetups() {
			t.Run(proto+"/"+setup.name, func(t *testing.T) {
				renegotiate(t, proto, setup, 9*time.Second, 0, false, 2)
			})
		}
	}
}

// TestRenegotiationWithRealServerAndTheOtherDataFormat is the same with the format
// of the data channel that has 32-bit packet ids, which the client chooses by not
// announcing epochs.
func TestRenegotiationWithRealServerAndTheOtherDataFormat(t *testing.T) {
	setups := serverSetups()
	for _, tc := range []struct {
		proto string
		setup serverSetup
	}{{"udp", setups[3]}, {"tcp", setups[0]}} {
		t.Run(tc.proto+"/"+tc.setup.name, func(t *testing.T) {
			renegotiate(t, tc.proto, tc.setup, 9*time.Second, 0, true, 2)
		})
	}
}

// TestRenegotiationOfAMinuteWithRealServer is the long one: 40 seconds, 10 echo
// requests a second, a new key every 3 seconds, nothing lost.
func TestRenegotiationOfAMinuteWithRealServer(t *testing.T) {
	setups := serverSetups()
	for _, tc := range []struct {
		proto string
		setup serverSetup
	}{{"udp", setups[3]}, {"tcp", setups[0]}} {
		t.Run(tc.proto+"/"+tc.setup.name, func(t *testing.T) {
			renegotiate(t, tc.proto, tc.setup, 40*time.Second, 0, false, 10)
		})
	}
}

// TestClientRenegotiationWithRealServer: the client's RenegotiateAfter is 3 seconds and
// the server's is its default hour, so the client starts every renegotiation.
func TestClientRenegotiationWithRealServer(t *testing.T) {
	setups := serverSetups()
	for _, tc := range []struct {
		proto string
		setup serverSetup
	}{{"udp", setups[4]}, {"tcp", setups[0]}} {
		t.Run(tc.proto+"/"+tc.setup.name, func(t *testing.T) {
			renegotiate(t, tc.proto, tc.setup, 12*time.Second, 3*time.Second, false, 3)
		})
	}
}

// renegotiate runs a client against a server for d with a stream of echo requests.
// serverReneg is true when the server's --reneg-sec is 3; clientAfter is the client's
// RenegotiateAfter (0 for the default). It wants at least min renegotiations in the
// server's log.
func renegotiate(t *testing.T, proto string, setup serverSetup, d, clientAfter time.Duration, noEpoch bool, minimum int) {
	t.Helper()
	extra, wrap := setup.make(t)
	args := append([]string{"--verb", "7"}, extra...)
	if clientAfter == 0 {
		args = append(args, "--reneg-sec", "3")
	}
	srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: args})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := Dial(ctx, proto, srv.Addr(), &Config{
		TLS: tlsConfigFor(srv.PKI), ControlWrap: wrap, RenegotiateAfter: clientAfter, noEpoch: noEpoch,
	})
	if err != nil {
		t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
	}
	packets := packetReader(t, conn)
	sent := echoStream(t, conn, srv, packets, d)
	if n := handshakes(srv) - 1; n < minimum {
		t.Errorf("the server did %d renegotiations, want at least %d\nserver log:\n%s", n, minimum, srv.Log())
	}
	// The server pushed dyn-tls-crypt and made the key for the renegotiations.
	if !strings.Contains(srv.Log(), "Outgoing dynamic tls-crypt: Cipher 'AES-256-CTR' initialized") {
		t.Errorf("the server did not make a dynamic tls-crypt key\nserver log:\n%s", srv.Log())
	}
	select {
	case <-conn.s.Done():
		t.Fatalf("the session ended: %v\nserver log:\n%s", conn.s.Err(), srv.Log())
	default:
	}
	t.Logf("%d echo requests, all answered, across %d renegotiations", sent, handshakes(srv)-1)
}

// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package ctrlwrap

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// resetExchange sends a wrapped CONTROL_HARD_RESET_CLIENT_V2 to a real server
// over UDP and returns the answer, unwrapped and parsed, or nil when the server
// stays silent for wait.
func resetExchange(t *testing.T, w Wrapper, addr string, wait time.Duration) (*wire.Control, wire.SessionID) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sid := wire.RandomSessionID()
	reset := wire.Control{Opcode: wire.HardResetClientV2, KeyID: 0, SessionID: sid, PacketID: 0}
	body, err := wire.AppendControlBody(nil, &reset)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := w.Wrap(nil, wire.FirstByte(reset.Opcode, reset.KeyID), sid, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, sid // no answer
	}
	answer := buf[:n]
	answerBody, err := w.Unwrap(answer)
	if err != nil {
		t.Fatalf("the server's answer does not unwrap: %v\nanswer: %x", err, answer)
	}
	op, keyID := wire.SplitFirstByte(answer[0])
	c, err := wire.ParseControlBody(op, answerBody)
	if err != nil {
		t.Fatalf("the server's answer does not parse: %v", err)
	}
	c.KeyID = keyID
	copy(c.SessionID[:], answer[1:headerSize])
	return &c, sid
}

// TestTLSAuthWithRealServer sends a tls-auth protected reset to the real server
// and checks that it answers with a reset of its own that carries our session
// id and an ack for packet 0: the bytes of this package are the bytes that
// OpenVPN reads and writes.
func TestTLSAuthWithRealServer(t *testing.T) {
	tests := []struct {
		name      string
		serverDir string // the direction argument of the server's --tls-auth; "" for none
		auth      string // the server's --auth; "" for its default, SHA1
		newHash   func() hash.Hash
		clientDir keys.Direction
	}{
		{"SHA1, direction 0 and 1", "0", "", sha1.New, keys.Inverse},
		{"SHA256", "0", "SHA256", sha256.New, keys.Inverse},
		{"SHA384", "0", "SHA384", sha512.New384, keys.Inverse},
		{"SHA512", "0", "SHA512", sha512.New, keys.Inverse},
		{"no direction", "", "", sha1.New, keys.Bidirectional},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyFile := servertest.GenKey(t, "tls-auth")
			f, err := os.Open(keyFile)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			key, err := keys.ParseStaticKey(f)
			if err != nil {
				t.Fatalf("the key that openvpn made does not parse: %v", err)
			}

			extra := []string{"--tls-auth", keyFile}
			if tt.serverDir != "" {
				extra = append(extra, tt.serverDir) // the direction follows the key file
			}
			if tt.auth != "" {
				extra = append(extra, "--auth", tt.auth)
			}
			// Verbose 7 makes the server log what it does with a first packet.
			extra = append(extra, "--verb", "7")
			srv := servertest.Start(t, servertest.Options{Extra: extra})

			w, err := NewTLSAuth(key, tt.clientDir, tt.newHash, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			answer, sid := resetExchange(t, w, srv.Addr(), 5*time.Second)
			if answer == nil {
				t.Fatalf("the server did not answer; its log:\n%s", srv.Log())
			}
			if answer.Opcode != wire.HardResetServerV2 {
				t.Errorf("the answer is %v, want CONTROL_HARD_RESET_SERVER_V2", answer.Opcode)
			}
			if len(answer.Acks) != 1 || answer.Acks[0] != 0 {
				t.Errorf("acks = %v, want [0]: the reset of the client has packet id 0", answer.Acks)
			}
			if answer.RemoteSessionID != sid {
				t.Errorf("the server's session id for us is %v, want %v", answer.RemoteSessionID, sid)
			}
			if answer.PacketID != 0 {
				t.Errorf("packet id = %d, want 0", answer.PacketID)
			}
			if answer.SessionID.IsZero() {
				t.Error("the server's session id is zero")
			}
			// The server's own words for what it did: it answered a reset with
			// a reset that is a challenge, keeping no state until we reply.
			srv.WaitLog(t, "Reset packet from client, sending HMAC based reset challenge", 2*time.Second)
		})
	}
}

func TestTLSAuthRefusedByRealServer(t *testing.T) {
	serverKeyFile := servertest.GenKey(t, "tls-auth")
	srv := servertest.Start(t, servertest.Options{Extra: []string{"--tls-auth", serverKeyFile, "0", "--verb", "7"}})

	// A key that is not the server's: the HMAC is wrong, so the server says nothing.
	other := testKey(0x77)
	w, err := NewTLSAuth(other, keys.Inverse, sha1.New, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if answer, _ := resetExchange(t, w, srv.Addr(), time.Second); answer != nil {
		t.Fatalf("the server answered a packet with the wrong key: %+v", answer)
	}
	// The server says why it dropped the packet, and did not treat it as a reset.
	srv.WaitLog(t, "packet HMAC authentication failed", 2*time.Second)
	if got := srv.Log(); strings.Contains(got, "sending HMAC based reset challenge") {
		t.Errorf("the server took a packet with the wrong key for a reset:\n%s", got)
	}
}

// TestTLSCryptWithRealServer does for tls-crypt what TestTLSAuthWithRealServer
// does for tls-auth: the reset is encrypted, the server decrypts it and its
// answer, encrypted with the other key, decrypts here.
func TestTLSCryptWithRealServer(t *testing.T) {
	keyFile := servertest.GenKey(t, "tls-crypt")
	f, err := os.Open(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	key, err := keys.ParseStaticKey(f)
	if err != nil {
		t.Fatalf("the key that openvpn made does not parse: %v", err)
	}
	srv := servertest.Start(t, servertest.Options{Extra: []string{"--tls-crypt", keyFile, "--verb", "7"}})

	w, err := NewTLSCrypt(key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	answer, sid := resetExchange(t, w, srv.Addr(), 5*time.Second)
	if answer == nil {
		t.Fatalf("the server did not answer; its log:\n%s", srv.Log())
	}
	if answer.Opcode != wire.HardResetServerV2 {
		t.Errorf("the answer is %v, want CONTROL_HARD_RESET_SERVER_V2", answer.Opcode)
	}
	if len(answer.Acks) != 1 || answer.Acks[0] != 0 {
		t.Errorf("acks = %v, want [0]", answer.Acks)
	}
	if answer.RemoteSessionID != sid {
		t.Errorf("the server's session id for us is %v, want %v", answer.RemoteSessionID, sid)
	}
	if answer.PacketID != 0 || answer.SessionID.IsZero() {
		t.Errorf("packet id %d, session id %v", answer.PacketID, answer.SessionID)
	}
	srv.WaitLog(t, "Reset packet from client, sending HMAC based reset challenge", 2*time.Second)
}

func TestTLSCryptRefusedByRealServer(t *testing.T) {
	serverKeyFile := servertest.GenKey(t, "tls-crypt")
	srv := servertest.Start(t, servertest.Options{Extra: []string{"--tls-crypt", serverKeyFile, "--verb", "7"}})

	// Another key: the packet does not decrypt to anything that authenticates.
	w, err := NewTLSCrypt(testKey(0x77), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if answer, _ := resetExchange(t, w, srv.Addr(), time.Second); answer != nil {
		t.Fatalf("the server answered a packet with the wrong key: %+v", answer)
	}
	srv.WaitLog(t, "tls-crypt unwrap error", 2*time.Second)
	if got := srv.Log(); strings.Contains(got, "sending HMAC based reset challenge") {
		t.Errorf("the server took a packet with the wrong key for a reset:\n%s", got)
	}

	// A tls-auth packet is not a tls-crypt packet either.
	auth, err := NewTLSAuth(testKey(0x77), keys.Inverse, sha1.New, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if answer, _ := resetExchange(t, auth, srv.Addr(), time.Second); answer != nil {
		t.Fatalf("a tls-crypt server answered a tls-auth packet: %+v", answer)
	}
}

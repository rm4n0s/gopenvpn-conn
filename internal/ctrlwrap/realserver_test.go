// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package ctrlwrap

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// peer is one UDP connection to a real server, with the Wrapper that protects
// what is sent and read on it. The server answers a reset statelessly for the
// address it came from, so the packets of one handshake share one connection.
type peer struct {
	t    *testing.T
	conn net.Conn
	w    Wrapper
	sid  wire.SessionID
}

func newPeer(t *testing.T, w Wrapper, addr string) *peer {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	})
	return &peer{t: t, conn: conn, w: w, sid: wire.RandomSessionID()}
}

// send wraps a control packet from us (our session id is filled in) and writes it.
func (p *peer) send(c wire.Control) {
	p.t.Helper()
	c.SessionID = p.sid
	body, err := wire.AppendControlBody(nil, &c)
	if err != nil {
		p.t.Fatal(err)
	}
	packet, err := p.w.Wrap(nil, wire.FirstByte(c.Opcode, c.KeyID), p.sid, body)
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.conn.Write(packet); err != nil {
		p.t.Fatal(err)
	}
}

// recv reads one packet, unwraps and parses it. It returns nil when the server
// is silent for wait.
func (p *peer) recv(wait time.Duration) *wire.Control {
	p.t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		p.t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := p.conn.Read(buf)
	if err != nil {
		return nil
	}
	answer := buf[:n]
	body, err := p.w.Unwrap(answer)
	if err != nil {
		p.t.Fatalf("the server's answer does not unwrap: %v\nanswer: %x", err, answer)
	}
	op, keyID := wire.SplitFirstByte(answer[0])
	c, err := wire.ParseControlBody(op, body)
	if err != nil {
		p.t.Fatalf("the server's answer does not parse: %v", err)
	}
	c.KeyID = keyID
	copy(c.SessionID[:], answer[1:headerSize])
	return &c
}

// resetExchange sends a wrapped reset (op is the opcode of the client's first
// packet) to a real server and returns the answer, or nil when the server stays
// silent for wait, and our session id.
func resetExchange(t *testing.T, w Wrapper, addr string, op wire.Opcode, wait time.Duration) (*wire.Control, wire.SessionID) {
	t.Helper()
	p := newPeer(t, w, addr)
	p.send(wire.Control{Opcode: op, PacketID: 0})
	return p.recv(wait), p.sid
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
			key := readStaticKey(t, keyFile)

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
			answer, sid := resetExchange(t, w, srv.Addr(), wire.HardResetClientV2, 5*time.Second)
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
	if answer, _ := resetExchange(t, w, srv.Addr(), wire.HardResetClientV2, time.Second); answer != nil {
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
	key := readStaticKey(t, keyFile)
	srv := servertest.Start(t, servertest.Options{Extra: []string{"--tls-crypt", keyFile, "--verb", "7"}})

	w, err := NewTLSCrypt(key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	answer, sid := resetExchange(t, w, srv.Addr(), wire.HardResetClientV2, 5*time.Second)
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
	if answer, _ := resetExchange(t, w, srv.Addr(), wire.HardResetClientV2, time.Second); answer != nil {
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
	if answer, _ := resetExchange(t, auth, srv.Addr(), wire.HardResetClientV2, time.Second); answer != nil {
		t.Fatalf("a tls-crypt server answered a tls-auth packet: %+v", answer)
	}
}

// TestTLSCryptV2WithRealServer is the whole of what tls-crypt-v2 needs of the
// start of a handshake, against a real server: the reset (V3) with the wrapped
// key appended, the server's answer with its early negotiation TLV, and the
// third packet, a CONTROL_WKC_V1 that carries the wrapped key again.
func TestTLSCryptV2WithRealServer(t *testing.T) {
	serverKey := servertest.GenKey(t, "tls-crypt-v2-server")
	clientKeyFile := servertest.GenTLSCryptV2ClientKey(t, serverKey)
	key := readV2ClientKey(t, clientKeyFile)
	srv := servertest.Start(t, servertest.Options{Extra: []string{"--tls-crypt-v2", serverKey, "--verb", "7"}})

	w, err := NewTLSCryptV2(key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	p := newPeer(t, w, srv.Addr())
	p.send(wire.Control{Opcode: wire.HardResetClientV3, PacketID: 0})
	answer := p.recv(5 * time.Second)
	if answer == nil {
		t.Fatalf("the server did not answer; its log:\n%s", srv.Log())
	}
	if answer.Opcode != wire.HardResetServerV2 {
		t.Errorf("the answer is %v, want CONTROL_HARD_RESET_SERVER_V2", answer.Opcode)
	}
	if len(answer.Acks) != 1 || answer.Acks[0] != 0 || answer.RemoteSessionID != p.sid || answer.PacketID != 0 {
		t.Errorf("the answer does not ack our reset: %+v", answer)
	}
	// The first packet had 0x0f in its replay id, so the server answers with
	// the TLV of early negotiation, and asks for the wrapped key again.
	resend, err := wire.ParseEarlyNegotiation(answer.Payload)
	if err != nil {
		t.Fatalf("the payload of the server's reset is not early negotiation TLVs: %v (payload %x)", err, answer.Payload)
	}
	if !resend {
		t.Errorf("the server did not ask for the wrapped key again (payload %x)", answer.Payload)
	}
	srv.WaitLog(t, "Reset packet from client, sending HMAC based reset challenge", 2*time.Second)

	// The third packet: the ack of the server's reset, with the wrapped key.
	p.send(wire.Control{
		Opcode: wire.ControlWKCV1, Acks: []uint32{answer.PacketID},
		RemoteSessionID: answer.SessionID, PacketID: 1,
	})
	srv.WaitLog(t, "Valid packet (P_CONTROL_WKC_V1) with HMAC challenge", 3*time.Second)
	ack := p.recv(3 * time.Second)
	if ack == nil {
		t.Fatalf("the server did not ack the third packet; its log:\n%s", srv.Log())
	}
	if ack.Opcode != wire.AckV1 || len(ack.Acks) != 1 || ack.Acks[0] != 1 || ack.RemoteSessionID != p.sid {
		t.Errorf("the answer to the third packet is not an ack of packet 1: %+v", ack)
	}
}

// TestTLSCryptV2ThirdPacketNeedsTheWrappedKey shows why CONTROL_WKC_V1 exists: a
// third packet without the wrapped key cannot be read by a server that kept no
// state, so it starts no session.
func TestTLSCryptV2ThirdPacketNeedsTheWrappedKey(t *testing.T) {
	serverKey := servertest.GenKey(t, "tls-crypt-v2-server")
	clientKeyFile := servertest.GenTLSCryptV2ClientKey(t, serverKey)
	key := readV2ClientKey(t, clientKeyFile)
	srv := servertest.Start(t, servertest.Options{Extra: []string{"--tls-crypt-v2", serverKey, "--verb", "7"}})
	w, err := NewTLSCryptV2(key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	p := newPeer(t, w, srv.Addr())
	p.send(wire.Control{Opcode: wire.HardResetClientV3, PacketID: 0})
	answer := p.recv(5 * time.Second)
	if answer == nil {
		t.Fatalf("no answer; log:\n%s", srv.Log())
	}
	// A CONTROL_V1 instead of a CONTROL_WKC_V1.
	p.send(wire.Control{
		Opcode: wire.ControlV1, Acks: []uint32{answer.PacketID},
		RemoteSessionID: answer.SessionID, PacketID: 1,
	})
	time.Sleep(1500 * time.Millisecond)
	if got := srv.Log(); strings.Contains(got, "accepting new connection") {
		t.Errorf("a session started from a third packet without the wrapped key:\n%s", got)
	}
}

func TestTLSCryptV2RefusedByRealServer(t *testing.T) {
	serverKey := servertest.GenKey(t, "tls-crypt-v2-server")
	otherServerKey := servertest.GenKey(t, "tls-crypt-v2-server")
	// A client key made for another server: its wrapped key does not unwrap.
	key := readV2ClientKey(t, servertest.GenTLSCryptV2ClientKey(t, otherServerKey))
	srv := servertest.Start(t, servertest.Options{Extra: []string{"--tls-crypt-v2", serverKey, "--verb", "7"}})
	w, err := NewTLSCryptV2(key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if answer, _ := resetExchange(t, w, srv.Addr(), wire.HardResetClientV3, time.Second); answer != nil {
		t.Fatalf("the server answered a client key of another server: %+v", answer)
	}
	if got := srv.Log(); strings.Contains(got, "sending HMAC based reset challenge") {
		t.Errorf("the server took the packet for a reset:\n%s", got)
	}
}

// readStaticKey reads a static key file that a test or openvpn made.
func readStaticKey(t testing.TB, path string) *keys.StaticKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.ParseStaticKey(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("the key file does not parse: %v", err)
	}
	return key
}

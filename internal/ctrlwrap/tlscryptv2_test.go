// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// v2Key is the client key of OpenVPN's own tests (internal/keys/testdata).
func v2Key(t testing.TB) *keys.TLSCryptV2ClientKey {
	t.Helper()
	return readV2ClientKey(t, "../keys/testdata/tls-crypt-v2-client.key")
}

// v2Pair makes a tls-crypt-v2 client and the server end that shares its Kc.
func v2Pair(t testing.TB, clk *clock) (client WKCWrapper, server Wrapper, key *keys.TLSCryptV2ClientKey) {
	t.Helper()
	key = v2Key(t)
	client, err := NewTLSCryptV2(key, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewTLSCryptServer(&key.Kc, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	return client, server, key
}

// stripWKc does what a server does with a packet that carries a wrapped key:
// it reads the length from the last 2 bytes and splits the packet.
func stripWKc(t testing.TB, packet []byte) (rest, wkc []byte) {
	t.Helper()
	if len(packet) < 2 {
		t.Fatal("no length at the end")
	}
	n := int(binary.BigEndian.Uint16(packet[len(packet)-2:]))
	if n > len(packet) {
		t.Fatalf("the length at the end is %d, the packet is %d bytes", n, len(packet))
	}
	return packet[:len(packet)-n], packet[len(packet)-n:]
}

func TestTLSCryptV2AppendsTheWrappedKeyWhereItBelongs(t *testing.T) {
	controlOpcodes := []wire.Opcode{
		wire.SoftResetV1, wire.ControlV1, wire.AckV1, wire.HardResetClientV2,
		wire.HardResetServerV2, wire.HardResetClientV3, wire.ControlWKCV1,
	}
	body := controlBody(t, 3, []byte("a payload"))
	for _, op := range controlOpcodes {
		t.Run(op.String(), func(t *testing.T) {
			client, server, key := v2Pair(t, newClock())
			first := wire.FirstByte(op, 2)
			packet, err := client.Wrap(nil, first, testSID, body)
			if err != nil {
				t.Fatal(err)
			}
			hasWKc := op == wire.HardResetClientV3 || op == wire.ControlWKCV1
			base := headerSize + client.Overhead() + len(body)
			if hasWKc {
				if len(packet) != base+len(key.WKc) {
					t.Fatalf("the packet is %d bytes, want %d plus the %d of WKc", len(packet), base, len(key.WKc))
				}
				if !bytes.HasSuffix(packet, key.WKc) {
					t.Error("the packet does not end with WKc")
				}
				// The server splits WKc off by the length at the end of the packet.
				rest, wkc := stripWKc(t, packet)
				if !bytes.Equal(wkc, key.WKc) {
					t.Error("the server would read another WKc")
				}
				packet = rest
			} else if len(packet) != base {
				t.Fatalf("the packet is %d bytes, want %d: it has no WKc", len(packet), base)
			}
			// What is left is an ordinary tls-crypt packet under Kc.
			got, err := server.Unwrap(packet)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, body) {
				t.Errorf("body = %x, want %x", got, body)
			}
		})
	}
}

func TestTLSCryptV2WrappedKeyIsNotEncrypted(t *testing.T) {
	client, _, key := v2Pair(t, newClock())
	packet, err := client.Wrap(nil, wire.FirstByte(wire.HardResetClientV3, 0), testSID, []byte("secret payload!!"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(packet, key.WKc) {
		t.Error("WKc is not in the packet as it is in the key file: the server could not read it")
	}
	if bytes.Contains(packet, []byte("secret payload")) {
		t.Error("the body is in the clear")
	}
}

func TestTLSCryptV2EarlyNegotiationPacketIDs(t *testing.T) {
	// The first packet carries 0x0f000001: the server sees from the top byte of
	// the id that the client can resend its wrapped key. The ids go on from there.
	client, _, _ := v2Pair(t, newClock())
	ops := []wire.Opcode{wire.HardResetClientV3, wire.HardResetClientV3, wire.ControlWKCV1, wire.ControlV1, wire.AckV1}
	for i, op := range ops {
		packet, err := client.Wrap(nil, wire.FirstByte(op, 0), testSID, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := wire.EarlyNegotiationStart + uint32(i) + 1
		if got := binary.BigEndian.Uint32(packet[headerSize:]); got != want {
			t.Errorf("packet %d (%v): id %#x, want %#x", i, op, got, want)
		}
		if packet[headerSize] != 0x0f {
			t.Errorf("packet %d: the top byte of the id is %#x, want 0x0f", i, packet[headerSize])
		}
	}
}

func TestTLSCryptV2ReceivesLikeTLSCrypt(t *testing.T) {
	client, server, _ := v2Pair(t, newClock())
	body := controlBody(t, 0, []byte("from the server"))
	// A server's reset has no wrapped key: it is wrapped with Kc.
	packet, err := server.Wrap(nil, wire.FirstByte(wire.HardResetServerV2, 0), testSID, body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Unwrap(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body = %x, want %x", got, body)
	}
	if _, err := client.Unwrap(packet); err == nil {
		t.Error("a replayed packet was accepted")
	}
	// A client's own packets are not for a client: two clients share no key.
	own, err := client.Wrap(nil, 0x20, testSID, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Unwrap(own); err == nil {
		t.Error("the client accepted a packet that it wrapped itself")
	}
}

func TestTLSCryptV2WKcLen(t *testing.T) {
	client, _, key := v2Pair(t, newClock())
	if client.WKcLen() != len(key.WKc) || client.WKcLen() != 299 {
		t.Errorf("WKcLen = %d, want %d (299 for this key)", client.WKcLen(), len(key.WKc))
	}
	if client.Overhead() != 40 {
		t.Errorf("Overhead = %d, want 40 as for tls-crypt", client.Overhead())
	}
}

func TestTLSCryptV2KeepsItsOwnCopyOfTheKey(t *testing.T) {
	key := v2Key(t)
	client, err := NewTLSCryptV2(key, newClock().now)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(key.WKc)
	for i := range key.WKc {
		key.WKc[i] = 0
	}
	packet, err := client.Wrap(nil, wire.FirstByte(wire.HardResetClientV3, 0), testSID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(packet, want) {
		t.Error("WKc changed with the key it was made from")
	}
}

func TestTLSCryptV2WrapFailsWithAnUnusableClock(t *testing.T) {
	clk := newClock()
	clk.t = time.Unix(-100, 0)
	client, _, _ := v2Pair(t, clk)
	before := []byte("keep")
	got, err := client.Wrap(before, wire.FirstByte(wire.HardResetClientV3, 0), testSID, nil)
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("tlsCryptV2.Wrap->tlsCrypt.Wrap->Sender.Next.ClockOutOfRange") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if !bytes.Equal(got, before) {
		t.Errorf("dst changed on failure (and WKc was added?): %x", got)
	}
}

func TestTLSCryptV2NilKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	_, _ = NewTLSCryptV2(nil, nil)
}

func FuzzTLSCryptV2RoundTrip(f *testing.F) {
	f.Add(byte(wire.HardResetClientV3<<3), []byte("body"))
	f.Add(byte(wire.ControlV1<<3|1), []byte{})
	f.Fuzz(func(t *testing.T, first byte, body []byte) {
		client, server, key := v2Pair(t, newClock())
		packet, err := client.Wrap(nil, first, testSID, body)
		if err != nil {
			t.Fatal(err)
		}
		if op, _ := wire.SplitFirstByte(first); op == wire.HardResetClientV3 || op == wire.ControlWKCV1 {
			var wkc []byte
			packet, wkc = stripWKc(t, packet)
			if !bytes.Equal(wkc, key.WKc) {
				t.Fatal("WKc is wrong")
			}
		}
		got, err := server.Unwrap(packet)
		if err != nil {
			t.Fatalf("a packet that was wrapped is refused: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("body = %x, want %x", got, body)
		}
	})
}

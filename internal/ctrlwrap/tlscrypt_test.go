// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

func TestTLSCryptRoundTrip(t *testing.T) {
	bodies := map[string][]byte{
		"empty":     nil,
		"one byte":  {9},
		"10 bytes":  []byte("1234567890"),
		"full size": bytes.Repeat([]byte{0xab}, 1200),
		"large":     bytes.Repeat([]byte{0x5a}, 60000),
	}
	for name, body := range bodies {
		for _, dir := range []string{"client to server", "server to client"} {
			t.Run(name+"/"+dir, func(t *testing.T) {
				client, server := newCryptPair(t, newClock())
				from, to := client, server
				if dir == "server to client" {
					from, to = server, client
				}
				first := wire.FirstByte(wire.ControlV1, 4)
				packet, err := from.Wrap(nil, first, testSID, body)
				if err != nil {
					t.Fatal(err)
				}
				if want := headerSize + from.Overhead() + len(body); len(packet) != want {
					t.Errorf("the packet is %d bytes, want %d", len(packet), want)
				}
				if from.Overhead() != 40 {
					t.Errorf("Overhead = %d, want 40 (8 of replay id and 32 of tag)", from.Overhead())
				}
				got, err := to.Unwrap(packet)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, body) {
					t.Errorf("Unwrap returned another body (%d bytes, want %d)", len(got), len(body))
				}
			})
		}
	}
}

// TestTLSCryptWireFormat rebuilds a packet from the draft with crypto/aes,
// crypto/hmac and the offsets of the static key, not with the code under test.
func TestTLSCryptWireFormat(t *testing.T) {
	clk := newClock()
	key := testKey(0x60)
	w, err := NewTLSCrypt(key, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	first := wire.FirstByte(wire.HardResetClientV2, 0)
	body := []byte("an acknowledgement count, ids, and a payload")

	// A client sends with key 1: cipher key at bytes 128 to 159, HMAC key at
	// 192 to 223 (each part of the static key has 64 bytes of each).
	block, err := aes.NewCipher(key[128 : 128+32])
	if err != nil {
		t.Fatal(err)
	}
	hmacKey := key[192 : 192+32]
	const startTime = uint32(clockStart)
	for id := uint32(1); id <= 3; id++ {
		got, err := w.Wrap(nil, first, testSID, body)
		if err != nil {
			t.Fatal(err)
		}
		header := append([]byte{first}, testSID[:]...)
		header = binary.BigEndian.AppendUint32(header, id)
		header = binary.BigEndian.AppendUint32(header, startTime)
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(header)
		mac.Write(body)
		tag := mac.Sum(nil)
		ciphertext := make([]byte, len(body))
		cipher.NewCTR(block, tag[:16]).XORKeyStream(ciphertext, body)

		want := append(append(header, tag...), ciphertext...)
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d:\n got %x\nwant %x", id, got, want)
		}
		clk.advance(time.Minute)
	}
}

func TestTLSCryptHidesTheBody(t *testing.T) {
	client, _ := newCryptPair(t, newClock())
	secret := []byte("a certificate is in here, said the TLS handshake")
	packet, err := client.Wrap(nil, 0x20, testSID, secret)
	if err != nil {
		t.Fatal(err)
	}
	for n := 4; n <= len(secret); n++ {
		if bytes.Contains(packet, secret[:n]) {
			t.Fatalf("the packet contains the first %d bytes of the body", n)
		}
	}
	// The same body in two packets is two different ciphertexts.
	again, err := client.Wrap(nil, 0x20, testSID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(packet[cryptHeaderSize+cryptTagSize:], again[cryptHeaderSize+cryptTagSize:]) {
		t.Error("two packets with the same body have the same ciphertext")
	}
}

func TestTLSCryptRefusesForgeries(t *testing.T) {
	client, server := newCryptPair(t, newClock())
	first := wire.FirstByte(wire.ControlV1, 1)
	body := controlBody(t, 7, []byte("hello"))
	packet, err := client.Wrap(nil, first, testSID, body)
	if err != nil {
		t.Fatal(err)
	}
	for i := range packet {
		for bit := 0; bit < 8; bit++ {
			forged := bytes.Clone(packet)
			forged[i] ^= 1 << bit
			_, err := server.Unwrap(forged)
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("byte %d bit %d: a forged packet was accepted (%v)", i, bit, err)
			}
			if !appErr.HasRoute("tlsCrypt.Unwrap.TLSCryptTagMismatch") && !appErr.HasRoute("tlsCrypt.Unwrap.TLSCryptPacketIDZero") {
				t.Fatalf("byte %d bit %d: unexpected failure path: %s", i, bit, appErr.Route())
			}
		}
	}
	for n := cryptHeaderSize + cryptTagSize; n < len(packet); n++ {
		if _, err := server.Unwrap(packet[:n]); err == nil {
			t.Fatalf("a packet cut to %d bytes was accepted", n)
		}
	}
	if _, err := server.Unwrap(append(bytes.Clone(packet), 0)); err == nil {
		t.Fatal("a packet with a byte added was accepted")
	}
	// Nothing was recorded by the forgeries.
	got, err := server.Unwrap(packet)
	if err != nil {
		t.Fatalf("the genuine packet was refused after the forgeries: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body = %x", got)
	}
}

func TestTLSCryptTooShort(t *testing.T) {
	_, server := newCryptPair(t, newClock())
	const min = cryptHeaderSize + cryptTagSize
	for n := 0; n < min; n++ {
		_, err := server.Unwrap(make([]byte, n))
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("%d bytes: expected *errors.Error, got %T: %v", n, err, err)
		}
		if !appErr.HasRoute("tlsCrypt.Unwrap.TLSCryptTooShort") {
			t.Errorf("%d bytes: unexpected failure path: %s", n, appErr.Route())
		}
		if appErr.Metadata["got"] != n || appErr.Metadata["want"] != min {
			t.Errorf("%d bytes: metadata = %v", n, appErr.Metadata)
		}
	}
	// A packet with no body is the shortest valid one.
	client, server2 := newCryptPair(t, newClock())
	packet, err := client.Wrap(nil, 0x20, testSID, nil)
	if err != nil || len(packet) != min {
		t.Fatalf("empty body: %d bytes, %v", len(packet), err)
	}
	if body, err := server2.Unwrap(packet); err != nil || len(body) != 0 {
		t.Errorf("empty body: %x, %v", body, err)
	}
}

func TestTLSCryptWrongKeyOrRole(t *testing.T) {
	clk := newClock()
	client := func(seed byte) Wrapper {
		w, err := NewTLSCrypt(testKey(seed), clk.now)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	server := func(seed byte) Wrapper {
		w, err := NewTLSCryptServer(testKey(seed), clk.now)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	tests := []struct {
		name         string
		from, to     Wrapper
		wantAccepted bool
	}{
		{"a client and a server of one key", client(1), server(1), true},
		{"another key", client(1), server(2), false},
		{"two clients", client(1), client(1), false},
		{"two servers", server(1), server(1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := tt.from.Wrap(nil, 0x20, testSID, controlBody(t, 0, []byte("x")))
			if err != nil {
				t.Fatal(err)
			}
			_, err = tt.to.Unwrap(packet)
			if tt.wantAccepted != (err == nil) {
				t.Errorf("accepted = %v, want %v (%v)", err == nil, tt.wantAccepted, err)
			}
			if err != nil {
				appErr, ok := errors.FromError(err)
				if !ok || !appErr.HasRoute("tlsCrypt.Unwrap.TLSCryptTagMismatch") {
					t.Errorf("unexpected failure: %v", err)
				}
			}
		})
	}
}

func TestTLSCryptReplays(t *testing.T) {
	clk := newClock()
	client, server := newCryptPair(t, clk)
	var packets [][]byte
	for i := 0; i < 100; i++ {
		p, err := client.Wrap(nil, 0x20, testSID, controlBody(t, uint32(i), nil))
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p)
	}
	expectReplay := func(p []byte, what string) {
		t.Helper()
		_, err := server.Unwrap(p)
		appErr, ok := errors.FromError(err)
		if !ok || !appErr.HasRoute("tlsCrypt.Unwrap.TLSCryptReplay") {
			t.Errorf("%s: expected a replay error, got %v", what, err)
		}
	}
	for _, i := range []int{2, 0, 1, 4, 3} {
		if _, err := server.Unwrap(packets[i]); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	for i := 0; i < 5; i++ {
		expectReplay(packets[i], "a packet taken before")
	}
	if _, err := server.Unwrap(packets[99]); err != nil {
		t.Fatal(err)
	}
	expectReplay(packets[34], "more than the window behind")
	if _, err := server.Unwrap(packets[40]); err != nil {
		t.Fatalf("a packet 60 behind the highest: %v", err)
	}
	expectReplay(packets[99], "the highest again")

	// And a packet that is late by more than the age.
	clk.advance(20 * time.Second)
	expectReplay(packets[50], "a packet 20 s after one that is higher")
}

func TestTLSCryptStartID(t *testing.T) {
	// tls-crypt-v2 starts its ids at 0x0f000000: the first packet is 0x0f000001.
	w, err := newTLSCrypt(testKey(1), keys.Inverse, 0x0f000000, newClock().now)
	if err != nil {
		t.Fatal(err)
	}
	for want := uint32(0x0f000001); want <= 0x0f000003; want++ {
		packet, err := w.Wrap(nil, 0x20, testSID, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint32(packet[headerSize:]); got != want {
			t.Errorf("packet id = %#x, want %#x", got, want)
		}
	}
}

func TestTLSCryptConstructorFailures(t *testing.T) {
	key := testKey(1)
	for _, dir := range []keys.Direction{keys.Bidirectional, keys.Direction(9)} {
		_, err := newTLSCrypt(key, dir, 0, nil)
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("%v: expected *errors.Error, got %T: %v", dir, err, err)
		}
		if !appErr.HasRoute("newTLSCrypt.TLSCryptNeedsDirection") {
			t.Errorf("%v: unexpected failure path: %s", dir, appErr.Route())
		}
		if appErr.Metadata["direction"] != dir.String() {
			t.Errorf("%v: metadata = %v", dir, appErr.Metadata)
		}
	}
	t.Run("nil key panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("no panic")
			}
		}()
		_, _ = NewTLSCrypt(nil, nil)
	})
	t.Run("nil clock is the real one", func(t *testing.T) {
		w, err := NewTLSCrypt(key, nil)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := w.Wrap(nil, 0x20, testSID, nil)
		if err != nil {
			t.Fatal(err)
		}
		sent := binary.BigEndian.Uint32(packet[headerSize+4:])
		if d := time.Since(time.Unix(int64(sent), 0)); d < -2*time.Second || d > 5*time.Second {
			t.Errorf("the time field is %v off the real clock", d)
		}
	})
}

func TestTLSCryptWrapFailsWithAnUnusableClock(t *testing.T) {
	clk := newClock()
	clk.t = time.Unix(-100, 0)
	client, _ := newCryptPair(t, clk)
	before := []byte("keep")
	got, err := client.Wrap(before, 0x20, testSID, nil)
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("tlsCrypt.Wrap->Sender.Next.ClockOutOfRange") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if !bytes.Equal(got, before) {
		t.Errorf("dst changed on failure: %x", got)
	}
}

func TestTLSCryptConcurrentUse(t *testing.T) {
	clk := newClock()
	client, server := newCryptPair(t, clk)
	const goroutines, each = 8, 100
	var mu sync.Mutex
	var packets [][]byte
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				p, err := client.Wrap(nil, 0x20, testSID, controlBody(t, 0, []byte("x")))
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				packets = append(packets, p)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	idOf := func(p []byte) uint32 { return binary.BigEndian.Uint32(p[headerSize:]) }
	sort.Slice(packets, func(i, j int) bool { return idOf(packets[i]) < idOf(packets[j]) })
	for i, p := range packets {
		if idOf(p) != uint32(i)+1 {
			t.Fatalf("packet %d has id %d: ids are repeated or missing", i, idOf(p))
		}
		if _, err := server.Unwrap(p); err != nil {
			t.Fatalf("packet id %d: %v", idOf(p), err)
		}
	}

	// One goroutine wraps while another unwraps.
	ch := make(chan []byte, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for p := range ch {
			if _, err := server.Unwrap(p); err != nil {
				t.Errorf("unwrap while wrapping: %v", err)
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		p, err := client.Wrap(nil, 0x20, testSID, controlBody(t, 0, nil))
		if err != nil {
			t.Fatal(err)
		}
		ch <- p
	}
	close(ch)
	<-done
}

func FuzzTLSCryptUnwrap(f *testing.F) {
	client, _ := newCryptPair(f, newClock())
	seed, err := client.Wrap(nil, 0x20, testSID, []byte{0, 0, 0, 0, 1, 'x'})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add(make([]byte, cryptHeaderSize+cryptTagSize))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, server := newCryptPair(t, newClock())
		if body, err := server.Unwrap(packet); err == nil && !bytes.Equal(packet, seed) {
			t.Fatalf("a packet that was not made with the key was accepted: %x -> %x", packet, body)
		}
	})
}

func FuzzTLSCryptRoundTrip(f *testing.F) {
	f.Add(byte(0x20), []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte("body"))
	f.Fuzz(func(t *testing.T, first byte, sidBytes, body []byte) {
		var sid wire.SessionID
		copy(sid[:], sidBytes)
		client, server := newCryptPair(t, newClock())
		packet, err := client.Wrap(nil, first, sid, body)
		if err != nil {
			t.Fatal(err)
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

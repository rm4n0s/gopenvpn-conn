// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

func TestTLSAuthRoundTrip(t *testing.T) {
	directions := []struct {
		name           string
		sender, remote keys.Direction
	}{
		{"client to server", keys.Inverse, keys.Normal},
		{"server to client", keys.Normal, keys.Inverse},
		{"no direction", keys.Bidirectional, keys.Bidirectional},
	}
	bodies := map[string][]byte{"empty": nil, "one byte": {9}, "full size": bytes.Repeat([]byte{0xab}, 1200)}
	for _, h := range hashes {
		for _, d := range directions {
			for name, body := range bodies {
				t.Run(h.name+"/"+d.name+"/"+name, func(t *testing.T) {
					clk := newClock()
					key := testKey(0x30)
					from, err := NewTLSAuth(key, d.sender, h.new, clk.now)
					if err != nil {
						t.Fatal(err)
					}
					to, err := NewTLSAuth(key, d.remote, h.new, clk.now)
					if err != nil {
						t.Fatal(err)
					}
					first := wire.FirstByte(wire.ControlV1, 2)
					packet, err := from.Wrap(nil, first, testSID, body)
					if err != nil {
						t.Fatal(err)
					}
					if want := headerSize + from.Overhead() + len(body); len(packet) != want {
						t.Errorf("the packet is %d bytes, want %d", len(packet), want)
					}
					if from.Overhead() != h.size+8 {
						t.Errorf("Overhead = %d, want %d", from.Overhead(), h.size+8)
					}
					got, err := to.Unwrap(packet)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, body) {
						t.Errorf("Unwrap = %x, want %x", got, body)
					}
				})
			}
		}
	}
}

// TestTLSAuthWireFormat checks the bytes of a packet against the layout of the
// draft, worked out here with crypto/hmac and the offsets of the static key,
// not with the code under test.
func TestTLSAuthWireFormat(t *testing.T) {
	for _, h := range hashes {
		t.Run(h.name, func(t *testing.T) {
			clk := newClock()
			key := testKey(0x40)
			w, err := NewTLSAuth(key, keys.Inverse, h.new, clk.now)
			if err != nil {
				t.Fatal(err)
			}
			first := wire.FirstByte(wire.HardResetClientV2, 0)
			body := []byte{0, 0, 0, 0, 0}

			// A client sends with key 1, whose HMAC key starts at byte 128+64 = 192.
			hmacKey := key[192 : 192+h.size]
			const startTime = uint32(clockStart) // the time field is the time of the first packet
			for id := uint32(1); id <= 3; id++ {
				got, err := w.Wrap(nil, first, testSID, body)
				if err != nil {
					t.Fatal(err)
				}
				var replayID [8]byte
				binary.BigEndian.PutUint32(replayID[:4], id)
				binary.BigEndian.PutUint32(replayID[4:], startTime)
				mac := hmac.New(h.new, hmacKey)
				mac.Write(replayID[:])
				mac.Write([]byte{first})
				mac.Write(testSID[:])
				mac.Write(body)

				want := append([]byte{first}, testSID[:]...)
				want = mac.Sum(want)
				want = append(want, replayID[:]...)
				want = append(want, body...)
				if !bytes.Equal(got, want) {
					t.Fatalf("packet %d:\n got %x\nwant %x", id, got, want)
				}
				clk.advance(time.Minute) // the next packet still has the time of the first
			}
		})
	}
}

func TestTLSAuthRefusesForgeries(t *testing.T) {
	for _, h := range hashes {
		t.Run(h.name, func(t *testing.T) {
			clk := newClock()
			client, server := newPair(t, h.new, clk)
			first := wire.FirstByte(wire.ControlV1, 1)
			packet, err := client.Wrap(nil, first, testSID, controlBody(t, 7, []byte("hello")))
			if err != nil {
				t.Fatal(err)
			}

			// Every bit of the packet matters: flip each one in turn. All of
			// them fail, and none of them changes what the receiver has seen.
			for i := range packet {
				for bit := 0; bit < 8; bit++ {
					forged := bytes.Clone(packet)
					forged[i] ^= 1 << bit
					_, err := server.Unwrap(forged)
					appErr, ok := errors.FromError(err)
					if !ok {
						t.Fatalf("byte %d bit %d: a forged packet was accepted (%v)", i, bit, err)
					}
					if !appErr.HasRoute("tlsAuth.Unwrap.TLSAuthHMACMismatch") && !appErr.HasRoute("tlsAuth.Unwrap.TLSAuthPacketIDZero") {
						t.Fatalf("byte %d bit %d: unexpected failure path: %s", i, bit, appErr.Route())
					}
				}
			}
			// Cut or lengthened, the packet fails too.
			for n := headerSize + h.size + 8; n < len(packet); n++ {
				if _, err := server.Unwrap(packet[:n]); err == nil {
					t.Fatalf("a packet cut to %d bytes was accepted", n)
				}
			}
			if _, err := server.Unwrap(append(bytes.Clone(packet), 0)); err == nil {
				t.Fatal("a packet with a byte added was accepted")
			}
			// The forgeries recorded nothing: the real packet is still new.
			body, err := server.Unwrap(packet)
			if err != nil {
				t.Fatalf("the genuine packet was refused after the forgeries: %v", err)
			}
			if !bytes.Equal(body, controlBody(t, 7, []byte("hello"))) {
				t.Errorf("body = %x", body)
			}
		})
	}
}

func TestTLSAuthTooShort(t *testing.T) {
	_, server := newPair(t, sha1.New, newClock())
	min := headerSize + 20 + 8
	for n := 0; n < min; n++ {
		_, err := server.Unwrap(make([]byte, n))
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("%d bytes: expected *errors.Error, got %T: %v", n, err, err)
		}
		if !appErr.HasRoute("tlsAuth.Unwrap.TLSAuthTooShort") {
			t.Errorf("%d bytes: unexpected failure path: %s", n, appErr.Route())
		}
		if appErr.Metadata["got"] != n || appErr.Metadata["want"] != min {
			t.Errorf("%d bytes: metadata = %v", n, appErr.Metadata)
		}
	}
}

func TestTLSAuthWrongKeyOrDirection(t *testing.T) {
	clk := newClock()
	mk := func(seed byte, dir keys.Direction) Wrapper {
		w, err := NewTLSAuth(testKey(seed), dir, sha1.New, clk.now)
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
		{"matching directions", mk(1, keys.Inverse), mk(1, keys.Normal), true},
		{"another key", mk(1, keys.Inverse), mk(2, keys.Normal), false},
		{"two clients", mk(1, keys.Inverse), mk(1, keys.Inverse), false},
		{"two servers", mk(1, keys.Normal), mk(1, keys.Normal), false},
		{"direction against none", mk(1, keys.Inverse), mk(1, keys.Bidirectional), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := tt.from.Wrap(nil, 0x20, testSID, controlBody(t, 0, nil))
			if err != nil {
				t.Fatal(err)
			}
			_, err = tt.to.Unwrap(packet)
			if tt.wantAccepted != (err == nil) {
				t.Errorf("accepted = %v, want %v (%v)", err == nil, tt.wantAccepted, err)
			}
			if err != nil {
				appErr, ok := errors.FromError(err)
				if !ok || !appErr.HasRoute("tlsAuth.Unwrap.TLSAuthHMACMismatch") {
					t.Errorf("unexpected failure: %v", err)
				}
			}
		})
	}
}

func TestTLSAuthReplays(t *testing.T) {
	clk := newClock()
	client, server := newPair(t, sha1.New, clk)
	wrap := func(n int) [][]byte {
		var out [][]byte
		for i := 0; i < n; i++ {
			p, err := client.Wrap(nil, 0x20, testSID, controlBody(t, uint32(i), nil))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, p)
		}
		return out
	}
	expectReplay := func(p []byte, what string) {
		t.Helper()
		_, err := server.Unwrap(p)
		appErr, ok := errors.FromError(err)
		if !ok || !appErr.HasRoute("tlsAuth.Unwrap.TLSAuthReplay") {
			t.Errorf("%s: expected a replay error, got %v", what, err)
		}
	}
	packets := wrap(100)

	// Out of order, inside the window of 64: each is taken once.
	for _, i := range []int{2, 0, 1, 4, 3} {
		if _, err := server.Unwrap(packets[i]); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	for i := 0; i < 5; i++ {
		expectReplay(packets[i], "a packet taken before")
	}
	// A big step ahead, then a packet from before the window.
	if _, err := server.Unwrap(packets[99]); err != nil {
		t.Fatal(err)
	}
	expectReplay(packets[34], "100 behind 36 more than the window")
	if _, err := server.Unwrap(packets[40]); err != nil { // 60 behind: inside
		t.Fatalf("a packet 60 behind the highest: %v", err)
	}
	expectReplay(packets[99], "the highest again")
}

func TestTLSAuthRefusesALatePacketAfterTheAge(t *testing.T) {
	clk := newClock()
	client, server := newPair(t, sha1.New, clk)
	var packets [][]byte
	for i := 0; i < 10; i++ {
		p, err := client.Wrap(nil, 0x20, testSID, controlBody(t, uint32(i), nil))
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p)
	}
	if _, err := server.Unwrap(packets[9]); err != nil {
		t.Fatal(err)
	}
	clk.advance(10 * time.Second)
	if _, err := server.Unwrap(packets[3]); err != nil {
		t.Fatalf("a packet 10 s after the highest one: %v", err)
	}
	clk.advance(10 * time.Second) // the highest packet is now 20 s old
	_, err := server.Unwrap(packets[4])
	appErr, ok := errors.FromError(err)
	if !ok || !appErr.HasRoute("tlsAuth.Unwrap.TLSAuthReplay") {
		t.Errorf("a packet 20 s after the highest one: %v, want a replay error", err)
	}
}

func TestTLSAuthANewSessionOfTheSameKey(t *testing.T) {
	// A client that starts again has ids from 1 and a later time: the server
	// takes them, and then refuses the old session's packets.
	clk := newClock()
	key := testKey(5)
	server, err := NewTLSAuth(key, keys.Normal, sha1.New, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	newClient := func() Wrapper {
		w, err := NewTLSAuth(key, keys.Inverse, sha1.New, clk.now)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	old := newClient()
	oldPacket, err := old.Wrap(nil, 0x20, testSID, controlBody(t, 0, nil))
	if err != nil {
		t.Fatal(err)
	}
	laterOld, err := old.Wrap(nil, 0x20, testSID, controlBody(t, 1, nil))
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(5 * time.Second)
	fresh := newClient() // time 5 s later, ids from 1 again
	freshPacket, err := fresh.Wrap(nil, 0x20, testSID, controlBody(t, 0, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Unwrap(freshPacket); err != nil {
		t.Fatalf("the new session: %v", err)
	}
	for name, p := range map[string][]byte{"first": oldPacket, "second": laterOld} {
		if _, err := server.Unwrap(p); err == nil {
			t.Errorf("a %s packet of the old session was taken after the new one", name)
		}
	}
}

func TestTLSAuthConstructorFailures(t *testing.T) {
	key := testKey(1)
	t.Run("hash larger than the key", func(t *testing.T) {
		_, err := NewTLSAuth(key, keys.Inverse, func() hash.Hash { return bigHash{sha1.New()} }, nil)
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("expected *errors.Error, got %T: %v", err, err)
		}
		if !appErr.HasRoute("NewTLSAuth.HashTooLarge") {
			t.Errorf("unexpected failure path: %s", appErr.Route())
		}
		if appErr.Metadata["size"] != 65 || appErr.Metadata["max"] != keys.PartSize {
			t.Errorf("metadata = %v", appErr.Metadata)
		}
	})
	t.Run("unknown direction", func(t *testing.T) {
		_, err := NewTLSAuth(key, keys.Direction(9), sha1.New, nil)
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("expected *errors.Error, got %T: %v", err, err)
		}
		if !appErr.HasRoute("NewTLSAuth->StaticKey.Parts.UnknownDirection") {
			t.Errorf("unexpected failure path: %s", appErr.Route())
		}
	})
	t.Run("nil arguments panic", func(t *testing.T) {
		for name, fn := range map[string]func(){
			"nil key":  func() { _, _ = NewTLSAuth(nil, keys.Inverse, sha1.New, nil) },
			"nil hash": func() { _, _ = NewTLSAuth(key, keys.Inverse, nil, nil) },
		} {
			func() {
				defer func() {
					if recover() == nil {
						t.Errorf("%s: no panic", name)
					}
				}()
				fn()
			}()
		}
	})
	t.Run("nil clock is the real one", func(t *testing.T) {
		w, err := NewTLSAuth(key, keys.Inverse, sha1.New, nil)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := w.Wrap(nil, 0x20, testSID, nil)
		if err != nil {
			t.Fatal(err)
		}
		sent := binary.BigEndian.Uint32(packet[headerSize+20+4:])
		if d := time.Since(time.Unix(int64(sent), 0)); d < -2*time.Second || d > 5*time.Second {
			t.Errorf("the time field is %v off the real clock", d)
		}
	})
}

// bigHash is a hash of 65 bytes, one more than the HMAC key of a static key.
type bigHash struct{ hash.Hash }

func (bigHash) Size() int { return 65 }

func TestTLSAuthWrapFailsWithAnUnusableClock(t *testing.T) {
	clk := newClock()
	clk.t = time.Unix(-100, 0)
	client, _ := newPair(t, sha1.New, clk)
	before := []byte("keep")
	got, err := client.Wrap(before, 0x20, testSID, nil)
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("tlsAuth.Wrap->Sender.Next.ClockOutOfRange") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if !bytes.Equal(got, before) {
		t.Errorf("dst changed on failure: %x", got)
	}
}

func TestTLSAuthConcurrentUse(t *testing.T) {
	// Many goroutines wrap at once: every packet has its own id, none repeated
	// (a repeated id would be a replay), and the receiver takes them all.
	clk := newClock()
	client, server := newPair(t, sha1.New, clk)
	const goroutines, each = 8, 100
	var mu sync.Mutex
	var packets [][]byte
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				p, err := client.Wrap(nil, 0x20, testSID, controlBody(t, 0, nil))
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
	idOf := func(p []byte) uint32 { return binary.BigEndian.Uint32(p[headerSize+20:]) }
	sort.Slice(packets, func(i, j int) bool { return idOf(packets[i]) < idOf(packets[j]) })
	for i, p := range packets {
		if idOf(p) != uint32(i)+1 {
			t.Fatalf("packet %d has id %d: ids are repeated or missing", i, idOf(p))
		}
		if _, err := server.Unwrap(p); err != nil {
			t.Fatalf("packet id %d: %v", idOf(p), err)
		}
	}

	// One goroutine wraps while another unwraps: each direction has its own state.
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

func FuzzTLSAuthUnwrap(f *testing.F) {
	clk := newClock()
	client, _ := newPair(f, sha1.New, clk)
	seed, err := client.Wrap(nil, 0x20, testSID, []byte{0, 0, 0, 0, 1, 'x'})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add(make([]byte, headerSize+28))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, server := newPair(t, sha1.New, newClock())
		// Never a panic, and a packet nobody made with the key is never taken.
		if body, err := server.Unwrap(packet); err == nil && !bytes.Equal(packet, seed) {
			t.Fatalf("a packet that was not made with the key was accepted: %x -> %x", packet, body)
		}
	})
}

func FuzzTLSAuthRoundTrip(f *testing.F) {
	f.Add(byte(0x20), []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte("body"))
	f.Fuzz(func(t *testing.T, first byte, sidBytes, body []byte) {
		var sid wire.SessionID
		copy(sid[:], sidBytes)
		client, server := newPair(t, sha1.New, newClock())
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

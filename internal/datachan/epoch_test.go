// SPDX-License-Identifier: GPL-2.0-only

package datachan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/rm4n0s/errors"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
)

var epochHeader = Header{KeyID: 3, HasPeerID: true, PeerID: 0xabcdef}

// epochPair makes the two ends of a channel: the client sends with the keys that
// the server receives with, and back.
func epochPair(t testing.TB, name string, o EpochOptions) (client, server *EpochChannel) {
	t.Helper()
	c := mustCipher(t, name)
	a, b := testKey(1), testKey(9)
	client, err := NewEpochChannel(c, a, b, epochHeader, o)
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewEpochChannel(c, b, a, epochHeader, o)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func pid(packet []byte) (epoch uint16, counter uint64) {
	id := binary.BigEndian.Uint64(packet[4:12])
	return uint16(id >> 48 & 0xffff), id & maxCounter
}

func TestEpochRoundTrip(t *testing.T) {
	sizes := []int{1, 2, 15, 16, 17, 100, 1400, 1500, 9000}
	for _, name := range cipherNames {
		t.Run(name, func(t *testing.T) {
			client, server := epochPair(t, name, EpochOptions{})
			now := epoch
			for i, n := range sizes {
				payload := bytes.Repeat([]byte{byte(i + 1)}, n)
				for _, dir := range []struct {
					from, to *EpochChannel
				}{{client, server}, {server, client}} {
					packet, err := dir.from.Seal(nil, payload)
					if err != nil {
						t.Fatal(err)
					}
					if want := epochHeaderSize + n + TagSize; len(packet) != want {
						t.Errorf("packet of %d bytes of payload is %d bytes, want %d", n, len(packet), want)
					}
					if packet[0] != 9<<3|3 || !bytes.Equal(packet[1:4], []byte{0xab, 0xcd, 0xef}) {
						t.Errorf("header % x", packet[:4])
					}
					if e, c := pid(packet); e != 1 || c != uint64(i+1) {
						t.Errorf("packet id: epoch %d counter %d, want 1 and %d", e, c, i+1)
					}
					now = now.Add(time.Millisecond)
					got, err := dir.to.Open(nil, packet, now)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("Open of %d bytes = %d bytes, %v", n, len(got), err)
					}
				}
			}
			if d := server.Dropped(); d != (Drops{}) {
				t.Errorf("dropped %+v", d)
			}
		})
	}
}

// ovpnLabel is OVPN-Expand-Label by hand with the standard library, from the draft.
func ovpnLabel(t *testing.T, secret []byte, label string, length int) []byte {
	t.Helper()
	l := "ovpn " + label
	info := []byte{byte(length >> 8 & 0xff), byte(length & 0xff), byte(len(l) & 0xff)}
	info = append(info, l...)
	info = append(info, 0) // an empty context
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestEpochPacketBytes builds the packets of epochs 1 and 3 by hand from the draft
// and compares: the epoch key chain, the data key and IV of each epoch, the nonce
// (the packet id and four zero bytes, XORed with the 12-byte IV), the additional
// data (the whole header) and the tag at the end.
func TestEpochPacketBytes(t *testing.T) {
	for _, name := range cipherNames {
		t.Run(name, func(t *testing.T) {
			c := mustCipher(t, name)
			key := testKey(5)
			ch, err := NewEpochChannel(c, key, testKey(6), epochHeader, EpochOptions{})
			if err != nil {
				t.Fatal(err)
			}
			secret := bytes.Clone(key.Cipher[:32]) // E_1
			for want := uint16(1); want <= 3; want++ {
				if want > 1 {
					secret = ovpnLabel(t, secret, "datakey upd", 32)
				}
				if want == 2 {
					continue // the channel is moved from 1 to 3 below
				}
				if want == 3 {
					ch.sendMu.Lock()
					err := ch.moveSendTo(3)
					ch.sendMu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}
				dataKey := ovpnLabel(t, secret, "data_key", c.KeySize())
				iv := ovpnLabel(t, secret, "data_iv", 12)
				var aead cipher.AEAD
				if name == "CHACHA20-POLY1305" {
					aead, err = chacha20poly1305.New(dataKey)
				} else {
					var block cipher.Block
					if block, err = aes.NewCipher(dataKey); err == nil {
						aead, err = cipher.NewGCM(block)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				for counter := uint64(1); counter <= 2; counter++ {
					payload := []byte("an IP packet, more or less")
					got, err := ch.Seal(nil, payload)
					if err != nil {
						t.Fatal(err)
					}
					header := []byte{9<<3 | 3, 0xab, 0xcd, 0xef}
					header = binary.BigEndian.AppendUint64(header, uint64(want)<<48|counter)
					nonce := make([]byte, 12)
					copy(nonce, header[4:])
					for i := range nonce {
						nonce[i] ^= iv[i]
					}
					expect := aead.Seal(append([]byte{}, header...), nonce, payload, header)
					if !bytes.Equal(got, expect) {
						t.Errorf("epoch %d counter %d\n got %x\nwant %x", want, counter, got, expect)
					}
				}
			}
		})
	}
}

// TestKnownEpochPacket pins the bytes of the first packet of epoch 1 (the payload is
// "hello"; the keys are testKey(1) and testKey(9)), which TestEpochPacketBytes builds
// by hand, so that a change of the format shows.
func TestKnownEpochPacket(t *testing.T) {
	tests := []struct {
		name   string
		packet string
	}{
		{"AES-256-GCM", "4babcdef00010000000000017263ef225aa4ccabd1145807f49d1946a8e3c6c262"},
		{"CHACHA20-POLY1305", "4babcdef000100000000000100abf750810d5e39c7357aa429af26317ef92c07e2"},
	}
	for _, tt := range tests {
		client, server := epochPair(t, tt.name, EpochOptions{})
		got, err := client.Seal(nil, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != tt.packet {
			t.Errorf("%s: packet %x, want %s", tt.name, got, tt.packet)
		}
		want, _ := hex.DecodeString(tt.packet)
		if out, err := server.Open(nil, want, epoch); err != nil || string(out) != "hello" {
			t.Errorf("%s: Open of the pinned packet = %q, %v", tt.name, out, err)
		}
	}
}

func TestEpochMovesWithTheUsageLimit(t *testing.T) {
	for _, name := range cipherNames {
		t.Run(name, func(t *testing.T) {
			client, server := epochPair(t, name, EpochOptions{UsageLimit: 40})
			var lastEpoch uint16 = 1
			seen := map[uint64]bool{}
			now := epoch
			for i := range 1500 {
				packet, err := client.Seal(nil, []byte{byte(i), 1, 2})
				if err != nil {
					t.Fatal(err)
				}
				e, c := pid(packet)
				if e < lastEpoch || e > lastEpoch+1 {
					t.Fatalf("the epoch went from %d to %d", lastEpoch, e)
				}
				if e != lastEpoch && c != 1 {
					t.Fatalf("the first packet of epoch %d has counter %d", e, c)
				}
				lastEpoch = e
				key := uint64(e)<<48 | c
				if seen[key] {
					t.Fatalf("epoch %d counter %d was used twice", e, c)
				}
				seen[key] = true
				now = now.Add(time.Millisecond)
				if _, err := server.Open(nil, packet, now); err != nil {
					t.Fatalf("packet %d (epoch %d, counter %d): %v", i, e, c, err)
				}
			}
			if lastEpoch < 20 {
				t.Errorf("only %d epochs in 1500 packets with a limit of 40", lastEpoch)
			}
			if got := server.ReceiveEpoch(); got != lastEpoch {
				t.Errorf("the receiver is at epoch %d, the sender at %d", got, lastEpoch)
			}
			if d := server.Dropped(); d != (Drops{}) {
				t.Errorf("dropped %+v", d)
			}
		})
	}
}

// Packets that arrive out of order across the end of an epoch are all taken: the
// ones of the epoch before come in as retiring, and nothing is lost.
func TestEpochReorderedPacketsAcrossTheBoundary(t *testing.T) {
	client, server := epochPair(t, "AES-256-GCM", EpochOptions{UsageLimit: 60})
	var packets [][]byte
	for i := range 400 {
		p, err := client.Seal(nil, []byte{byte(i), byte(i >> 8)})
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p)
	}
	if e, _ := pid(packets[len(packets)-1]); e < 5 {
		t.Fatalf("only %d epochs", e)
	}
	// Reverse each run of 10: the packets of two neighboring epochs mix.
	for i := 0; i+10 <= len(packets); i += 10 {
		for a, b := i, i+9; a < b; a, b = a+1, b-1 {
			packets[a], packets[b] = packets[b], packets[a]
		}
	}
	got := 0
	for _, p := range packets {
		if _, err := server.Open(nil, p, epoch); err != nil {
			e, c := pid(p)
			t.Errorf("epoch %d counter %d: %v", e, c, err)
			continue
		}
		got++
	}
	if got != len(packets) {
		t.Errorf("%d of %d packets opened", got, len(packets))
	}
}

func TestEpochsFarInTheFutureAreDropped(t *testing.T) {
	client, server := epochPair(t, "AES-256-GCM", EpochOptions{}) // 4 future keys: epochs 2 to 5
	seal := func(e uint16) []byte {
		t.Helper()
		client.sendMu.Lock()
		err := client.moveSendTo(e)
		client.sendMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		p, err := client.Seal(nil, []byte{1})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	far := seal(6)
	if _, err := server.Open(nil, far, epoch); err == nil {
		t.Fatal("a packet of epoch 6 opened with 4 future keys")
	} else {
		wantTag(t, err, tagUnknownEpoch, "EpochChannel.Open.DataPacketUnknownEpoch")
	}
	if server.ReceiveEpoch() != 1 || server.Dropped().Epoch != 1 {
		t.Errorf("receive epoch %d, drops %+v", server.ReceiveEpoch(), server.Dropped())
	}
	// The edge of the window is taken, and the receiver, and then its sender, move there.
	client2, server2 := epochPair(t, "AES-256-GCM", EpochOptions{})
	client2.sendMu.Lock()
	if err := client2.moveSendTo(5); err != nil {
		t.Fatal(err)
	}
	client2.sendMu.Unlock()
	edge, err := client2.Seal(nil, []byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := server2.Open(nil, edge, epoch); err != nil || !bytes.Equal(out, []byte{2}) {
		t.Fatalf("epoch 5: %x, %v", out, err)
	}
	if server2.ReceiveEpoch() != 5 || server2.SendEpoch() != 5 {
		t.Errorf("the server is at receive epoch %d, send epoch %d, want 5 and 5", server2.ReceiveEpoch(), server2.SendEpoch())
	}
	// What the server sends now is epoch 5 and the client takes it.
	back, err := server2.Seal(nil, []byte{3})
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := pid(back); e != 5 {
		t.Errorf("the server's packet is of epoch %d", e)
	}
	if out, err := client2.Open(nil, back, epoch); err != nil || !bytes.Equal(out, []byte{3}) {
		t.Errorf("the client's Open of epoch 5 = %x, %v", out, err)
	}
	// Epoch 1 is retiring now, and still opens; epochs 2 to 4 are gone, and so is 6.
	if _, err := server2.Open(nil, mustSealAt(t, 1), epoch); err != nil {
		t.Errorf("a packet of epoch 1 after the move to 5: %v", err)
	}
	for _, e := range []uint16{2, 3, 4} {
		if _, err := server2.Open(nil, mustSealAt(t, e), epoch); err == nil {
			t.Errorf("a packet of epoch %d opened after the move to 5", e)
		}
	}
}

// mustSealAt is a packet of the given epoch from a fresh pair of the default keys
// (the packet of epoch 1 of the test above).
func mustSealAt(t *testing.T, e uint16) []byte {
	t.Helper()
	client, _ := epochPair(t, "AES-256-GCM", EpochOptions{})
	client.sendMu.Lock()
	if err := client.moveSendTo(e); err != nil {
		t.Fatal(err)
	}
	client.sendMu.Unlock()
	p, err := client.Seal(nil, []byte{9})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEpochReplayIsPerEpoch(t *testing.T) {
	client, server := epochPair(t, "CHACHA20-POLY1305", EpochOptions{})
	a1, _ := client.Seal(nil, []byte{1})
	a2, _ := client.Seal(nil, []byte{2})
	a3, _ := client.Seal(nil, []byte{3}) // never delivered until the end
	client.sendMu.Lock()
	if err := client.moveSendTo(2); err != nil {
		t.Fatal(err)
	}
	client.sendMu.Unlock()
	b1, _ := client.Seal(nil, []byte{4})
	b2, _ := client.Seal(nil, []byte{5})

	steps := []struct {
		name   string
		packet []byte
		ok     bool
		tag    string
	}{
		{"a1", a1, true, ""},
		{"a1 again", a1, false, tagReplayed},
		{"b1 moves to epoch 2", b1, true, ""},
		{"b1 again", b1, false, tagReplayed},
		{"a2 arrives late, as retiring", a2, true, ""},
		{"a2 again, in the retiring window", a2, false, tagReplayed},
		{"a1 again, in the retiring window", a1, false, tagReplayed},
		{"b2", b2, true, ""},
		{"a3, never seen, retiring still holds it", a3, true, ""},
	}
	for _, s := range steps {
		_, err := server.Open(nil, s.packet, epoch)
		if (err == nil) != s.ok {
			t.Errorf("%s: err = %v, want ok = %v", s.name, err, s.ok)
		}
		if err != nil {
			wantTag(t, err, s.tag, "EpochChannel.Open."+s.tag)
		}
	}
	// A third epoch retires the second, and the first is then unknown.
	client.sendMu.Lock()
	if err := client.moveSendTo(3); err != nil {
		t.Fatal(err)
	}
	client.sendMu.Unlock()
	c1, _ := client.Seal(nil, []byte{6})
	if _, err := server.Open(nil, c1, epoch); err != nil {
		t.Fatal(err)
	}
	client1, _ := epochPair(t, "CHACHA20-POLY1305", EpochOptions{})
	old, _ := client1.Seal(nil, []byte{7}) // epoch 1 again, from a fresh pair
	if _, err := server.Open(nil, old, epoch); err == nil {
		t.Error("a packet of epoch 1 opened after epoch 3 became current")
	} else {
		wantTag(t, err, tagUnknownEpoch, "EpochChannel.Open.DataPacketUnknownEpoch")
	}
}

// TestEpochLookupWindow is the table of OpenVPN's tests (crypto_test_epoch_key_
// receive_lookup and crypto_test_epoch_edge), with 13 future keys.
func TestEpochLookupWindow(t *testing.T) {
	_, server := epochPair(t, "AES-128-GCM", EpochOptions{FutureKeys: 13})
	known := func(want ...uint16) {
		t.Helper()
		in := map[uint16]bool{}
		for _, e := range want {
			in[e] = true
		}
		for e := uint16(0); e < 30; e++ {
			if slot, _ := server.lookup(e); (slot != nil) != in[e] {
				t.Errorf("lookup(%d) found = %v, want %v", e, slot != nil, in[e])
			}
		}
		for _, e := range []uint16{2000, 0xefff, 0xffff} {
			if slot, _ := server.lookup(e); slot != nil {
				t.Errorf("lookup(%d) found a key", e)
			}
		}
	}
	known(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)
	if err := server.promote(7 - 2); err != nil { // the key of epoch 7
		t.Fatal(err)
	}
	known(1, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20)
	if err := server.promote(0); err != nil { // epoch 8
		t.Fatal(err)
	}
	known(7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21)
	if server.recv.retiring.epoch != 7 || server.recv.current.epoch != 8 || len(server.recv.ahead) != 13 {
		t.Errorf("retiring %d, current %d, %d future keys", server.recv.retiring.epoch, server.recv.current.epoch, len(server.recv.ahead))
	}
	// Move 13 epochs at a time at the edge of the window, as crypto_test_epoch_edge does.
	for range 13 {
		if err := server.promote(0); err != nil {
			t.Fatal(err)
		}
	}
	if server.recv.current.epoch != 21 {
		t.Fatalf("current epoch %d", server.recv.current.epoch)
	}
	if slot, _ := server.lookup(21 + 14); slot != nil {
		t.Error("an epoch 14 ahead is known with 13 future keys")
	}
}

// placeReceiverAt puts the receiver of a channel at an epoch by deriving the keys
// from a made-up secret: going through 65,000 epochs one by one would only make the
// test slow.
func placeReceiverAt(t *testing.T, ch *EpochChannel, at uint16) {
	t.Helper()
	e := keys.EpochKey{Epoch: 1}
	copy(e.Secret[:], bytes.Repeat([]byte{0x5a}, 32))
	for e.Epoch < at {
		var err error
		if e, err = e.Next(); err != nil {
			t.Fatal(err)
		}
	}
	st, err := newEpochState(ch.cipher, e)
	if err != nil {
		t.Fatal(err)
	}
	ch.recv.current = recvSlot{epochState: st, window: ch.newWindow()}
	ch.recv.retiring = recvSlot{}
	ch.recv.ahead = nil
	ch.recv.top = e
	if err := ch.fillAhead(); err != nil {
		t.Fatal(err)
	}
}

// Near the end of the 16-bit epochs there are no future keys, so the receiver never
// derives a key past 0xffff (OpenVPN's crypto_test_epoch_key_overflow, with 32).
func TestEpochLookupAtTheEndOfTheEpochs(t *testing.T) {
	_, server := epochPair(t, "AES-128-GCM", EpochOptions{FutureKeys: 32})
	placeReceiverAt(t, server, 0xffff-40)
	found := func(e uint16) bool { slot, _ := server.lookup(e); return slot != nil }
	// Inside the window, and not too near the end: found.
	for _, e := range []uint16{0xffff - 40, 0xffff - 39, 0xffff - 34, 0xffff - 33} {
		if !found(e) {
			t.Errorf("lookup(%d) found nothing", e)
		}
	}
	// A key past that would need future keys past 0xffff: not given.
	for _, e := range []uint16{0xffff - 32, 0xffff - 31, 0xffff - 9, 0xffff} {
		if found(e) {
			t.Errorf("lookup(%d) found a key", e)
		}
	}
	_, ahead := server.lookup(0xffff - 33)
	if err := server.promote(ahead); err != nil {
		t.Fatal(err)
	}
	if server.recv.current.epoch != 0xffff-33 || !found(0xffff-33) || found(0xffff-32) || found(0xffff) {
		t.Errorf("after the last move: current %d", server.recv.current.epoch)
	}
	if len(server.recv.ahead) != 32 || server.recv.top.Epoch != 0xffff-1 {
		t.Errorf("%d future keys, the last of epoch %d", len(server.recv.ahead), server.recv.top.Epoch)
	}
}

// CHACHA20-POLY1305 has no usage limit, so only the 48-bit counter moves its epoch.
func TestEpochSenderCounterEnds(t *testing.T) {
	client, server := epochPair(t, "CHACHA20-POLY1305", EpochOptions{})
	client.send.counter = maxCounter - 1
	last, err := client.Seal(nil, []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if e, c := pid(last); e != 1 || c != maxCounter {
		t.Fatalf("last packet of the epoch: %d, %d", e, c)
	}
	next, err := client.Seal(nil, []byte{2}) // the counter is used up: epoch 2
	if err != nil {
		t.Fatal(err)
	}
	if e, c := pid(next); e != 2 || c != 1 {
		t.Fatalf("first packet after: epoch %d counter %d, want 2 and 1", e, c)
	}
	for _, p := range [][]byte{last, next} {
		if _, err := server.Open(nil, p, epoch); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEpochSenderEndsAtTheLastEpoch(t *testing.T) {
	client, _ := epochPair(t, "CHACHA20-POLY1305", EpochOptions{})
	e := keys.EpochKey{Epoch: keys.MaxEpoch}
	copy(e.Secret[:], bytes.Repeat([]byte{7}, 32))
	client.sendMu.Lock()
	if err := client.setSend(e); err != nil {
		t.Fatal(err)
	}
	client.sendMu.Unlock()
	client.send.counter = maxCounter - 1
	if _, err := client.Seal(nil, []byte{1}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		out, err := client.Seal([]byte("keep"), []byte{2})
		wantTag(t, err, tagPacketIDExhausted, "EpochChannel.Seal.DataPacketIDExhausted")
		if string(out) != "keep" {
			t.Errorf("Seal returned %q with its error", out)
		}
	}
}

func TestEpochNeedsRenegotiation(t *testing.T) {
	client, _ := epochPair(t, "AES-256-GCM", EpochOptions{})
	if client.NeedsRenegotiation() {
		t.Error("a new channel needs a renegotiation")
	}
	for _, tt := range []struct {
		epoch uint16
		want  bool
	}{{RenegotiateEpoch - 1, false}, {RenegotiateEpoch, true}, {0xffff, true}} {
		e := keys.EpochKey{Epoch: tt.epoch}
		client.sendMu.Lock()
		if err := client.setSend(e); err != nil {
			t.Fatal(err)
		}
		client.sendMu.Unlock()
		if got := client.NeedsRenegotiation(); got != tt.want {
			t.Errorf("at epoch %#x: %v, want %v", tt.epoch, got, tt.want)
		}
	}
}

// When what a receiver took reaches its limit it moves its own sender to a new
// epoch, to push the peer to a new key; the peer need not follow.
func TestEpochTheReceiveLimitMovesTheSender(t *testing.T) {
	client, _ := epochPair(t, "AES-256-GCM", EpochOptions{UsageLimit: 30})
	// The server sends a lot, with the default limit of its own, which is far away.
	srv, err := NewEpochChannel(mustCipher(t, "AES-256-GCM"), testKey(9), testKey(1), epochHeader, EpochOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		p, err := srv.Seal(nil, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Open(nil, p, epoch); err != nil {
			t.Fatal(err)
		}
	}
	if client.SendEpoch() != 1 {
		t.Fatalf("the client moved before it sent anything: epoch %d", client.SendEpoch())
	}
	p, err := client.Seal(nil, []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := pid(p); e != 2 {
		t.Errorf("the client's packet is of epoch %d, want 2: its receive key reached the limit", e)
	}
	// The server (limit far away) takes the packet and moves too.
	if _, err := srv.Open(nil, p, epoch); err != nil {
		t.Fatal(err)
	}
	if srv.SendEpoch() != 2 {
		t.Errorf("the server did not follow: epoch %d", srv.SendEpoch())
	}
}

func TestEpochAnyChangedByteIsRefused(t *testing.T) {
	for _, name := range cipherNames {
		t.Run(name, func(t *testing.T) {
			client, server := epochPair(t, name, EpochOptions{})
			good, err := client.Seal(nil, []byte("some payload that is long enough"))
			if err != nil {
				t.Fatal(err)
			}
			flips := 0
			for i := range good {
				for bit := range 8 {
					bad := bytes.Clone(good)
					bad[i] ^= 1 << bit
					flips++
					if got, err := server.Open(nil, bad, epoch); err == nil {
						t.Fatalf("byte %d bit %d changed and the packet opened as %q", i, bit, got)
					}
				}
			}
			d := server.Dropped()
			if total := d.Short + d.Format + d.KeyID + d.Replay + d.Auth + d.Epoch; total != uint64(flips) {
				t.Errorf("%d flips, %d drops (%+v)", flips, total, d)
			}
			if server.ReceiveEpoch() != 1 {
				t.Errorf("a forged packet moved the receiver to epoch %d", server.ReceiveEpoch())
			}
			if got, err := server.Open(nil, good, epoch); err != nil || string(got) != "some payload that is long enough" {
				t.Errorf("the good packet after the bad ones: %q, %v", got, err)
			}
		})
	}
}

// A forged packet of a future epoch does not move anything.
func TestEpochForgedFutureEpochChangesNothing(t *testing.T) {
	client, server := epochPair(t, "AES-256-GCM", EpochOptions{})
	p, _ := client.Seal(nil, []byte("x"))
	forged := bytes.Clone(p)
	binary.BigEndian.PutUint64(forged[4:], 3<<48|1) // epoch 3, with the tag of epoch 1
	if _, err := server.Open(nil, forged, epoch); err == nil {
		t.Fatal("a forged packet opened")
	}
	if server.ReceiveEpoch() != 1 || server.SendEpoch() != 1 {
		t.Errorf("epochs moved to %d and %d", server.ReceiveEpoch(), server.SendEpoch())
	}
	if _, err := server.Open(nil, p, epoch); err != nil {
		t.Errorf("the real packet: %v", err)
	}
}

func TestEpochOpenRefusals(t *testing.T) {
	client, server := epochPair(t, "AES-256-GCM", EpochOptions{})
	good, _ := client.Seal(nil, []byte("payload"))
	otherKeyID := bytes.Clone(good)
	otherKeyID[0] ^= 1
	control := append([]byte{4 << 3}, good[1:]...)
	v1 := append([]byte{6<<3 | 3}, good[1:]...)
	epoch0 := bytes.Clone(good)
	binary.BigEndian.PutUint64(epoch0[4:], 1)
	tests := []struct {
		name   string
		packet []byte
		tag    string
		route  string
		drops  Drops
	}{
		{"nothing", nil, tagPacketTooShort, "EpochChannel.Open.DataPacketTooShort", Drops{Short: 1}},
		{"one byte short", good[:epochMinPacket-1], tagPacketTooShort, "EpochChannel.Open.DataPacketTooShort", Drops{Short: 1}},
		{"a control packet", control, tagWrongFormat, "EpochChannel.Open.DataPacketWrongFormat", Drops{Format: 1}},
		{"DATA_V1", v1, tagWrongFormat, "EpochChannel.Open.DataPacketWrongFormat", Drops{Format: 1}},
		{"another key id", otherKeyID, tagWrongKeyID, "EpochChannel.Open.DataPacketWrongKeyID", Drops{KeyID: 1}},
		{"epoch 0", epoch0, tagUnknownEpoch, "EpochChannel.Open.DataPacketUnknownEpoch", Drops{Epoch: 1}},
	}
	for _, tt := range tests {
		before := server.Dropped()
		_, err := server.Open(nil, tt.packet, epoch)
		wantTag(t, err, tt.tag, tt.route)
		after := server.Dropped()
		var got Drops
		got.Short, got.Format, got.KeyID, got.Epoch = after.Short-before.Short, after.Format-before.Format, after.KeyID-before.KeyID, after.Epoch-before.Epoch
		if got != tt.drops {
			t.Errorf("%s: drops %+v, want %+v", tt.name, got, tt.drops)
		}
	}
	if _, err := server.Open(nil, good, epoch); err != nil {
		t.Errorf("the good packet after the refusals: %v", err)
	}
	if _, err := server.Open(nil, good, epoch); err == nil {
		t.Error("a replay opened")
	} else {
		wantTag(t, err, tagReplayed, "EpochChannel.Open.DataPacketReplayed")
	}
}

func TestEpochNewRefusals(t *testing.T) {
	c := mustCipher(t, "AES-256-GCM")
	tests := []struct {
		name  string
		build func() error
		tag   string
		route string
	}{
		{"no peer id", func() error {
			_, err := NewEpochChannel(c, testKey(1), testKey(2), Header{KeyID: 1}, EpochOptions{})
			return err
		}, tagEpochNeedsPeerID, "NewEpochChannel.DataEpochNeedsPeerID"},
		{"a key id that is too big", func() error {
			_, err := NewEpochChannel(c, testKey(1), testKey(2), Header{KeyID: 8, HasPeerID: true}, EpochOptions{})
			return err
		}, tagBadHeader, "NewEpochChannel->Header.validate.DataHeaderInvalid"},
		{"a cipher that is not one", func() error {
			_, err := NewEpochChannel(Cipher{}, testKey(1), testKey(2), epochHeader, EpochOptions{})
			return err
		}, tagBadCipher, "NewEpochChannel.DataCipherInvalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { wantTag(t, tt.build(), tt.tag, tt.route) })
	}
}

func TestEpochSealRefusesAnEmptyPayload(t *testing.T) {
	client, _ := epochPair(t, "AES-256-GCM", EpochOptions{})
	_, err := client.Seal(nil, nil)
	wantTag(t, err, tagEmptyPayload, "EpochChannel.Seal.DataPayloadEmpty")
	if client.send.counter != 0 {
		t.Error("a refused payload used a packet id")
	}
}

func TestEpochStrictOrder(t *testing.T) {
	client, server := epochPair(t, "AES-256-GCM", EpochOptions{Strict: true, UsageLimit: 12})
	var packets [][]byte
	for i := range 60 {
		p, err := client.Seal(nil, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p)
	}
	for i, p := range packets {
		if _, err := server.Open(nil, p, epoch); err != nil {
			t.Fatalf("packet %d in order: %v", i, err)
		}
	}
	if server.ReceiveEpoch() < 3 {
		t.Errorf("only epoch %d", server.ReceiveEpoch())
	}
	// Out of order and repeats are refused in the epoch they belong to.
	p1, _ := client.Seal(nil, []byte{1})
	p2, _ := client.Seal(nil, []byte{2})
	p3, _ := client.Seal(nil, []byte{3})
	for _, step := range []struct {
		p  []byte
		ok bool
	}{{p1, true}, {p3, false}, {p1, false}, {p2, true}, {p3, true}} {
		if _, err := server.Open(nil, step.p, epoch); (err == nil) != step.ok {
			t.Errorf("err = %v, want ok = %v", err, step.ok)
		}
	}
}

func TestEpochAllocations(t *testing.T) {
	for _, name := range cipherNames {
		client, server := epochPair(t, name, EpochOptions{Window: 1 << 16, MaxAge: time.Hour})
		payload := bytes.Repeat([]byte{7}, 1400)
		sealed := make([]byte, 0, 2048)
		opened := make([]byte, 0, 2048)
		if got := testing.AllocsPerRun(100, func() {
			if _, err := client.Seal(sealed[:0], payload); err != nil {
				t.Fatal(err)
			}
		}); got != 0 {
			t.Errorf("%s: Seal allocates %v times per packet, want 0", name, got)
		}
		packets := make([][]byte, 101)
		for i := range packets {
			packets[i], _ = client.Seal(nil, payload)
		}
		i := 0
		if got := testing.AllocsPerRun(100, func() {
			if _, err := server.Open(opened[:0], packets[i], epoch); err != nil {
				t.Fatal(err)
			}
			i++
		}); got != 0 {
			t.Errorf("%s: Open allocates %v times per packet, want 0", name, got)
		}
	}
}

// Both directions run at the same time, each with a goroutine that seals and one
// that opens, and the limit is so small that the packets that come make a sender
// move to new epochs (the sender is moved by Open while Seal runs): under -race. Each
// side raises its epoch when its keys reach the limit and again to follow the other,
// so with a limit this small the epochs run away from each other much faster than
// they do with the real limit of 2^36; the window of future keys is made wide enough
// that this test never leaves it (a sender that does leave the window of a receiver
// is dropped, which is how the epochs are meant to work, SPEC §10).
func TestEpochSealAndOpenAtTheSameTime(t *testing.T) {
	client, server := epochPair(t, "AES-128-GCM", EpochOptions{UsageLimit: 25, FutureKeys: 200})
	const n = 300
	var wg sync.WaitGroup
	direction := func(from, to *EpochChannel, name string) {
		packets, opened := make(chan []byte), make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer close(packets)
			for i := range n {
				p, err := from.Seal(nil, []byte{byte(i & 0xff)})
				if err != nil {
					t.Errorf("%s Seal: %v", name, err)
					return
				}
				packets <- p
				<-opened
			}
		}()
		go func() {
			defer wg.Done()
			for p := range packets {
				if _, err := to.Open(nil, p, epoch); err != nil {
					t.Errorf("%s Open: %v", name, err)
				}
				opened <- struct{}{}
			}
		}()
	}
	direction(client, server, "client to server")
	direction(server, client, "server to client")
	wg.Wait()
	if client.ReceiveEpoch() < 10 || server.ReceiveEpoch() < 10 {
		t.Errorf("the epochs stayed at %d and %d", client.ReceiveEpoch(), server.ReceiveEpoch())
	}
}

func TestChannelInterface(t *testing.T) {
	var _ Channel = (*EpochChannel)(nil)
	for _, hh := range headers {
		a, b := testKey(1), testKey(2)
		c := mustCipher(t, "AES-256-GCM")
		client, err := NewChannel(c, a, b, hh.h, ReceiverOptions{})
		if err != nil {
			t.Fatal(err)
		}
		server, err := NewChannel(c, b, a, hh.h, ReceiverOptions{})
		if err != nil {
			t.Fatal(err)
		}
		packet, err := client.Seal(nil, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		if out, err := server.Open(nil, packet, epoch); err != nil || string(out) != "hello" {
			t.Errorf("%s: %q, %v", hh.name, out, err)
		}
		if client.NeedsRenegotiation() || server.Dropped() != (Drops{}) {
			t.Errorf("%s: renegotiation %v, drops %+v", hh.name, client.NeedsRenegotiation(), server.Dropped())
		}
	}
	if _, err := NewChannel(Cipher{}, testKey(1), testKey(2), Header{}, ReceiverOptions{}); err == nil {
		t.Error("a channel of no cipher")
	}
	if _, err := NewChannel(mustCipher(t, "AES-256-GCM"), testKey(1), testKey(2), Header{KeyID: 9}, ReceiverOptions{}); err == nil {
		t.Error("a channel with a key id that is too big")
	}
}

func BenchmarkEpochSeal(b *testing.B) {
	for _, name := range cipherNames {
		b.Run(name, func(b *testing.B) {
			client, _ := epochPair(b, name, EpochOptions{})
			payload := make([]byte, 1400)
			dst := make([]byte, 0, 2048)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				if _, err := client.Seal(dst[:0], payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEpochOpen(b *testing.B) {
	for _, name := range cipherNames {
		b.Run(name, func(b *testing.B) {
			client, server := epochPair(b, name, EpochOptions{Window: 1 << 16, MaxAge: time.Hour})
			payload := make([]byte, 1400)
			packets := make([][]byte, 1<<15)
			for i := range packets {
				packets[i], _ = client.Seal(nil, payload)
			}
			dst := make([]byte, 0, 2048)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			i := 0
			for b.Loop() {
				if i == len(packets) {
					b.StopTimer()
					client, server = epochPair(b, name, EpochOptions{Window: 1 << 16, MaxAge: time.Hour})
					for j := range packets {
						packets[j], _ = client.Seal(nil, payload)
					}
					i = 0
					b.StartTimer()
				}
				if _, err := server.Open(dst[:0], packets[i], epoch); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}

func FuzzEpochOpen(f *testing.F) {
	client, _ := epochPair(f, "AES-256-GCM", EpochOptions{})
	for _, p := range [][]byte{{1}, []byte("hello"), bytes.Repeat([]byte{9}, 100)} {
		packet, _ := client.Seal(nil, p)
		f.Add(packet, false, false)
		f.Add(packet[:len(packet)/2], true, false)
		forged := bytes.Clone(packet)
		binary.BigEndian.PutUint64(forged[4:], 3<<48|5)
		f.Add(forged, false, true)
	}
	f.Add([]byte(nil), false, false)
	f.Fuzz(func(t *testing.T, packet []byte, chacha, strict bool) {
		name := "AES-256-GCM"
		if chacha {
			name = "CHACHA20-POLY1305"
		}
		_, server := epochPair(t, name, EpochOptions{Strict: strict})
		before := bytes.Clone(packet)
		for range 2 { // the second time, an accepted packet is a replay
			out, err := server.Open([]byte("p"), packet, epoch)
			if err != nil {
				if _, ok := errors.FromError(err); !ok {
					t.Fatalf("error %v is not tagged", err)
				}
				continue
			}
			if len(out) < 1 || out[0] != 'p' {
				t.Fatalf("Open lost the bytes of dst: %q", out)
			}
		}
		if !bytes.Equal(packet, before) {
			t.Fatal("Open changed the packet")
		}
		if got := server.ReceiveEpoch(); got < 1 {
			t.Fatalf("the receive epoch is %d", got)
		}
	})
}

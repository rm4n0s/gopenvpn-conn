// SPDX-License-Identifier: GPL-2.0-only

package datachan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/rm4n0s/errors"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
)

var epoch = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// testKey is a key for the tests (it is not a secret): the bytes count up from seed.
func testKey(seed byte) *keys.DirectionKey {
	var k keys.DirectionKey
	for i := range k.Cipher {
		k.Cipher[i] = seed + byte(i)
		k.HMAC[i] = seed + 100 + byte(i)
	}
	return &k
}

var (
	headers = []struct {
		name string
		h    Header
	}{
		{"DATA_V2", Header{KeyID: 3, HasPeerID: true, PeerID: 0xabcdef}},
		{"DATA_V1", Header{KeyID: 5}},
	}
	cipherNames = []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"}
)

func mustCipher(t testing.TB, name string) Cipher {
	t.Helper()
	c, ok := LookupCipher(name)
	if !ok {
		t.Fatalf("no cipher %s", name)
	}
	return c
}

func pair(t testing.TB, name string, h Header, opts ReceiverOptions) (*Sender, *Receiver) {
	t.Helper()
	c := mustCipher(t, name)
	s, err := NewSender(c, testKey(1), h)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReceiver(c, testKey(1), h, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

func wantTag(t *testing.T, err error, tag, route string) {
	t.Helper()
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not an *errors.Error", err, err)
	}
	if appErr.Tag != tag || !appErr.HasRoute(route) {
		t.Fatalf("error has tag %s and route %s, want tag %s and route %s", appErr.Tag, appErr.Route(), tag, route)
	}
}

func TestLookupCipher(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		keySize int
		ok      bool
	}{
		{"AES-128-GCM", "AES-128-GCM", 16, true},
		{"AES-192-GCM", "AES-192-GCM", 24, true},
		{"AES-256-GCM", "AES-256-GCM", 32, true},
		{"CHACHA20-POLY1305", "CHACHA20-POLY1305", 32, true},
		{"aes-256-gcm", "AES-256-GCM", 32, true},
		{"AES-256-CBC", "", 0, false},
		{"", "", 0, false},
	}
	for _, tt := range tests {
		c, ok := LookupCipher(tt.name)
		if ok != tt.ok || c.Name() != tt.want || c.KeySize() != tt.keySize {
			t.Errorf("LookupCipher(%q) = %q, %d, %v; want %q, %d, %v", tt.name, c.Name(), c.KeySize(), ok, tt.want, tt.keySize, tt.ok)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	sizes := []int{1, 2, 15, 16, 17, 100, 1400, 1500, 9000}
	for _, name := range cipherNames {
		for _, hh := range headers {
			t.Run(name+"/"+hh.name, func(t *testing.T) {
				s, r := pair(t, name, hh.h, ReceiverOptions{})
				now := epoch
				for i, n := range sizes {
					payload := bytes.Repeat([]byte{byte(i + 1)}, n)
					packet, err := s.Seal(nil, payload)
					if err != nil {
						t.Fatal(err)
					}
					if want := hh.h.headerSize() + TagSize + n; len(packet) != want {
						t.Errorf("packet of %d bytes of payload is %d bytes, want %d", n, len(packet), want)
					}
					if packet[0]>>3 != map[bool]byte{true: 9, false: 6}[hh.h.HasPeerID] || packet[0]&7 != hh.h.KeyID {
						t.Errorf("first byte is %#02x", packet[0])
					}
					if hh.h.HasPeerID && uint32(packet[1])<<16|uint32(packet[2])<<8|uint32(packet[3]) != hh.h.PeerID {
						t.Errorf("peer id bytes are % x", packet[1:4])
					}
					if bytes.Contains(packet, payload[:min(n, 16)]) && n >= 16 {
						t.Error("the payload is in the packet in the clear")
					}
					now = now.Add(time.Millisecond)
					got, err := r.Open(nil, packet, now)
					if err != nil {
						t.Fatalf("Open: %v", err)
					}
					if !bytes.Equal(got, payload) {
						t.Errorf("payload of %d bytes came back as %d different bytes", n, len(got))
					}
				}
				if d := r.Dropped(); d != (Drops{}) {
					t.Errorf("dropped %+v", d)
				}
			})
		}
	}
}

// TestPacketBytes builds each packet by hand, from the format in the draft, with
// the standard library and nothing of this package, and compares: the nonce is the
// packet id and then the implicit IV, the additional data is the header of DATA_V2
// or the packet id of DATA_V1, and the tag is before the ciphertext.
func TestPacketBytes(t *testing.T) {
	for _, name := range cipherNames {
		for _, hh := range headers {
			t.Run(name+"/"+hh.name, func(t *testing.T) {
				c := mustCipher(t, name)
				key := testKey(7)
				s, err := NewSender(c, key, hh.h)
				if err != nil {
					t.Fatal(err)
				}
				var aead cipher.AEAD
				if name == "CHACHA20-POLY1305" {
					aead, err = chacha20poly1305.New(key.Cipher[:32])
				} else {
					var block cipher.Block
					block, err = aes.NewCipher(key.Cipher[:c.KeySize()])
					if err == nil {
						aead, err = cipher.NewGCM(block)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				for id := uint32(1); id <= 3; id++ {
					payload := []byte("an IP packet, more or less " + string(rune('a'+id)))
					got, err := s.Seal(nil, payload)
					if err != nil {
						t.Fatal(err)
					}

					peer := binary.BigEndian.AppendUint32(nil, hh.h.PeerID)
					header := append([]byte{9<<3 | hh.h.KeyID}, peer[1:]...)
					if !hh.h.HasPeerID {
						header = []byte{6<<3 | hh.h.KeyID}
					}
					pid := binary.BigEndian.AppendUint32(nil, id)
					ad := append(append([]byte{}, header...), pid...)
					if !hh.h.HasPeerID {
						ad = pid
					}
					nonce := append(append([]byte{}, pid...), key.HMAC[:8]...)
					sealed := aead.Seal(nil, nonce, payload, ad) // ciphertext, then tag
					n := len(payload)
					want := append(append(append([]byte{}, header...), pid...), sealed[n:]...)
					want = append(want, sealed[:n]...)
					if !bytes.Equal(got, want) {
						t.Errorf("packet %d\n got %x\nwant %x", id, got, want)
					}
				}
			})
		}
	}
}

// TestKnownPacket pins the bytes of one packet of each format, which TestPacketBytes
// builds by hand from the draft, so that a change of the format shows. The key is
// testKey(1) and the payload "hello", the first packet.
func TestKnownPacket(t *testing.T) {
	tests := []struct {
		name   string
		h      Header
		packet string
	}{
		{"AES-256-GCM", Header{KeyID: 0, HasPeerID: true, PeerID: 1}, "4800000100000001d8f9ce912a2111293026a31311d63df5f9284812e2"},
		{"CHACHA20-POLY1305", Header{KeyID: 1}, "31000000019fe26c5ecb4fb9e9b0f29fc00745329a6186a2ad24"},
	}
	for _, tt := range tests {
		s, r := pair(t, tt.name, tt.h, ReceiverOptions{})
		got, err := s.Seal(nil, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != tt.packet {
			t.Errorf("%s: packet %x, want %s", tt.name, got, tt.packet)
		}
		want, _ := hex.DecodeString(tt.packet)
		if out, err := r.Open(nil, want, epoch); err != nil || string(out) != "hello" {
			t.Errorf("%s: Open of the pinned packet = %q, %v", tt.name, out, err)
		}
	}
}

func TestSealAndOpenAppend(t *testing.T) {
	s, r := pair(t, "AES-256-GCM", Header{HasPeerID: true, PeerID: 9}, ReceiverOptions{})
	prefix := []byte("prefix")
	packet, err := s.Seal(append([]byte{}, prefix...), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(packet, prefix) {
		t.Fatal("Seal changed the bytes of dst")
	}
	got, err := r.Open([]byte("out:"), packet[len(prefix):], epoch)
	if err != nil || string(got) != "out:payload" {
		t.Errorf("Open = %q, %v", got, err)
	}
}

func TestEveryPacketIDIsNew(t *testing.T) {
	s, _ := pair(t, "AES-128-GCM", Header{}, ReceiverOptions{})
	seen := map[uint32]bool{}
	nonces := map[[12]byte]bool{}
	for want := uint32(1); want <= 5000; want++ {
		packet, err := s.Seal(nil, []byte{1})
		if err != nil {
			t.Fatal(err)
		}
		id := binary.BigEndian.Uint32(packet[1:])
		if id != want || seen[id] {
			t.Fatalf("packet %d has id %d", want, id)
		}
		seen[id] = true
		n := nonceOf(id, s.iv)
		if nonces[n] {
			t.Fatalf("nonce of id %d repeats", id)
		}
		nonces[n] = true
	}
}

func TestPacketIDsEndBeforeTheyWrap(t *testing.T) {
	s, r := pair(t, "AES-256-GCM", Header{}, ReceiverOptions{})
	s.SetNextID(math.MaxUint32 - 2)
	if s.NeedsRenegotiation() != true {
		t.Error("a sender near the end of its ids does not ask for a new key")
	}
	var last uint32
	for range 3 {
		packet, err := s.Seal(nil, []byte{1})
		if err != nil {
			t.Fatal(err)
		}
		last = binary.BigEndian.Uint32(packet[1:])
		if _, err := r.Open(nil, packet, epoch); err != nil {
			t.Fatalf("Open of id %d: %v", last, err)
		}
	}
	if last != math.MaxUint32 {
		t.Fatalf("the last id was %d", last)
	}
	for range 2 {
		out, err := s.Seal([]byte("keep"), []byte{1})
		wantTag(t, err, tagPacketIDExhausted, "Sender.Seal.DataPacketIDExhausted")
		if string(out) != "keep" {
			t.Errorf("Seal returned %q with its error", out)
		}
	}
}

func TestNeedsRenegotiation(t *testing.T) {
	s, _ := pair(t, "AES-256-GCM", Header{}, ReceiverOptions{})
	if s.NeedsRenegotiation() {
		t.Error("a new sender needs a renegotiation")
	}
	s.SetNextID(RenegotiateAt - 1)
	if s.NeedsRenegotiation() {
		t.Error("asked one id too early")
	}
	s.SetNextID(RenegotiateAt)
	if !s.NeedsRenegotiation() {
		t.Error("did not ask at the trigger")
	}
	if _, err := s.Seal(nil, []byte{1}); err != nil {
		t.Errorf("a sender that wants a new key must go on sending until the ids end: %v", err)
	}
}

func TestSealRefusals(t *testing.T) {
	s, _ := pair(t, "AES-256-GCM", Header{}, ReceiverOptions{})
	_, err := s.Seal(nil, nil)
	wantTag(t, err, tagEmptyPayload, "Sender.Seal.DataPayloadEmpty")
	if s.next.Load() != 1 {
		t.Error("a refused payload used a packet id")
	}
}

func TestNewRefusals(t *testing.T) {
	c := mustCipher(t, "AES-256-GCM")
	tests := []struct {
		name  string
		build func() error
		tag   string
		route string
	}{
		{"sender key id", func() error { _, err := NewSender(c, testKey(1), Header{KeyID: 8}); return err }, tagBadHeader, "NewSender->Header.validate.DataHeaderInvalid"},
		{"sender peer id", func() error {
			_, err := NewSender(c, testKey(1), Header{HasPeerID: true, PeerID: 1 << 24})
			return err
		}, tagBadHeader, "NewSender->Header.validate.DataHeaderInvalid"},
		{"sender cipher", func() error { _, err := NewSender(Cipher{}, testKey(1), Header{}); return err }, tagBadCipher, "NewSender->newDirection.DataCipherInvalid"},
		{"receiver key id", func() error { _, err := NewReceiver(c, testKey(1), Header{KeyID: 9}, ReceiverOptions{}); return err }, tagBadHeader, "NewReceiver->Header.validate.DataHeaderInvalid"},
		{"receiver cipher", func() error { _, err := NewReceiver(Cipher{}, testKey(1), Header{}, ReceiverOptions{}); return err }, tagBadCipher, "NewReceiver->newDirection.DataCipherInvalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { wantTag(t, tt.build(), tt.tag, tt.route) })
	}
	// A peer id that is too big is no matter for DATA_V1, which has none.
	if _, err := NewSender(c, testKey(1), Header{PeerID: 1 << 30}); err != nil {
		t.Errorf("a peer id with no DATA_V2: %v", err)
	}
}

func TestOpenRefusals(t *testing.T) {
	for _, hh := range headers {
		t.Run(hh.name, func(t *testing.T) {
			s, r := pair(t, "AES-256-GCM", hh.h, ReceiverOptions{})
			good, err := s.Seal(nil, []byte("payload"))
			if err != nil {
				t.Fatal(err)
			}
			other := Header{KeyID: hh.h.KeyID, HasPeerID: !hh.h.HasPeerID, PeerID: 5}
			so, err := NewSender(mustCipher(t, "AES-256-GCM"), testKey(1), other)
			if err != nil {
				t.Fatal(err)
			}
			otherFormat, err := so.Seal(nil, []byte("payload"))
			if err != nil {
				t.Fatal(err)
			}
			otherKeyID := bytes.Clone(good)
			otherKeyID[0] ^= 1

			tests := []struct {
				name   string
				packet []byte
				tag    string
				route  string
				drops  Drops
			}{
				{"nothing", nil, tagPacketTooShort, "Receiver.Open.DataPacketTooShort", Drops{Short: 1}},
				{"one byte short", good[:hh.h.minPacket()-1], tagPacketTooShort, "Receiver.Open.DataPacketTooShort", Drops{Short: 1}},
				{"the other format", otherFormat, tagWrongFormat, "Receiver.Open.DataPacketWrongFormat", Drops{Format: 1}},
				{"a control packet", append([]byte{4 << 3}, good[1:]...), tagWrongFormat, "Receiver.Open.DataPacketWrongFormat", Drops{Format: 1}},
				{"another key id", otherKeyID, tagWrongKeyID, "Receiver.Open.DataPacketWrongKeyID", Drops{KeyID: 1}},
			}
			for _, tt := range tests {
				_, err := r.Open(nil, tt.packet, epoch)
				wantTag(t, err, tt.tag, tt.route)
				if d := r.Dropped(); d != tt.drops {
					t.Errorf("%s: drops = %+v, want %+v", tt.name, d, tt.drops)
				}
				*r = *rewind(t, r)
			}
			// Nothing of that touched the receiver's state: the good packet still opens.
			if got, err := r.Open(nil, good, epoch); err != nil || string(got) != "payload" {
				t.Errorf("Open(good) = %q, %v", got, err)
			}
		})
	}
}

// rewind returns a receiver like r with the drop counters at zero.
func rewind(t *testing.T, r *Receiver) *Receiver {
	t.Helper()
	n := &Receiver{aead: r.aead, iv: r.iv, header: r.header, window: r.window}
	return n
}

// TestAnyChangedByteIsRefused flips each bit of each byte of a packet, one at a
// time: nothing opens, every flip is counted as a drop, and none of them uses up
// the packet id, so the good packet is still accepted at the end.
func TestAnyChangedByteIsRefused(t *testing.T) {
	for _, name := range cipherNames {
		for _, hh := range headers {
			t.Run(name+"/"+hh.name, func(t *testing.T) {
				s, r := pair(t, name, hh.h, ReceiverOptions{})
				good, err := s.Seal(nil, []byte("some payload that is long enough"))
				if err != nil {
					t.Fatal(err)
				}
				flips := 0
				for i := range good {
					for bit := range 8 {
						bad := bytes.Clone(good)
						bad[i] ^= 1 << bit
						flips++
						if got, err := r.Open(nil, bad, epoch); err == nil {
							t.Fatalf("byte %d bit %d changed and the packet opened as %q", i, bit, got)
						}
					}
				}
				d := r.Dropped()
				if total := d.Short + d.Format + d.KeyID + d.Replay + d.Auth; total != uint64(flips) {
					t.Errorf("%d flips, %d drops (%+v)", flips, total, d)
				}
				if got, err := r.Open(nil, good, epoch); err != nil || string(got) != "some payload that is long enough" {
					t.Errorf("the good packet after the bad ones: %q, %v", got, err)
				}
			})
		}
	}
}

func TestTruncatedAndExtendedPacketsAreRefused(t *testing.T) {
	s, r := pair(t, "AES-256-GCM", Header{HasPeerID: true}, ReceiverOptions{})
	good, err := s.Seal(nil, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	for n := range len(good) {
		if _, err := r.Open(nil, good[:n], epoch); err == nil {
			t.Errorf("a packet cut to %d bytes opened", n)
		}
	}
	if _, err := r.Open(nil, append(bytes.Clone(good), 0), epoch); err == nil {
		t.Error("a packet with an extra byte opened")
	}
}

func TestWrongKeyIsRefused(t *testing.T) {
	c := mustCipher(t, "AES-256-GCM")
	s, err := NewSender(c, testKey(1), Header{})
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]*keys.DirectionKey{
		"another cipher key": testKey(2),
		"another second key": func() *keys.DirectionKey { k := testKey(1); k.HMAC[0] ^= 1; return k }(),
	} {
		r, err := NewReceiver(c, k, Header{}, ReceiverOptions{})
		if err != nil {
			t.Fatal(err)
		}
		packet, err := s.Seal(nil, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.Open(nil, packet, epoch)
		wantTag(t, err, tagAuthFailed, "Receiver.Open.DataPacketAuthFailed")
		if r.Dropped().Auth != 1 {
			t.Errorf("%s: %+v", name, r.Dropped())
		}
	}
	// Another cipher with the same key.
	r, err := NewReceiver(mustCipher(t, "CHACHA20-POLY1305"), testKey(1), Header{}, ReceiverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	packet, _ := s.Seal(nil, []byte("x"))
	if _, err := r.Open(nil, packet, epoch); err == nil {
		t.Error("a packet of another cipher opened")
	}
}

func TestReplayWindow(t *testing.T) {
	s, r := pair(t, "AES-256-GCM", Header{}, ReceiverOptions{Window: 8, MaxAge: 10 * time.Second})
	var packets [][]byte
	for range 20 {
		p, err := s.Seal(nil, []byte{1})
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p)
	}
	open := func(i int, at time.Duration) error {
		_, err := r.Open(nil, packets[i-1], epoch.Add(at))
		return err
	}
	for _, step := range []struct {
		id   int
		at   time.Duration
		pass bool
		what string
	}{
		{1, 0, true, "the first"},
		{1, 0, false, "a repeat"},
		{3, 0, true, "a gap"},
		{2, time.Second, true, "late but in the window and in time"},
		{2, time.Second, false, "a repeat of that"},
		{12, 2 * time.Second, true, "far ahead"},
		{3, 3 * time.Second, false, "now out of the window (12 - 3 >= 8)"},
		{5, 3 * time.Second, true, "12 - 5 = 7, in the window"},
		{4, 3 * time.Second, false, "12 - 4 = 8, out of the window"},
		{7, 3 * time.Second, true, "in the window"},
		{13, 4 * time.Second, true, "next"},
		{6, 20 * time.Second, false, "in the window, but 12 came more than 10 seconds before it"},
		{14, 20 * time.Second, true, "in order is always in time"},
	} {
		err := open(step.id, step.at)
		if (err == nil) != step.pass {
			t.Errorf("packet %d (%s): err = %v, want pass = %v", step.id, step.what, err, step.pass)
		}
		if err != nil {
			wantTag(t, err, tagReplayed, "Receiver.Open.DataPacketReplayed")
		}
	}
	if r.Dropped().Replay != 5 {
		t.Errorf("replay drops = %d, want 5", r.Dropped().Replay)
	}
	if r.Dropped().Auth != 0 {
		t.Errorf("auth drops = %d, want 0", r.Dropped().Auth)
	}
}

func TestDefaultReplayWindow(t *testing.T) {
	s, r := pair(t, "AES-128-GCM", Header{}, ReceiverOptions{})
	var packets [][]byte
	for range 200 {
		p, _ := s.Seal(nil, []byte{1})
		packets = append(packets, p)
	}
	if _, err := r.Open(nil, packets[99], epoch); err != nil { // id 100
		t.Fatal(err)
	}
	if _, err := r.Open(nil, packets[100-65], epoch); err == nil { // id 36: 100 - 36 = 64
		t.Error("an id 64 below the highest was accepted; the window is 64 packets")
	}
	if _, err := r.Open(nil, packets[100-64], epoch); err != nil { // id 37
		t.Errorf("an id 63 below the highest was refused: %v", err)
	}
	if _, err := r.Open(nil, packets[101], epoch.Add(16*time.Second)); err != nil { // id 102
		t.Fatal(err)
	}
	if _, err := r.Open(nil, packets[100], epoch.Add(33*time.Second)); err == nil { // id 101, more than 15 s after 102
		t.Error("an id that came more than 15 seconds after a higher one was accepted")
	}
}

// A forged packet that carries a high id leaves no trace in the replay window.
func TestForgedPacketIDsAreNotRemembered(t *testing.T) {
	s, r := pair(t, "AES-256-GCM", Header{}, ReceiverOptions{})
	first, _ := s.Seal(nil, []byte{1})
	forged := bytes.Clone(first)
	binary.BigEndian.PutUint32(forged[1:], 1_000_000) // a huge id, with the tag of id 1
	if _, err := r.Open(nil, forged, epoch); err == nil {
		t.Fatal("a forged packet opened")
	}
	if _, err := r.Open(nil, first, epoch); err != nil {
		t.Errorf("the real packet 1 after a forged one with a big id: %v", err)
	}
}

func TestOpenDoesNotChangeThePacket(t *testing.T) {
	s, r := pair(t, "AES-256-GCM", Header{HasPeerID: true}, ReceiverOptions{})
	packet, _ := s.Seal(nil, []byte("payload payload"))
	before := bytes.Clone(packet)
	if _, err := r.Open(nil, packet, epoch); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, before) {
		t.Error("Open changed the packet")
	}
}

func TestAllocations(t *testing.T) {
	for _, name := range cipherNames {
		for _, hh := range headers {
			s, r := pair(t, name, hh.h, ReceiverOptions{Window: 1 << 16, MaxAge: time.Hour})
			payload := bytes.Repeat([]byte{7}, 1400)
			sealed := make([]byte, 0, 2048)
			opened := make([]byte, 0, 2048)
			packet, _ := s.Seal(nil, payload)
			if _, err := r.Open(opened[:0], packet, epoch); err != nil { // sizes the scratch buffer
				t.Fatal(err)
			}
			if got := testing.AllocsPerRun(100, func() {
				if _, err := s.Seal(sealed[:0], payload); err != nil {
					t.Fatal(err)
				}
			}); got != 0 {
				t.Errorf("%s/%s: Seal allocates %v times per packet, want 0", name, hh.name, got)
			}
			packets := make([][]byte, 101)
			for i := range packets {
				packets[i], _ = s.Seal(nil, payload)
			}
			i := 0
			if got := testing.AllocsPerRun(100, func() {
				if _, err := r.Open(opened[:0], packets[i], epoch); err != nil {
					t.Fatal(err)
				}
				i++
			}); got != 0 {
				t.Errorf("%s/%s: Open allocates %v times per packet, want 0", name, hh.name, got)
			}
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, name := range cipherNames {
		b.Run(name, func(b *testing.B) {
			s, _ := pair(b, name, Header{HasPeerID: true, PeerID: 1}, ReceiverOptions{})
			payload := make([]byte, 1400)
			dst := make([]byte, 0, 2048)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				if _, err := s.Seal(dst[:0], payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, name := range cipherNames {
		b.Run(name, func(b *testing.B) {
			s, r := pair(b, name, Header{HasPeerID: true, PeerID: 1}, ReceiverOptions{Window: 1 << 16, MaxAge: time.Hour})
			payload := make([]byte, 1400)
			// A window as big as the number of packets lets each be opened once.
			packets := make([][]byte, 1<<15)
			for i := range packets {
				packets[i], _ = s.Seal(nil, payload)
			}
			dst := make([]byte, 0, 2048)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			i := 0
			for b.Loop() {
				if i == len(packets) {
					b.StopTimer()
					s, r = pair(b, name, Header{HasPeerID: true, PeerID: 1}, ReceiverOptions{Window: 1 << 16, MaxAge: time.Hour})
					for j := range packets {
						packets[j], _ = s.Seal(nil, payload)
					}
					i = 0
					b.StartTimer()
				}
				if _, err := r.Open(dst[:0], packets[i], epoch); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}

func FuzzOpen(f *testing.F) {
	for _, hh := range headers {
		for _, name := range []string{"AES-256-GCM", "CHACHA20-POLY1305"} {
			s, _ := pair(f, name, hh.h, ReceiverOptions{})
			for _, p := range [][]byte{{1}, []byte("hello"), bytes.Repeat([]byte{9}, 100)} {
				packet, _ := s.Seal(nil, p)
				f.Add(packet, hh.h.HasPeerID, name == "CHACHA20-POLY1305")
				f.Add(packet[:len(packet)/2], hh.h.HasPeerID, name == "CHACHA20-POLY1305")
			}
		}
	}
	f.Add([]byte(nil), true, false)
	f.Fuzz(func(t *testing.T, packet []byte, v2, chacha bool) {
		name := "AES-256-GCM"
		if chacha {
			name = "CHACHA20-POLY1305"
		}
		h := Header{KeyID: 3, HasPeerID: v2, PeerID: 0xabcdef}
		_, r := pair(t, name, h, ReceiverOptions{})
		before := bytes.Clone(packet)
		for range 2 { // the second time, an accepted packet is a replay
			out, err := r.Open([]byte("p"), packet, epoch)
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
	})
}

// A key of the wrong length is refused by the cipher constructors; NewSender and
// NewReceiver cut the key to the right length first, so only a direct call reaches
// this.
func TestCipherConstructorsRefuseABadKey(t *testing.T) {
	_, err := newGCM(make([]byte, 5))
	wantTag(t, err, tagCipherInit, "newGCM.DataCipherInitFailed")
	_, err = newChaCha(make([]byte, 5))
	wantTag(t, err, tagCipherInit, "newChaCha.DataCipherInitFailed")
}

// TestOverhead: Overhead is what a sealed packet is longer than its payload, in
// each format; the MSS clamp of the session depends on it (SPEC §10).
func TestOverhead(t *testing.T) {
	payload := make([]byte, 1400)
	for _, hh := range headers {
		s, _ := pair(t, "AES-256-GCM", hh.h, ReceiverOptions{})
		packet, err := s.Seal(nil, payload)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(packet) - len(payload); Overhead(hh.h, false) != got {
			t.Errorf("%s: Overhead = %d, a packet adds %d", hh.name, Overhead(hh.h, false), got)
		}
	}
	client, _ := epochPair(t, "AES-256-GCM", EpochOptions{})
	packet, err := client.Seal(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(packet) - len(payload); Overhead(epochHeader, true) != got {
		t.Errorf("epoch: Overhead = %d, a packet adds %d", Overhead(epochHeader, true), got)
	}
}

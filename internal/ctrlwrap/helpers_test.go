// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"sync"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// testKey is a static key whose bytes are easy to tell apart: byte i is seed+i.
func testKey(seed byte) *keys.StaticKey {
	var k keys.StaticKey
	b := seed
	for i := range k {
		k[i] = b
		b++
	}
	return &k
}

// clock is a clock that the test moves.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

// clockStart is where a clock starts: a constant, so that it converts to the
// 32-bit time of a packet with no doubt about its range.
const clockStart = 1_700_000_000

func newClock() *clock { return &clock{t: time.Unix(clockStart, 0)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// hashes are the digests that --auth can name and that fit a static key.
var hashes = []struct {
	name string
	new  func() hash.Hash
	size int
}{
	{"SHA1", sha1.New, 20},
	{"SHA256", sha256.New, 32},
	{"SHA384", sha512.New384, 48},
	{"SHA512", sha512.New, 64},
}

var testSID = wire.SessionID{1, 2, 3, 4, 5, 6, 7, 8}

// newPair makes the wrappers of the two ends of one tls-auth connection: a
// client (keys.Inverse) and a server (keys.Normal), on the same clock.
func newPair(t testing.TB, newHash func() hash.Hash, clk *clock) (client, server Wrapper) {
	t.Helper()
	key := testKey(0x20)
	client, err := NewTLSAuth(key, keys.Inverse, newHash, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewTLSAuth(key, keys.Normal, newHash, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

// controlBody is the body of a control packet with the given packet id and
// payload, as wire makes it.
func controlBody(t testing.TB, packetID uint32, payload []byte) []byte {
	t.Helper()
	body, err := wire.AppendControlBody(nil, &wire.Control{Opcode: wire.ControlV1, PacketID: packetID, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// newCryptPair makes the wrappers of the two ends of one tls-crypt connection.
func newCryptPair(t testing.TB, clk *clock) (client, server Wrapper) {
	t.Helper()
	key := testKey(0x50)
	client, err := NewTLSCrypt(key, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewTLSCryptServer(key, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

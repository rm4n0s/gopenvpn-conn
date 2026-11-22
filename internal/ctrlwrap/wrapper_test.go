// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

func TestPlain(t *testing.T) {
	w := NewPlain()
	first := wire.FirstByte(wire.ControlV1, 3)
	for _, body := range [][]byte{nil, {1}, bytes.Repeat([]byte{7}, 1200)} {
		packet, err := w.Wrap([]byte("dst"), first, testSID, body)
		if err != nil {
			t.Fatal(err)
		}
		want := append(append([]byte("dst"), first), testSID[:]...)
		want = append(want, body...)
		if !bytes.Equal(packet, want) {
			t.Errorf("Wrap = %x, want %x", packet, want)
		}
		got, err := w.Unwrap(packet[len("dst"):])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("Unwrap = %x, want %x", got, body)
		}
	}
	if w.Overhead() != 0 {
		t.Errorf("Overhead = %d, want 0", w.Overhead())
	}
}

func TestPlainTooShort(t *testing.T) {
	for n := 0; n < headerSize; n++ {
		_, err := NewPlain().Unwrap(make([]byte, n))
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("%d bytes: expected *errors.Error, got %T: %v", n, err, err)
		}
		if !appErr.HasRoute("plain.Unwrap.PlainTooShort") {
			t.Errorf("%d bytes: unexpected failure path: %s", n, appErr.Route())
		}
		if appErr.Metadata["got"] != n || appErr.Metadata["want"] != headerSize {
			t.Errorf("%d bytes: metadata = %v", n, appErr.Metadata)
		}
	}
	// A packet with just the header has an empty body.
	body, err := NewPlain().Unwrap(make([]byte, headerSize))
	if err != nil || len(body) != 0 {
		t.Errorf("header only: %x, %v", body, err)
	}
}

func TestDynamicWrapper(t *testing.T) {
	var original, exported keys.StaticKey
	for i := range original {
		original[i] = byte(i)
		exported[i] = byte(i * 7 & 0xff)
	}
	now := func() time.Time { return time.Unix(1_700_000_000, 0) }

	client, err := NewDynamic(exported[:], &original, false, now)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewDynamic(exported[:], &original, true, now)
	if err != nil {
		t.Fatal(err)
	}
	var sid wire.SessionID
	body := []byte("the body of a control packet")
	for _, dir := range []struct{ from, to Wrapper }{{client, server}, {server, client}} {
		packet, err := dir.from.Wrap(nil, 4<<3|1, sid, body)
		if err != nil {
			t.Fatal(err)
		}
		got, err := dir.to.Unwrap(packet)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("Unwrap = %q, %v", got, err)
		}
		if bytes.Contains(packet, body) {
			t.Error("the body is in the packet in the clear: dynamic tls-crypt encrypts")
		}
	}
	// The XOR is part of the key: without the original key the wrappers do not agree.
	other, err := NewDynamic(exported[:], nil, true, now)
	if err != nil {
		t.Fatal(err)
	}
	packet, _ := client.Wrap(nil, 4<<3|1, sid, body)
	if _, err := other.Unwrap(packet); err == nil {
		t.Error("a wrapper without the original key opened a packet")
	}
	// A key that is the original XORed with itself is the exported one alone.
	zero, err := NewDynamic(exported[:], &exported, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zero.Unwrap(packet); err == nil {
		t.Error("the exported key XORed with itself opened a packet")
	}
	_, err = NewDynamic(exported[:255], nil, false, now)
	if appErr, ok := errors.FromError(err); !ok || appErr.Tag != tagDynamicKeySize || !appErr.HasRoute("NewDynamic.DynamicTLSCryptKeySize") {
		t.Errorf("NewDynamic with 255 bytes = %v", err)
	}
}

func TestStaticKeyOfTheWrappers(t *testing.T) {
	var k keys.StaticKey
	for i := range k {
		k[i] = byte(i + 1)
	}
	auth, err := NewTLSAuth(&k, keys.Inverse, sha256.New, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	crypt, err := NewTLSCrypt(&k, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for name, w := range map[string]Wrapper{"tls-auth": auth, "tls-crypt": crypt} {
		sk, ok := w.(StaticKeyed)
		if !ok || *sk.StaticKey() != k {
			t.Errorf("%s: no static key, or another one", name)
		}
		got := sk.StaticKey()
		got[0] ^= 0xff
		if sk.StaticKey()[0] == got[0] {
			t.Errorf("%s: StaticKey gave the wrapper's own array", name)
		}
	}
	if _, ok := NewPlain().(StaticKeyed); ok {
		t.Error("no protection has a key")
	}
}

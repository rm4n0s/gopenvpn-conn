// SPDX-License-Identifier: GPL-2.0-only

package keys

import (
	"bytes"
	"testing"

	"github.com/rm4n0s/errors"
)

func TestSplitDataKeys(t *testing.T) {
	material := make([]byte, DataKeysSize)
	for i := range material {
		material[i] = byte(i)
	}
	k, err := SplitDataKeys(material)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		got  []byte
		from int
	}{
		{"client to server, cipher key", k.ClientToServer.Cipher[:], 0},
		{"client to server, second key", k.ClientToServer.HMAC[:], 64},
		{"server to client, cipher key", k.ServerToClient.Cipher[:], 128},
		{"server to client, second key", k.ServerToClient.HMAC[:], 192},
	}
	for _, tt := range tests {
		if !bytes.Equal(tt.got, material[tt.from:tt.from+64]) {
			t.Errorf("%s is not bytes %d to %d of the material", tt.name, tt.from, tt.from+64)
		}
	}
	// A copy: the caller may clear the material.
	clear(material)
	if k.ServerToClient.HMAC[63] != 255 {
		t.Error("the keys point into the material")
	}
	k.Clear()
	if *k != (DataKeys{}) {
		t.Error("Clear left key bytes")
	}
}

func TestSplitDataKeysWrongSize(t *testing.T) {
	for _, n := range []int{0, 1, 255, 257, 512} {
		_, err := SplitDataKeys(make([]byte, n))
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != tagBadDataKeys || !appErr.HasRoute("SplitDataKeys.BadDataKeys") {
			t.Errorf("SplitDataKeys(%d bytes) = %v, want %s", n, err, tagBadDataKeys)
		}
	}
}

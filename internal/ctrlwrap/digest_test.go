// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"crypto"
	"testing"

	"github.com/rm4n0s/errors"
)

func TestHashFor(t *testing.T) {
	tests := []struct {
		hash crypto.Hash
		size int
	}{
		{crypto.SHA1, 20}, {crypto.SHA256, 32}, {crypto.SHA384, 48}, {crypto.SHA512, 64},
	}
	for _, tt := range tests {
		t.Run(tt.hash.String(), func(t *testing.T) {
			newHash, err := HashFor(tt.hash)
			if err != nil {
				t.Fatal(err)
			}
			if got := newHash().Size(); got != tt.size {
				t.Errorf("size = %d, want %d", got, tt.size)
			}
		})
	}
}

func TestHashForRefusesOtherDigests(t *testing.T) {
	for _, h := range []crypto.Hash{0, crypto.MD5, crypto.SHA224, crypto.SHA3_256, crypto.BLAKE2b_512, crypto.Hash(999)} {
		newHash, err := HashFor(h)
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("%v: expected *errors.Error, got %T: %v", h, err, err)
		}
		if !appErr.HasRoute("HashFor.UnsupportedDigest") {
			t.Errorf("unexpected failure path: %s", appErr.Route())
		}
		if newHash != nil {
			t.Errorf("%v: a constructor came with the error", h)
		}
	}
}

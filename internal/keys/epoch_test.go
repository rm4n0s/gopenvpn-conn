// SPDX-License-Identifier: GPL-2.0-only

package keys

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/rm4n0s/errors"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The secret of OpenVPN's test_crypto.c for the labels.
const katPRK = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

// TestExpandLabelKnownAnswer: the vector of crypto_test_ovpn_label_expand in
// OpenVPN's tests, and the one of crypto_test_hkdf_expand_test_ovpn, which is the
// same computation with the info written out: 001b 0e "ovpn unit test" 00.
func TestExpandLabelKnownAnswer(t *testing.T) {
	secret := unhex(t, katPRK)
	got, err := ExpandLabel(secret, "unit test", nil, 16)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "185eaa1c7f228ab8eb29773214d92046"); !bytes.Equal(got, want) {
		t.Errorf("ExpandLabel = %x, want %x", got, want)
	}
	got, err = ExpandLabel(secret, "unit test", nil, 27)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "875a8eec18556380b8d933ed323c2df8e8eccf4972e683f06a83ac"); !bytes.Equal(got, want) {
		t.Errorf("ExpandLabel(27) = %x, want %x", got, want)
	}
	// The info that OpenVPN's test spells out is the info that ExpandLabel builds.
	info := string(unhex(t, "001b0e6f76706e20756e69742074657374"+"00"))
	direct, err := hkdf.Expand(sha256.New, secret, info, 27)
	if err != nil || !bytes.Equal(direct, got) {
		t.Errorf("HKDF with the info of the test = %x, %v", direct, err)
	}
}

// TestHKDFExpandVectors runs the vectors of RFC 5869 appendix A.1 to A.3 that
// OpenVPN's tests use (with SHA-256) through the standard library function that
// ExpandLabel stands on.
func TestHKDFExpandVectors(t *testing.T) {
	tests := []struct {
		name, prk, info, okm string
		length               int
	}{
		{"A.1", "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "f0f1f2f3f4f5f6f7f8f9",
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42},
		{"A.3", "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", "",
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", 42},
	}
	for _, tt := range tests {
		got, err := hkdf.Expand(sha256.New, unhex(t, tt.prk), string(unhex(t, tt.info)), tt.length)
		if err != nil || !bytes.Equal(got, unhex(t, tt.okm)) {
			t.Errorf("%s: %x, %v", tt.name, got, err)
		}
	}
}

// TestDataKeyKnownAnswer: epoch_test_derive_data_key of OpenVPN's tests: epoch 17
// with the secret 13 0c 00 00 ... and AES-192-GCM (a key of 24 bytes and an IV of 12).
func TestDataKeyKnownAnswer(t *testing.T) {
	e := EpochKey{Epoch: 17}
	e.Secret[0], e.Secret[1] = 19, 12
	key, iv, err := e.DataKey(24, 12)
	if err != nil {
		t.Fatal(err)
	}
	wantKey := unhex(t, "ed8533db1c28ace418e9006ab29c17417d60ebe6cd90bf0a")
	wantIV := unhex(t, "86890aabf032cb59f4cfa34e")
	if !bytes.Equal(key, wantKey) || !bytes.Equal(iv, wantIV) {
		t.Errorf("key %x, iv %x\nwant %x, %x", key, iv, wantKey, wantIV)
	}
}

func TestFirstEpochKey(t *testing.T) {
	var k DirectionKey
	for i := range k.Cipher {
		k.Cipher[i] = byte(i)
		k.HMAC[i] = 0xee
	}
	e := FirstEpochKey(&k)
	if e.Epoch != 1 || !bytes.Equal(e.Secret[:], k.Cipher[:32]) {
		t.Errorf("FirstEpochKey = %d, %x: not the first 32 bytes of the cipher key", e.Epoch, e.Secret)
	}
}

func TestNextEpochKey(t *testing.T) {
	e := EpochKey{Epoch: 1}
	copy(e.Secret[:], unhex(t, katPRK))
	n, err := e.Next()
	if err != nil {
		t.Fatal(err)
	}
	want, err := ExpandLabel(e.Secret[:], "datakey upd", nil, 32)
	if err != nil || n.Epoch != 2 || !bytes.Equal(n.Secret[:], want) {
		t.Errorf("Next = %d %x, want 2 %x (%v)", n.Epoch, n.Secret, want, err)
	}
	// Each epoch is a different key.
	seen := map[[32]byte]bool{e.Secret: true}
	k := e
	for range 300 {
		if k, err = k.Next(); err != nil {
			t.Fatal(err)
		}
		if seen[k.Secret] {
			t.Fatalf("the secret of epoch %d was seen before", k.Epoch)
		}
		seen[k.Secret] = true
	}
	k.Clear()
	if k != (EpochKey{}) {
		t.Error("Clear left bytes")
	}
}

func TestNoEpochAfterTheLast(t *testing.T) {
	_, err := EpochKey{Epoch: MaxEpoch}.Next()
	wantTag(t, err, tagNoNextEpoch, "EpochKey.Next.NoNextEpoch")
	if _, err := (EpochKey{Epoch: MaxEpoch - 1}).Next(); err != nil {
		t.Errorf("the last epoch is reachable: %v", err)
	}
}

func TestExpandLabelRefusals(t *testing.T) {
	secret := make([]byte, 32)
	tests := []struct {
		name    string
		secret  []byte
		label   string
		context []byte
		length  int
		tag     string
		route   string
	}{
		{"a short secret", secret[:31], "x", nil, 16, tagExpandLabelArgs, "ExpandLabel.ExpandLabelArgumentsInvalid"},
		{"a long secret", make([]byte, 33), "x", nil, 16, tagExpandLabelArgs, "ExpandLabel.ExpandLabelArgumentsInvalid"},
		{"no label", secret, "", nil, 16, tagExpandLabelArgs, "ExpandLabel.ExpandLabelArgumentsInvalid"},
		{"a long label", secret, string(make([]byte, 251)), nil, 16, tagExpandLabelArgs, "ExpandLabel.ExpandLabelArgumentsInvalid"},
		{"a long context", secret, "x", make([]byte, 256), 16, tagExpandLabelArgs, "ExpandLabel.ExpandLabelArgumentsInvalid"},
		{"a negative length", secret, "x", nil, -1, tagExpandLabelArgs, "ExpandLabel.ExpandLabelArgumentsInvalid"},
		{"a length that does not fit 16 bits", secret, "x", nil, 0x10000, tagExpandLabelArgs, "ExpandLabel.ExpandLabelArgumentsInvalid"},
		{"more than HKDF gives", secret, "x", nil, 255*32 + 1, tagExpandLabelFailed, "ExpandLabel.ExpandLabelFailed"},
	}
	for _, tt := range tests {
		_, err := ExpandLabel(tt.secret, tt.label, tt.context, tt.length)
		t.Run(tt.name, func(t *testing.T) { wantTag(t, err, tt.tag, tt.route) })
	}
	// The edges that are allowed.
	for _, ok := range []struct {
		label   string
		context []byte
		length  int
	}{{"x", nil, 0}, {string(make([]byte, 250)), nil, 1}, {"x", make([]byte, 255), 32}, {"x", nil, 255 * 32}} {
		if _, err := ExpandLabel(secret, ok.label, ok.context, ok.length); err != nil {
			t.Errorf("ExpandLabel(%d label bytes, %d context bytes, %d): %v", len(ok.label), len(ok.context), ok.length, err)
		}
	}
}

// The context is part of the info: a different context gives different bytes, and
// the label is too.
func TestExpandLabelDependsOnItsInputs(t *testing.T) {
	secret := unhex(t, katPRK)
	a, _ := ExpandLabel(secret, "data_key", nil, 32)
	b, _ := ExpandLabel(secret, "data_iv", nil, 32)
	c, _ := ExpandLabel(secret, "data_key", []byte{1}, 32)
	d, _ := ExpandLabel(secret, "data_key", nil, 31)
	if bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(a[:31], d) {
		t.Error("two derivations that differ in label, context or length gave the same bytes")
	}
}

func wantTag(t *testing.T, err error, tag, route string) {
	t.Helper()
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("error %v is not an *errors.Error", err)
	}
	if appErr.Tag != tag || !appErr.HasRoute(route) {
		t.Fatalf("tag %s and route %s, want tag %s and route %s", appErr.Tag, appErr.Route(), tag, route)
	}
}

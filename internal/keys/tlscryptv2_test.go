// SPDX-License-Identifier: GPL-2.0-only

package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/rm4n0s/errors"
)

func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join("testdata", name)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// pemKey makes a client key file from the data of the PEM block.
func pemKey(data []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: tlsCryptV2ClientKeyType, Bytes: data}))
}

// wkcOf makes a wrapped client key of n bytes whose last 2 bytes are its length.
func wkcOf(n uint16) []byte {
	wkc := bytes.Repeat([]byte{0xaa}, int(n))
	binary.BigEndian.PutUint16(wkc[n-2:], n)
	return wkc
}

func TestParseTLSCryptV2ClientKey(t *testing.T) {
	tests := []struct {
		file    string
		wkcSize int
	}{
		{"tls-crypt-v2-client.key", 299},          // metadata: a timestamp
		{"tls-crypt-v2-client-metadata.key", 297}, // custom metadata
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			key, err := ParseTLSCryptV2ClientKey(bytes.NewReader(readTestdata(t, tt.file)))
			if err != nil {
				t.Fatal(err)
			}
			// OpenVPN's test makes Kc from the bytes 0, 1, 2, ..., 255.
			var want StaticKey
			var b byte
			for i := range want {
				want[i] = b
				b++
			}
			if key.Kc != want {
				t.Error("Kc is not the first 256 bytes of the key")
			}
			if len(key.WKc) != tt.wkcSize {
				t.Errorf("WKc is %d bytes, want %d", len(key.WKc), tt.wkcSize)
			}
			if got := int(binary.BigEndian.Uint16(key.WKc[len(key.WKc)-2:])); got != len(key.WKc) {
				t.Errorf("the length at the end of WKc is %d, its length is %d", got, len(key.WKc))
			}
		})
	}
}

// TestWKcIsWhatTheServerKeyUnwraps unwraps the WKc of the test key with the
// test server key, as the draft says a server does (SIV: the IV is the tag,
// the tag covers the length and the plaintext), with crypto/aes and crypto/hmac.
// The plaintext starts with Kc: this shows that the split of the client key
// into Kc and WKc is where OpenVPN puts it.
func TestWKcIsWhatTheServerKeyUnwraps(t *testing.T) {
	var serverKey bytes.Buffer
	for _, line := range strings.Split(string(readTestdata(t, "tls-crypt-v2-server.key")), "\n") {
		serverKey.WriteString(line + "\n")
	}
	block, _ := pem.Decode(serverKey.Bytes())
	if block == nil || len(block.Bytes) != 128 {
		t.Fatalf("the server key is not one PEM block of 128 bytes")
	}
	// The server key is two 64-byte keys: Ke is the first 32 bytes of the
	// first and Ka the first 32 bytes of the second.
	ke, ka := block.Bytes[:32], block.Bytes[64:96]

	for _, file := range []string{"tls-crypt-v2-client.key", "tls-crypt-v2-client-metadata.key"} {
		t.Run(file, func(t *testing.T) {
			key, err := ParseTLSCryptV2ClientKey(bytes.NewReader(readTestdata(t, file)))
			if err != nil {
				t.Fatal(err)
			}
			wkc := key.WKc
			tag, ciphertext, length := wkc[:32], wkc[32:len(wkc)-2], wkc[len(wkc)-2:]
			aesBlock, err := aes.NewCipher(ke)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := make([]byte, len(ciphertext))
			cipher.NewCTR(aesBlock, tag[:16]).XORKeyStream(plaintext, ciphertext)

			mac := hmac.New(sha256.New, ka)
			mac.Write(length)
			mac.Write(plaintext)
			if !hmac.Equal(tag, mac.Sum(nil)) {
				t.Fatal("the tag of WKc does not check with the server key")
			}
			if len(plaintext) < StaticKeySize || !bytes.Equal(plaintext[:StaticKeySize], key.Kc[:]) {
				t.Error("the plaintext of WKc does not start with Kc")
			}
			if len(plaintext) == StaticKeySize {
				t.Error("WKc has no metadata")
			}
		})
	}
}

func TestParseTLSCryptV2ClientKeyFormats(t *testing.T) {
	good := readTestdata(t, "tls-crypt-v2-client.key")
	want, err := ParseTLSCryptV2ClientKey(bytes.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		file string
	}{
		{"as the genkey makes it, with text before", "some text\n" + string(good) + "and after\n"},
		{"windows line ends", strings.ReplaceAll(string(good), "\n", "\r\n")},
		{"another PEM block first", pemBlock("CERTIFICATE", []byte("not a key")) + string(good)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTLSCryptV2ClientKey(strings.NewReader(tt.file))
			if err != nil {
				t.Fatal(err)
			}
			if got.Kc != want.Kc || !bytes.Equal(got.WKc, want.WKc) {
				t.Error("the key differs")
			}
		})
	}
}

func pemBlock(typ string, data []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: data}))
}

func TestParseTLSCryptV2ClientKeyFailures(t *testing.T) {
	kc := bytes.Repeat([]byte{1}, StaticKeySize)
	tests := []struct {
		name  string
		file  string
		route string
		meta  map[string]any
	}{
		{"empty", "", "ParseTLSCryptV2ClientKey.TLSCryptV2KeyNotFound", nil},
		{"not PEM", "just text", "ParseTLSCryptV2ClientKey.TLSCryptV2KeyNotFound", nil},
		{"another kind of key", pemBlock("OpenVPN tls-crypt-v2 server key", append(kc, wkcOf(40)...)), "ParseTLSCryptV2ClientKey.TLSCryptV2KeyNotFound", nil},
		{"a static key is not a client key", string(readTestdata(t, "ta.key")), "ParseTLSCryptV2ClientKey.TLSCryptV2KeyNotFound", nil},
		{"broken base64", "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n!!!!\n-----END OpenVPN tls-crypt-v2 client key-----\n", "ParseTLSCryptV2ClientKey.TLSCryptV2KeyNotFound", nil},
		{"nothing after Kc", pemKey(kc), "ParseTLSCryptV2ClientKey.TLSCryptV2KeyTooShort", map[string]any{"got": 256, "want_at_least": 258}},
		{"one byte after Kc", pemKey(append(bytes.Clone(kc), 7)), "ParseTLSCryptV2ClientKey.TLSCryptV2KeyTooShort", nil},
		{"shorter than Kc", pemKey(kc[:100]), "ParseTLSCryptV2ClientKey.TLSCryptV2KeyTooShort", map[string]any{"got": 100}},
		{"the wrapped key says another length", pemKey(append(bytes.Clone(kc), 0, 0, 0, 40)), "ParseTLSCryptV2ClientKey.TLSCryptV2BadWKc", map[string]any{"length": 4, "declared": 40}},
		{"the wrapped key is cut", pemKey(append(bytes.Clone(kc), wkcOf(299)[:290]...)), "ParseTLSCryptV2ClientKey.TLSCryptV2BadWKc", nil},
		{"the wrapped key is larger than 1024", pemKey(append(bytes.Clone(kc), wkcOf(1025)...)), "ParseTLSCryptV2ClientKey.TLSCryptV2BadWKc", map[string]any{"length": 1025, "max": 1024}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTLSCryptV2ClientKey(strings.NewReader(tt.file))
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute(tt.route) {
				t.Errorf("unexpected failure path: %s, want %s", appErr.Route(), tt.route)
			}
			for k, v := range tt.meta {
				if appErr.Metadata[k] != v {
					t.Errorf("metadata %q = %v (%T), want %v (%T)", k, appErr.Metadata[k], appErr.Metadata[k], v, v)
				}
			}
			// No key bytes in the error.
			if text := fmt.Sprintf("%v|%+v|%s", appErr, appErr.Metadata, appErr.StackTrace()); strings.Contains(text, "AQEBAQEB") {
				t.Errorf("the error shows key material: %s", text)
			}
		})
	}
}

func TestParseTLSCryptV2ClientKeyLimits(t *testing.T) {
	kc := bytes.Repeat([]byte{1}, StaticKeySize)
	// The smallest and the largest wrapped key that are accepted.
	for _, n := range []uint16{2, 40, 299, MaxWKcSize} {
		key, err := ParseTLSCryptV2ClientKey(strings.NewReader(pemKey(append(bytes.Clone(kc), wkcOf(n)...))))
		if err != nil {
			t.Errorf("a wrapped key of %d bytes: %v", n, err)
			continue
		}
		if len(key.WKc) != int(n) {
			t.Errorf("WKc is %d bytes, want %d", len(key.WKc), n)
		}
	}
}

func TestParseTLSCryptV2ClientKeyReadFailures(t *testing.T) {
	_, err := ParseTLSCryptV2ClientKey(iotest.ErrReader(io.ErrClosedPipe))
	appErr, ok := errors.FromError(err)
	if !ok || !appErr.HasRoute("ParseTLSCryptV2ClientKey.TLSCryptV2KeyReadFailed") || !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("read failure: %v", err)
	}
	r := &countingReader{}
	_, err = ParseTLSCryptV2ClientKey(r)
	appErr, ok = errors.FromError(err)
	if !ok || !appErr.HasRoute("ParseTLSCryptV2ClientKey.TLSCryptV2KeyTooLarge") {
		t.Errorf("an endless reader: %v", err)
	}
	if r.n > 2*maxTLSCryptV2KeyFile {
		t.Errorf("read %d bytes of an endless reader", r.n)
	}
}

func TestParseTLSCryptV2ClientKeyKeepsItsOwnCopy(t *testing.T) {
	// The key does not point into a buffer that the caller may reuse.
	file := []byte(readTestdata(t, "tls-crypt-v2-client.key"))
	key, err := ParseTLSCryptV2ClientKey(bytes.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(key.WKc)
	for i := range file {
		file[i] = 0
	}
	if !bytes.Equal(before, key.WKc) {
		t.Error("WKc changed with the input")
	}
}

func FuzzParseTLSCryptV2ClientKey(f *testing.F) {
	f.Add(readTestdata(f, "tls-crypt-v2-client.key"))
	f.Add(readTestdata(f, "tls-crypt-v2-client-metadata.key"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := ParseTLSCryptV2ClientKey(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(key.WKc) < minWKcSize || len(key.WKc) > MaxWKcSize {
			t.Fatalf("WKc is %d bytes", len(key.WKc))
		}
		// A key that was read is the key that was written.
		again, err := ParseTLSCryptV2ClientKey(strings.NewReader(pemKey(append(bytes.Clone(key.Kc[:]), key.WKc...))))
		if err != nil {
			t.Fatalf("a key that was read cannot be written and read again: %v", err)
		}
		if again.Kc != key.Kc || !bytes.Equal(again.WKc, key.WKc) {
			t.Fatal("the key changed")
		}
	})
}

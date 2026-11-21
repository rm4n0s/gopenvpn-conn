// SPDX-License-Identifier: GPL-2.0-only

package keys

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/rm4n0s/errors"
)

// counting is a key whose byte i is i, so that each part is easy to tell.
func counting() StaticKey {
	var k StaticKey
	var b byte
	for i := range k {
		k[i] = b
		b++
	}
	return k
}

// render writes a key the way `openvpn --genkey` does: 16 bytes a line.
func render(k *StaticKey) string {
	var sb strings.Builder
	sb.WriteString(staticKeyBegin + "\n")
	for i := 0; i < len(k); i += 16 {
		sb.WriteString(hex.EncodeToString(k[i:i+16]) + "\n")
	}
	sb.WriteString(staticKeyEnd + "\n")
	return sb.String()
}

func TestParseStaticKeyOfOpenVPN(t *testing.T) {
	// testdata/ta.key was made by `openvpn --genkey tls-auth`. Read its digits
	// here without ParseStaticKey, to compare.
	data, err := os.ReadFile("testdata/ta.key")
	if err != nil {
		t.Fatal(err)
	}
	var digits strings.Builder
	in := false
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "-----BEGIN"):
			in = true
		case strings.HasPrefix(line, "-----END"):
			in = false
		case in:
			digits.WriteString(strings.TrimSpace(line))
		}
	}
	want, err := hex.DecodeString(digits.String())
	if err != nil || len(want) != StaticKeySize {
		t.Fatalf("the test key is not 256 bytes: %d, %v", len(want), err)
	}
	key, err := ParseStaticKey(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key[:], want) {
		t.Error("the key is not the one in the file")
	}
}

func TestParseStaticKeyFormats(t *testing.T) {
	want := counting()
	standard := render(&want)
	oneLine := staticKeyBegin + "\n" + hex.EncodeToString(want[:]) + "\n" + staticKeyEnd + "\n"
	// Upper case digits, with the two marker lines as they must be written.
	upper := strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(standard),
		strings.ToUpper(staticKeyBegin), staticKeyBegin), strings.ToUpper(staticKeyEnd), staticKeyEnd)
	tests := []struct {
		name string
		file string
	}{
		{"the format of genkey", "#\n# 2048 bit OpenVPN static key\n#\n" + standard},
		{"nothing around it", standard},
		{"no newline at the end", strings.TrimSuffix(standard, "\n")},
		{"all digits on one line", oneLine},
		{"windows line ends", strings.ReplaceAll(standard, "\n", "\r\n")},
		{"upper case digits", upper},
		{"white space around lines", "  " + strings.ReplaceAll(standard, "\n", " \t\n\t ")},
		{"blank lines inside", strings.Replace(standard, "\n", "\n\n", 5)},
		{"text before and after", "junk\nBEGIN\n" + standard + "-----BEGIN OpenVPN Static key V1-----\n00\n"},
		{"digits split by spaces", staticKeyBegin + "\n" + strings.Join(splitEvery(hex.EncodeToString(want[:]), 7), " ") + "\n" + staticKeyEnd},
		{"4 bytes a line", staticKeyBegin + "\n" + strings.Join(splitEvery(hex.EncodeToString(want[:]), 8), "\n") + "\n" + staticKeyEnd},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseStaticKey(strings.NewReader(tt.file))
			if err != nil {
				t.Fatal(err)
			}
			if *got != want {
				t.Error("the key differs")
			}
		})
	}
}

func splitEvery(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func TestParseStaticKeyFailures(t *testing.T) {
	want := counting()
	good := render(&want)
	hexAll := hex.EncodeToString(want[:])
	block := func(digits string) string { return staticKeyBegin + "\n" + digits + "\n" + staticKeyEnd + "\n" }

	tests := []struct {
		name  string
		file  string
		route string
		meta  map[string]any
	}{
		{"empty", "", "ParseStaticKey.StaticKeyNotFound", map[string]any{"begin_found": false}},
		{"no begin line", strings.Replace(good, staticKeyBegin, "-----BEGIN SOMETHING ELSE-----", 1), "ParseStaticKey.StaticKeyNotFound", map[string]any{"begin_found": false}},
		{"no end line", strings.Replace(good, staticKeyEnd, "", 1), "ParseStaticKey.StaticKeyNotFound", map[string]any{"begin_found": true}},
		{"end before begin", staticKeyEnd + "\n" + staticKeyBegin + "\n" + hexAll + "\n", "ParseStaticKey.StaticKeyNotFound", map[string]any{"begin_found": true}},
		{"begin and end on the same line", staticKeyBegin + staticKeyEnd + hexAll, "ParseStaticKey.StaticKeyNotFound", nil},
		{"a letter that is not a digit", staticKeyBegin + "\n" + hexAll[:32] + "\n" + hexAll[32:60] + "xx\n" + staticKeyEnd, "ParseStaticKey.StaticKeyBadHex", map[string]any{"line": 3}},
		{"a digit that is not hexadecimal on line 2", staticKeyBegin + "\n" + "zz\n" + staticKeyEnd, "ParseStaticKey.StaticKeyBadHex", map[string]any{"line": 2}},
		{"255 bytes", block(hexAll[:510]), "ParseStaticKey.StaticKeyBadLength", map[string]any{"hex_digits": 510, "want": 512}},
		{"257 bytes", block(hexAll + "00"), "ParseStaticKey.StaticKeyBadLength", map[string]any{"hex_digits": 514}},
		{"one key of 128 bytes, which OpenVPN reads", block(hexAll[:256]), "ParseStaticKey.StaticKeyBadLength", map[string]any{"hex_digits": 256}},
		{"an odd number of digits", block(hexAll[:511]), "ParseStaticKey.StaticKeyBadLength", map[string]any{"hex_digits": 511}},
		{"no digits", block(""), "ParseStaticKey.StaticKeyBadLength", map[string]any{"hex_digits": 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseStaticKey(strings.NewReader(tt.file))
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
			// No key material in an error, in any form it is logged.
			text := fmt.Sprintf("%v|%+v|%v|%s", appErr, appErr.Metadata, appErr.StackTrace(), appErr.Message)
			for _, piece := range []string{hexAll[:16], hexAll[100:116], hexAll[500:510]} {
				if strings.Contains(text, piece) {
					t.Errorf("the error contains key digits %q: %s", piece, text)
				}
			}
		})
	}
}

func TestParseStaticKeyReadFailed(t *testing.T) {
	boom := io.ErrClosedPipe // an error from outside the module, for the cause
	_, err := ParseStaticKey(iotest.ErrReader(boom))
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("ParseStaticKey.StaticKeyReadFailed") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if !errors.Is(err, boom) {
		t.Errorf("the cause is lost: %v", err)
	}
}

func TestParseStaticKeyTooLarge(t *testing.T) {
	// A key file is read up to a limit: a reader that never ends must not be
	// read to the end.
	r := &countingReader{}
	_, err := ParseStaticKey(r)
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("ParseStaticKey.StaticKeyTooLarge") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if r.n > 2*maxStaticKeyFile {
		t.Errorf("read %d bytes of an endless reader, the limit is %d", r.n, maxStaticKeyFile)
	}
}

type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	c.n += len(p)
	return len(p), nil
}

func TestParts(t *testing.T) {
	k := counting()
	// Key 0 is bytes 0 to 127 (cipher 0 to 63, HMAC 64 to 127); key 1 is 128 to 255.
	part := func(first byte) KeyPart {
		var p KeyPart
		for i := range p.Cipher {
			p.Cipher[i] = first + byte(i)
			p.HMAC[i] = first + PartSize + byte(i)
		}
		return p
	}
	key0, key1 := part(0), part(128)
	tests := []struct {
		dir           Direction
		send, receive KeyPart
	}{
		{Bidirectional, key0, key0},
		{Normal, key0, key1},
		{Inverse, key1, key0},
	}
	for _, tt := range tests {
		t.Run(tt.dir.String(), func(t *testing.T) {
			send, receive, err := k.Parts(tt.dir)
			if err != nil {
				t.Fatal(err)
			}
			if send != tt.send {
				t.Errorf("send part is wrong")
			}
			if receive != tt.receive {
				t.Errorf("receive part is wrong")
			}
		})
	}
}

func TestPartsAreCopies(t *testing.T) {
	k := counting()
	send, _, err := k.Parts(Inverse)
	if err != nil {
		t.Fatal(err)
	}
	send.Cipher[0] ^= 0xff
	again, _, _ := k.Parts(Inverse)
	if again.Cipher[0] != 128 {
		t.Error("changing a part changed the key")
	}
}

func TestPartsUnknownDirection(t *testing.T) {
	k := counting()
	for _, dir := range []Direction{-1, 3, 99} {
		_, _, err := k.Parts(dir)
		appErr, ok := errors.FromError(err)
		if !ok {
			t.Fatalf("direction %d: expected *errors.Error, got %T: %v", dir, err, err)
		}
		if !appErr.HasRoute("Parts.UnknownDirection") {
			t.Errorf("direction %d: unexpected failure path: %s", dir, appErr.Route())
		}
		if appErr.Metadata["direction"] != int(dir) {
			t.Errorf("metadata = %v", appErr.Metadata)
		}
	}
}

func TestDirectionString(t *testing.T) {
	for dir, want := range map[Direction]string{Bidirectional: "bidirectional", Normal: "normal", Inverse: "inverse", 7: "unknown"} {
		if got := dir.String(); got != want {
			t.Errorf("Direction(%d).String() = %q, want %q", int(dir), got, want)
		}
	}
}

func FuzzParseStaticKey(f *testing.F) {
	k := counting()
	f.Add([]byte(render(&k)))
	f.Add([]byte(strings.ToUpper(render(&k))))
	f.Add([]byte(staticKeyBegin + "\n" + staticKeyEnd))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := ParseStaticKey(bytes.NewReader(data))
		if err != nil {
			return
		}
		// A key that was read is the key that was written: render and read it again.
		again, err := ParseStaticKey(strings.NewReader(render(key)))
		if err != nil {
			t.Fatalf("a key that was read cannot be written and read again: %v", err)
		}
		if *again != *key {
			t.Fatal("the key changed")
		}
	})
}

// SPDX-License-Identifier: GPL-2.0-only

package ctrlmsg

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/rm4n0s/errors"
)

// str is a string of the message, written by hand: a length that counts the
// NUL, the bytes, the NUL.
func str(s string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(min(len(s)+1, math.MaxUint16)))
	b = append(b, s...)
	return append(b, 0)
}

func filled(n int, v byte) []byte { return bytes.Repeat([]byte{v}, n) }

func TestAppendClientKeyExchange(t *testing.T) {
	m := &ClientKeyExchange{
		Options:  "V4,tls-client",
		Username: "alice",
		Password: "s3cret",
		PeerInfo: "IV_VER=x\nIV_PROTO=14\n",
	}
	copy(m.PreMaster[:], filled(PreMasterSize, 0xa1))
	copy(m.Random1[:], filled(RandomSize, 0xb2))
	copy(m.Random2[:], filled(RandomSize, 0xc3))

	// The bytes of the plan's Facts, written out: 4 zero bytes, the key method,
	// 48 + 32 + 32 random bytes, and four strings.
	want := []byte{0, 0, 0, 0, 2}
	want = append(want, filled(48, 0xa1)...)
	want = append(want, filled(32, 0xb2)...)
	want = append(want, filled(32, 0xc3)...)
	want = append(want, 0, 14)
	want = append(want, "V4,tls-client"...)
	want = append(want, 0)
	want = append(want, 0, 6, 'a', 'l', 'i', 'c', 'e', 0)
	want = append(want, 0, 7, 's', '3', 'c', 'r', 'e', 't', 0)
	want = append(want, str("IV_VER=x\nIV_PROTO=14\n")...)

	got, err := AppendClientKeyExchange(nil, m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("message =\n%x\nwant\n%x", got, want)
	}
	// Appending goes after what dst has.
	got, err = AppendClientKeyExchange([]byte("prefix"), m)
	if err != nil || !bytes.Equal(got, append([]byte("prefix"), want...)) {
		t.Errorf("appending to a prefix: %v", err)
	}
}

func TestAppendClientKeyExchangeEmptyCredentials(t *testing.T) {
	got, err := AppendClientKeyExchange(nil, &ClientKeyExchange{Options: "o", PeerInfo: "p"})
	if err != nil {
		t.Fatal(err)
	}
	// An absent user name or password is the empty string: length 1, one NUL.
	tail := got[len(got)-len("\x00\x02o\x00\x00\x01\x00\x00\x01\x00\x00\x02p\x00"):]
	if want := []byte("\x00\x02o\x00\x00\x01\x00\x00\x01\x00\x00\x02p\x00"); !bytes.Equal(tail, want) {
		t.Errorf("strings = %q, want %q", tail, want)
	}
}

func TestAppendClientKeyExchangeRefusesBadStrings(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	tests := []struct {
		name  string
		m     ClientKeyExchange
		route string
		field string
	}{
		{"options at the limit", ClientKeyExchange{Options: long(MaxOptionsLen - 1)}, "", ""},
		{"options too long", ClientKeyExchange{Options: long(MaxOptionsLen)}, "AppendClientKeyExchange.StringTooLong", "options"},
		{"username at the limit", ClientKeyExchange{Options: "o", Username: long(MaxCredentialLen - 1)}, "", ""},
		{"username too long", ClientKeyExchange{Options: "o", Username: long(MaxCredentialLen)}, "AppendClientKeyExchange.StringTooLong", "username"},
		{"password too long", ClientKeyExchange{Options: "o", Password: long(MaxCredentialLen)}, "AppendClientKeyExchange.StringTooLong", "password"},
		{"peer info at the limit", ClientKeyExchange{Options: "o", PeerInfo: long(0xffff - 1)}, "", ""},
		{"peer info too long", ClientKeyExchange{Options: "o", PeerInfo: long(0xffff)}, "AppendClientKeyExchange.StringTooLong", "peer info"},
		{"NUL in the options", ClientKeyExchange{Options: "a\x00b"}, "AppendClientKeyExchange.StringHasNUL", "options"},
		{"NUL in the password", ClientKeyExchange{Options: "o", Password: "a\x00b"}, "AppendClientKeyExchange.StringHasNUL", "password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AppendClientKeyExchange(nil, &tt.m)
			if tt.route == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute(tt.route) {
				t.Errorf("unexpected failure path: %s", appErr.Route())
			}
			if appErr.Metadata["field"] != tt.field {
				t.Errorf("metadata = %v, want field %q", appErr.Metadata, tt.field)
			}
			if got != nil {
				t.Error("bytes came with the error")
			}
			// No secret in the error: the password is never in it.
			if strings.Contains(err.Error(), "s3cret") || strings.Contains(appErr.Route(), "s3cret") {
				t.Error("the error has a secret")
			}
		})
	}
}

func TestErrorsDoNotCarryCredentials(t *testing.T) {
	m := &ClientKeyExchange{Options: "o", Username: "alice-the-user", Password: strings.Repeat("p", MaxCredentialLen)}
	_, err := AppendClientKeyExchange(nil, m)
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatal(err)
	}
	for k, v := range appErr.Metadata {
		if s, isString := v.(string); isString && (strings.Contains(s, "alice") || strings.Contains(s, "ppp")) {
			t.Errorf("metadata %q has credentials: %q", k, s)
		}
	}
	if strings.Contains(appErr.Message, "ppp") || strings.Contains(appErr.Message, "alice") {
		t.Error("the message has credentials")
	}
}

func TestNewClientKeyExchangeIsRandom(t *testing.T) {
	a := NewClientKeyExchange("o", "u", "p", "i")
	b := NewClientKeyExchange("o", "u", "p", "i")
	if a.Options != "o" || a.Username != "u" || a.Password != "p" || a.PeerInfo != "i" {
		t.Errorf("the strings are not those given: %+v", a)
	}
	if a.PreMaster == b.PreMaster || a.Random1 == b.Random1 || a.Random2 == b.Random2 {
		t.Error("two messages have the same random bytes")
	}
	var zero [PreMasterSize]byte
	if a.PreMaster == zero {
		t.Error("the pre-master secret is all zero")
	}
}

// serverMessage writes the server's message by hand.
func serverMessage(random1, random2 byte, strs ...string) []byte {
	b := []byte{0, 0, 0, 0, 2}
	b = append(b, filled(32, random1)...)
	b = append(b, filled(32, random2)...)
	for _, s := range strs {
		b = append(b, str(s)...)
	}
	return b
}

func TestParseServerKeyExchange(t *testing.T) {
	b := serverMessage(1, 2, "V4,tls-server", "", "", "IV_PROTO=1\n")
	m, err := ParseServerKeyExchange(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Random1 != [32]byte(filled(32, 1)) || m.Random2 != [32]byte(filled(32, 2)) {
		t.Errorf("random fields = %x %x", m.Random1, m.Random2)
	}
	if m.Options != "V4,tls-server" || m.Username != "" || m.Password != "" || m.PeerInfo != "IV_PROTO=1\n" {
		t.Errorf("strings = %+v", m)
	}
}

func TestParseServerKeyExchangeLeniencies(t *testing.T) {
	// The four leading bytes and the high bits of the method byte are not checked,
	// and a length of 0 is no string, as OpenVPN reads them.
	b := serverMessage(0, 0, "o")
	b[0], b[1], b[2], b[3] = 1, 2, 3, 4
	b[4] = 0xf2
	b = append(b, 0, 0, 0, 0, 0, 0) // no user name, no password, no peer info
	m, err := ParseServerKeyExchange(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Options != "o" || m.Username != "" || m.Password != "" || m.PeerInfo != "" {
		t.Errorf("strings = %+v", m)
	}
}

func TestParseServerKeyExchangeFailures(t *testing.T) {
	good := serverMessage(1, 2, "opts", "", "", "info")
	withLen := func(b []byte, at int, n uint16) []byte {
		c := bytes.Clone(b)
		binary.BigEndian.PutUint16(c[at:], n)
		return c
	}
	optionsAt := 4 + 1 + 64
	tests := []struct {
		name  string
		b     []byte
		route string
		field string
	}{
		{"empty", nil, "ParseServerKeyExchange.KeyExchangeTruncated", ""},
		{"fixed part cut", good[:60], "ParseServerKeyExchange.KeyExchangeTruncated", ""},
		{"method 1", func() []byte { c := bytes.Clone(good); c[4] = 1; return c }(), "ParseServerKeyExchange.BadKeyMethod", ""},
		{"method 0", func() []byte { c := bytes.Clone(good); c[4] = 0; return c }(), "ParseServerKeyExchange.BadKeyMethod", ""},
		{"no options length", good[:optionsAt+1], "ParseServerKeyExchange->readString.KeyExchangeTruncated", "options"},
		{"options absent", withLen(good, optionsAt, 0), "ParseServerKeyExchange->readString.StringMissing", "options"},
		{"options too long", withLen(good, optionsAt, MaxOptionsLen+1), "ParseServerKeyExchange->readString.StringTooLong", "options"},
		{"options cut", good[:optionsAt+4], "ParseServerKeyExchange->readString.KeyExchangeTruncated", "options"},
		{"options not terminated", func() []byte { c := bytes.Clone(good); c[optionsAt+2+4] = 'x'; return c }(), "ParseServerKeyExchange->readString.StringNotTerminated", "options"},
		{"options with a NUL inside", func() []byte { c := bytes.Clone(good); c[optionsAt+2+1] = 0; return c }(), "ParseServerKeyExchange->readString.StringHasNUL", "options"},
		{"username too long", serverMessage(1, 2, "o", strings.Repeat("u", MaxCredentialLen), "", ""), "ParseServerKeyExchange->readString.StringTooLong", "username"},
		{"no password", serverMessage(1, 2, "o", "u")[:len(serverMessage(1, 2, "o", "u"))], "ParseServerKeyExchange->readString.KeyExchangeTruncated", "password"},
		{"trailing bytes", append(bytes.Clone(good), 0), "ParseServerKeyExchange.KeyExchangeTrailing", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseServerKeyExchange(tt.b)
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute(tt.route) {
				t.Errorf("unexpected failure path: %s, want %s", appErr.Route(), tt.route)
			}
			if tt.field != "" && appErr.Metadata["field"] != tt.field {
				t.Errorf("metadata = %v, want field %q", appErr.Metadata, tt.field)
			}
			if m != nil {
				t.Error("a message came with the error")
			}
		})
	}
}

func FuzzParseServerKeyExchange(f *testing.F) {
	f.Add(serverMessage(1, 2, "V4,tls-server", "", "", "IV_PROTO=1\n"))
	f.Add(serverMessage(0, 0, "o", "u", "p", ""))
	f.Add([]byte{})
	f.Add(serverMessage(1, 2, "o")[:70])
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseServerKeyExchange(b)
		if err != nil {
			if m != nil {
				t.Fatal("a message and an error")
			}
			if _, ok := errors.FromError(err); !ok {
				t.Fatalf("the error is not tagged: %T", err)
			}
			return
		}
		// What parsed is what was in the bytes: writing it again gives the
		// same fields (the strings, which have no NUL inside).
		again := serverMessage(0, 0, m.Options, m.Username, m.Password, m.PeerInfo)
		m2, err := ParseServerKeyExchange(again)
		if err != nil {
			t.Fatalf("a message that was parsed does not parse again: %v", err)
		}
		if m2.Options != m.Options || m2.Username != m.Username || m2.Password != m.Password || m2.PeerInfo != m.PeerInfo {
			t.Fatalf("the fields changed: %+v then %+v", m, m2)
		}
		for _, s := range []string{m.Options, m.Username, m.Password, m.PeerInfo} {
			if strings.IndexByte(s, 0) >= 0 {
				t.Fatal("a string with a NUL was accepted")
			}
		}
	})
}

func FuzzAppendClientKeyExchange(f *testing.F) {
	f.Add("V4,tls-client", "alice", "pw", "IV_VER=1\n")
	f.Add("", "", "", "")
	f.Add("a\x00b", "x", "y", "z")
	f.Fuzz(func(t *testing.T, options, user, pass, info string) {
		m := &ClientKeyExchange{Options: options, Username: user, Password: pass, PeerInfo: info}
		b, err := AppendClientKeyExchange(nil, m)
		if err != nil {
			return // refused, with a tag (checked by the table test)
		}
		// The server's reader, given the same strings after the 64 random bytes of a
		// server's message, reads what was written.
		tail := b[5+PreMasterSize+2*RandomSize:]
		server := append(append([]byte{0, 0, 0, 0, 2}, make([]byte, 2*RandomSize)...), tail...)
		got, err := ParseServerKeyExchange(server)
		if err != nil {
			// The options string may be empty (a length of 1 and a NUL is fine, so not here).
			t.Fatalf("the client's strings do not parse: %v", err)
		}
		if got.Options != options || got.Username != user || got.Password != pass || got.PeerInfo != info {
			t.Fatalf("the strings changed on the way")
		}
	})
}

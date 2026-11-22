// SPDX-License-Identifier: GPL-2.0-only

package ovpn

import (
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/rm4n0s/errors"
)

// TestWords are the cases of OpenVPN's test_parse_line (tests/unit_tests/openvpn/
// test_options_parse.c), with the answers of this grammar where it differs on purpose.
func TestWords(t *testing.T) {
	a256 := strings.Repeat("A", 255) + "O"
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"basic", "some-opt firstparm second-parm", []string{"some-opt", "firstparm", "second-parm"}},
		{"quoting, -- is not special here", `--some-opt 'first parm' "second' 'parm"`, []string{"--some-opt", "first parm", "second' 'parm"}},
		{"escaped quotes", `"some opt" 'first" "parm' "second\" \"parm"`, []string{"some opt", `first" "parm`, `second" "parm`}},
		{"escaped backslash", `some\\opt C:\\directory\\file`, []string{`some\opt`, `C:\directory\file`}},
		{"comment characters inside a word", "some-opt firstparm; second#parm", []string{"some-opt", "firstparm;", "second#parm"}},
		{"a comment", "some-opt firstparm # secondparm", []string{"some-opt", "firstparm"}},
		{"a comment with ;", "some-opt firstparm ; secondparm", []string{"some-opt", "firstparm"}},
		{"only a comment", "   # nothing here", nil},
		{"an empty line", "", nil},
		{"only white space", " \t\r", nil},
		{"a word just long enough", "opt " + a256, []string{"opt", a256}},
		{"quoting does not count for the length", `opt "` + a256 + `"`, []string{"opt", a256}},
		{"a very long line", "opt " + a256 + " " + a256 + " " + a256 + " " + a256, []string{"opt", a256, a256, a256, a256}},
		{"the most words", "0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15", strings.Fields("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15")},
		{"an escaped space keeps the word whole", `file C:\ and\ more`, []string{"file", "C: and more"}},
		{"an escaped tab", "a\\\tb", []string{"a\tb"}},
		{"an empty quoted word is a word", `opt "" ''`, []string{"opt", "", ""}},
		{"a quote inside a bare word is a character", `a"b c'd`, []string{`a"b`, "c'd"}},
		{"a closed quote and a word with no space between them are two words", `"a"b`, []string{"a", "b"}},
		{"a backslash is no escape in single quotes", `'a\b'`, []string{`a\b`}},
		{"CR at the end is white space", "opt arg\r", []string{"opt", "arg"}},
		{"tabs separate words", "opt\targ1\t\targ2", []string{"opt", "arg1", "arg2"}},
		{"an escaped quote starts a bare word", `\"a b`, []string{`"a`, "b"}},
		{"bytes that are not ASCII are kept", "opt héllo 日本", []string{"opt", "héllo", "日本"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := words(tt.in, 1)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("words(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func wantSyntax(t *testing.T, err error, route string, lineNo int) {
	t.Helper()
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not an *errors.Error", err, err)
	}
	if !appErr.HasRoute(route) {
		t.Fatalf("route %s, want %s", appErr.Route(), route)
	}
	if lineNo > 0 && appErr.Metadata["line"] != lineNo {
		t.Errorf("line %v in the metadata, want %d", appErr.Metadata["line"], lineNo)
	}
}

func TestWordsRefusals(t *testing.T) {
	tests := []struct {
		name, in, route string
	}{
		{"a double quote that is not closed", `--some-opt 'first parm "second parm"`, "words.ProfileSyntax"},
		{"only a double quote", `opt "abc`, "words.ProfileSyntax"},
		{"a single quote that is not closed", "opt 'abc", "words.ProfileSyntax"},
		{"a bad backslash in a bare word", `opt a\nb`, "words->escaped.ProfileSyntax"},
		{"a bad backslash in double quotes", `opt "a\nb"`, "words->escaped.ProfileSyntax"},
		{"a backslash that ends the line", `opt a\`, "words->escaped.ProfileSyntax"},
		{"a backslash before a comment character", `opt \;`, "words->escaped.ProfileSyntax"},
		{"too many words", "0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16", "words.ProfileSyntax"},
		{"a line that is too long", "opt " + strings.Repeat("A", maxLine), "words.ProfileSyntax"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := words(tt.in, 7)
			wantSyntax(t, err, tt.route, 7)
		})
	}
}

func TestLex(t *testing.T) {
	const cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	tests := []struct {
		name string
		in   string
		want []line
	}{
		{"options and comments", "client\n# a comment\n; another\nremote vpn.example.com 1194 udp\n\n  dev   tun  \n",
			[]line{{name: "client", lineNo: 1}, {name: "remote", args: []string{"vpn.example.com", "1194", "udp"}, lineNo: 4}, {name: "dev", args: []string{"tun"}, lineNo: 6}}},
		{"a leading -- is taken off", "--client\n--remote host 443", []line{{name: "client", lineNo: 1}, {name: "remote", args: []string{"host", "443"}, lineNo: 2}}},
		{"an inline file", "<ca>\n" + cert + "</ca>\nclient\n", []line{{name: "ca", inline: cert, isBlk: true, lineNo: 1}, {name: "client", lineNo: 6}}},
		{"an inline file with --", "--<ca>\n" + cert + "</ca>", []line{{name: "ca", inline: cert, isBlk: true, lineNo: 1}}},
		{"an empty inline file", "<ca>\n</ca>\n", []line{{name: "ca", inline: "", isBlk: true, lineNo: 1}}},
		{"the closing tag may be indented and followed by text", "<key>\nsecret\n   </key> and more\nclient", []line{{name: "key", inline: "secret\n", isBlk: true, lineNo: 1}, {name: "client", lineNo: 4}}},
		{"an inline file keeps its comments and leading space", "<tls-auth>\n# not a comment\n  indented\n</tls-auth>", []line{{name: "tls-auth", inline: "# not a comment\n  indented\n", isBlk: true, lineNo: 1}}},
		{"a connection block", "<connection>\nremote a 1194\nproto tcp\n</connection>\n<connection>\nremote b\n</connection>",
			[]line{{name: "connection", inline: "remote a 1194\nproto tcp\n", isBlk: true, lineNo: 1}, {name: "connection", inline: "remote b\n", isBlk: true, lineNo: 5}}},
		{"CR LF line ends", "client\r\n<ca>\r\n" + strings.ReplaceAll(cert, "\n", "\r\n") + "</ca>\r\nremote h 1\r\n",
			[]line{{name: "client", lineNo: 1}, {name: "ca", inline: cert, isBlk: true, lineNo: 2}, {name: "remote", args: []string{"h", "1"}, lineNo: 7}}},
		{"a UTF-8 byte order mark", "\xef\xbb\xbfclient\nproto udp", []line{{name: "client", lineNo: 1}, {name: "proto", args: []string{"udp"}, lineNo: 2}}},
		{"no line end at the end", "client", []line{{name: "client", lineNo: 1}}},
		{"a tag with a word after it is an option", "<ca> x\nclient", []line{{name: "<ca>", args: []string{"x"}, lineNo: 1}, {name: "client", lineNo: 2}}},
		{"nothing", "", nil},
		{"only comments", "# a\n; b\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := lex(strings.NewReader(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("lex = %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestLexRefusals(t *testing.T) {
	tests := []struct {
		name, in, route string
		line            int
	}{
		{"an unterminated inline block", "client\n<ca>\nabc\n", "lex->block.ProfileSyntax", 2},
		{"an inline block closed by another tag", "<ca>\nabc\n</cert>\n", "lex->block.ProfileSyntax", 1},
		{"an inline block with no name", "<>\n</>\n", "lex->block.ProfileSyntax", 1},
		{"an unterminated quote", "client\nremote \"host 1194\n", "lex->words.ProfileSyntax", 2},
		{"an unterminated quote after an inline file", "<ca>\nx\n</ca>\nremote 'h\n", "lex->words.ProfileSyntax", 4},
		{"a bad backslash", "client\nca C:\\dir\\file\n", "lex->words->escaped.ProfileSyntax", 2},
		{"an option with no name", "--\n", "lex.ProfileSyntax", 1},
		{"a NUL byte", "client\nremote a\x00b\n", "lex.ProfileSyntax", 2},
		{"a very long line", "client\n" + strings.Repeat("a", maxLine+1) + "\n", "lex->words.ProfileSyntax", 2},
		{"a very long line in an inline file", "<ca>\n" + strings.Repeat("a", maxLine+1) + "\n</ca>\n", "lex->block.ProfileSyntax", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := lex(strings.NewReader(tt.in))
			wantSyntax(t, err, tt.route, tt.line)
		})
	}
}

func TestLexTooLarge(t *testing.T) {
	// Lines that are all right, and too many of them.
	in := strings.Repeat("# "+strings.Repeat("x", 1000)+"\n", maxSize/1000+1)
	_, err := lex(strings.NewReader(in))
	appErr, ok := errors.FromError(err)
	if !ok || appErr.Tag != TagProfileTooLarge || !appErr.HasRoute("lex.ProfileTooLarge") {
		t.Fatalf("error = %v", err)
	}
	// Exactly the limit is fine.
	if _, err := lex(strings.NewReader(strings.Repeat("#"+strings.Repeat("x", 1022)+"\n", maxSize/1024))); err != nil {
		t.Errorf("a profile of %d bytes: %v", maxSize, err)
	}
}

func TestLexReadFailure(t *testing.T) {
	cause := io.ErrClosedPipe
	_, err := lex(iotest.ErrReader(cause))
	appErr, ok := errors.FromError(err)
	if !ok || appErr.Tag != TagReadFailed || !appErr.HasRoute("lex.ProfileReadFailed") || !errors.Is(err, cause) {
		t.Fatalf("error = %v", err)
	}
}

func TestLineNumbersCountTheLinesOfInlineFiles(t *testing.T) {
	in := "client\n<ca>\na\nb\nc\n</ca>\nremote h\n"
	got, err := lex(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2].lineNo != 7 {
		t.Fatalf("lex = %+v: the option after a block of 3 lines is on line 7", got)
	}
	// An error after a block is reported at its own line, too.
	_, err = lex(strings.NewReader(in + "x \"\n"))
	wantSyntax(t, err, "lex->words.ProfileSyntax", 8)
}

// TestLexAllWordsOfALongLine checks that the count of words is the limit and no more.
func TestLexAllWordsOfALongLine(t *testing.T) {
	var words []string
	for i := range 16 {
		words = append(words, strconv.Itoa(i))
	}
	got, err := lex(strings.NewReader(strings.Join(words, " ")))
	if err != nil || len(got) != 1 || len(got[0].args) != 15 {
		t.Fatalf("lex = %+v, %v", got, err)
	}
}

func FuzzLex(f *testing.F) {
	for _, s := range []string{
		"client\nremote h 1194 udp\n",
		"<ca>\n-----BEGIN CERTIFICATE-----\n</ca>\n",
		"\xef\xbb\xbfclient\r\n",
		`a "b \" c" 'd e' f\ g # h`,
		"<connection>\nremote a\n</connection>",
		"<ca>\nabc\n",
		"--",
		"\"",
		"a\\",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		lines, err := lex(strings.NewReader(in))
		if err != nil {
			appErr, ok := errors.FromError(err)
			if !ok || (appErr.Tag != TagSyntax && appErr.Tag != TagProfileTooLarge) {
				t.Fatalf("an error that is not tagged as the parser's: %v", err)
			}
			return
		}
		total := strings.Count(in, "\n") + 1
		last := 0
		for _, l := range lines {
			if l.name == "" || len(l.args) > maxArgs || l.lineNo < 1 || l.lineNo > total || l.lineNo <= last {
				t.Fatalf("a bad line: %+v (the profile has %d lines)", l, total)
			}
			if l.isBlk && len(l.args) != 0 || !l.isBlk && l.inline != "" {
				t.Fatalf("a bad line: %+v", l)
			}
			last = l.lineNo
		}
		// The same text gives the same lines.
		again, err := lex(strings.NewReader(in))
		if err != nil || !reflect.DeepEqual(lines, again) {
			t.Fatalf("lex is not deterministic: %v", err)
		}
	})
}

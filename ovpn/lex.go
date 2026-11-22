// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/options_parse.c (parse_line, read_config_file, check_inline_file, read_inline_file) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package ovpn

import (
	"io"
	"strings"

	"github.com/rm4n0s/errors"
)

// The limits of the grammar. OpenVPN's are 16 parameters, 256 bytes for a parameter and
// 256 for a line, and it cuts what is longer without saying so in some places; here
// anything over a limit is an error, and the limits for a line and a parameter are
// larger (SPEC §20 V12), as a profile with a long list of ciphers is not wrong.
const (
	// maxArgs is how many words follow an option's name on a line, and a line has at
	// most one more: the name. OpenVPN's MAX_PARMS.
	maxArgs = 15
	// maxLine is the longest line, in bytes, with its line end; it is also the longest
	// word.
	maxLine = 4096
	// maxSize is the longest profile, inline files included, in bytes.
	maxSize = 1 << 20
)

// line is one option of a profile: its name (without a leading "--"), its words, and
// for an inline file or a block (<ca> ... </ca>, <connection> ... </connection>) the text
// between the tags, which is then the option's only argument.
type line struct {
	name   string
	args   []string
	inline string
	isBlk  bool // an inline block: name is the tag, inline the text
	lineNo int  // the line of the option (of its opening tag for a block), from 1
}

// lex splits the text of a profile into options. A line is an option name and words
// separated by white space; a word is quoted with double quotes (a backslash escapes
// a double quote, a backslash and a white space character) or single quotes (no
// escapes), or is bare (a backslash escapes the same three); # and ; start a comment
// where a word could start, and mean nothing inside a word. A line that is only a tag
// <name> opens a block that ends at a line that starts with </name>. A UTF-8 byte order
// mark at the start is ignored, and a line may end in CR LF.
//
// OpenVPN: options_parse.c parse_line, read_config_file, check_inline_file.
func lex(r io.Reader) ([]line, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, errors.NewErr(TagReadFailed, err)
	}
	if len(data) > maxSize {
		return nil, errors.New(TagProfileTooLarge, "the profile is too large", "max", maxSize)
	}
	text := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	if strings.IndexByte(text, 0) >= 0 {
		return nil, errors.New(TagSyntax, "the profile has a NUL byte", "line", 1+strings.Count(text[:strings.IndexByte(text, 0)], "\n"))
	}
	lines := strings.Split(text, "\n")
	// A text that ends with a line end has an empty last element.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	var out []line
	for i := 0; i < len(lines); i++ {
		ws, err := words(lines[i], i+1)
		if err != nil {
			return nil, err
		}
		if len(ws) == 0 {
			continue
		}
		name := strings.TrimPrefix(ws[0], "--")
		if name == "" {
			return nil, errors.New(TagSyntax, "an option has no name", "line", i+1)
		}
		if len(ws) == 1 && len(name) >= 2 && name[0] == '<' && name[len(name)-1] == '>' {
			tag := name[1 : len(name)-1]
			text, next, err := block(lines, i, tag)
			if err != nil {
				return nil, err
			}
			out = append(out, line{name: tag, inline: text, isBlk: true, lineNo: i + 1})
			i = next
			continue
		}
		l := line{name: name, lineNo: i + 1}
		if len(ws) > 1 {
			l.args = ws[1:]
		}
		out = append(out, l)
	}
	return out, nil
}

// block collects the lines after the opening tag at lines[open], up to the line that
// starts (after white space) with the closing tag. It returns their text, each line
// with a line feed and no carriage return, and the index of the closing line.
//
// OpenVPN: options_parse.c read_inline_file.
func block(lines []string, open int, tag string) (text string, closing int, err error) {
	if tag == "" || strings.ContainsAny(tag, " \t<>") {
		return "", 0, errors.New(TagSyntax, "the tag of an inline block has no name or has a bad character", "line", open+1)
	}
	end := "</" + tag + ">"
	var b strings.Builder
	for i := open + 1; i < len(lines); i++ {
		if len(lines[i]) > maxLine {
			return "", 0, errors.New(TagSyntax, "a line is too long", "line", i+1, "max", maxLine)
		}
		if strings.HasPrefix(strings.TrimLeft(lines[i], " \t\v\f\r"), end) {
			return b.String(), i, nil
		}
		b.WriteString(strings.TrimSuffix(lines[i], "\r"))
		b.WriteByte('\n')
	}
	return "", 0, errors.New(TagSyntax, "an inline block is not closed", "line", open+1, "tag", tag)
}

// words splits one line into its words, with quotes and escapes taken out. no is the
// number of the line, for the errors.
//
// OpenVPN: options_parse.c parse_line.
func words(s string, no int) ([]string, error) {
	if len(s) > maxLine {
		return nil, errors.New(TagSyntax, "a line is too long", "line", no, "max", maxLine)
	}
	var out []string
	var w []byte
	i := 0
	for {
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i >= len(s) || s[i] == '#' || s[i] == ';' {
			return out, nil
		}
		if len(out) > maxArgs {
			return nil, errors.New(TagSyntax, "the line has too many words", "line", no, "max", maxArgs+1)
		}
		w = w[:0]
		switch s[i] {
		case '"':
			i++
			for {
				if i >= len(s) {
					return nil, errors.New(TagSyntax, "a double quote is not closed", "line", no)
				}
				c := s[i]
				if c == '"' {
					i++
					break
				}
				if c == '\\' {
					esc, err := escaped(s, i, no)
					if err != nil {
						return nil, err
					}
					w = append(w, esc)
					i += 2
					continue
				}
				w = append(w, c)
				i++
			}
		case '\'':
			i++
			for {
				if i >= len(s) {
					return nil, errors.New(TagSyntax, "a single quote is not closed", "line", no)
				}
				c := s[i]
				i++
				if c == '\'' {
					break
				}
				w = append(w, c)
			}
		default:
			for i < len(s) && !isSpace(s[i]) {
				c := s[i]
				if c == '\\' {
					esc, err := escaped(s, i, no)
					if err != nil {
						return nil, err
					}
					w = append(w, esc)
					i += 2
					continue
				}
				w = append(w, c)
				i++
			}
		}
		out = append(out, string(w))
	}
}

// escaped is the character that the backslash at s[i] stands for: a backslash, a
// double quote or a white space character, as OpenVPN has it. It is an error for
// anything else, and at the end of the line, where it is an error.
func escaped(s string, i, no int) (byte, error) {
	if i+1 < len(s) {
		if c := s[i+1]; c == '\\' || c == '"' || isSpace(c) {
			return c, nil
		}
	}
	return 0, errors.New(TagSyntax, "a backslash must be followed by a backslash, a double quote or white space", "line", no)
}

// isSpace is the white space of the C locale: what OpenVPN's isspace says.
func isSpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

const (
	// TagSyntax: the profile does not follow the grammar (a quote that is not closed,
	// a bad backslash, an inline block with no end, a line that is too long, too many
	// words on a line). Metadata: "line" (from 1, the line where it starts).
	TagSyntax = "ProfileSyntax"
	// TagProfileTooLarge: the profile is larger than the parser takes (1 MiB).
	// Metadata: "max".
	TagProfileTooLarge = "ProfileTooLarge"
	// TagReadFailed: reading the profile failed. The cause can be found with
	// errors.Is.
	TagReadFailed = "ProfileReadFailed"
)

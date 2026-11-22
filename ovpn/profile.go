// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/options.c (add_option) and doc/man-sections/ (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package ovpn

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
)

// DefaultConnectTimeout is how long one remote has to answer (the link, and the first
// packet of the server) when the profile has no connect-timeout: OpenVPN's 120
// seconds.
const DefaultConnectTimeout = 120 * time.Second

// Remote is one server of a profile, in the form that openvpn.Dial takes.
type Remote struct {
	// Network is "udp", "udp4", "udp6", "tcp", "tcp4" or "tcp6".
	Network string
	// Address is the host and the port: "vpn.example.com:1194", "[2001:db8::1]:443".
	Address string
}

// Profile is what a profile says, ready to use.
type Profile struct {
	// Config is the configuration of the connections: the TLS configuration made
	// from ca, cert, key, remote-cert-tls, verify-x509-name, peer-fingerprint,
	// tls-version-min and tls-groups, the protection of the control channel, the
	// credentials of auth-user-pass, the ciphers, the timers, the peer info and the
	// pull filters. Every Conn made from a Profile shares it, and it is not changed.
	Config *openvpn.Config
	// Remotes are the servers, in the order of the profile. With RemoteRandom the
	// order in which to try them is a random one, made when Dial runs.
	Remotes []Remote
	// RemoteRandom is true when the profile has remote-random.
	RemoteRandom bool
	// ConnectTimeout is how long one remote has to answer: for the link to be made
	// and the first packet of the server to come (connect-timeout, or
	// server-poll-timeout); DefaultConnectTimeout when the profile has none. It does
	// not bound the handshake with a server that has answered.
	ConnectTimeout time.Duration
	// NeedsCredentials is true when the profile has auth-user-pass with no file: the
	// caller has to set Config.Credentials before it dials.
	NeedsCredentials bool
	// Ignored are the names of the options that the profile has and the library does
	// nothing with (persist-tun, verb, nobind, ...), in the order of their first
	// appearance, each once.
	Ignored []string
}

// Parse reads a profile whose files are all inline (<ca>, <cert>, <key>, <tls-auth>,
// <tls-crypt>, <tls-crypt-v2>, <auth-user-pass>, <peer-fingerprint>): a file name in
// an option is an error (TagFileUnavailable), as Parse reads nothing but r.
func Parse(r io.Reader) (*Profile, error) {
	return parse(r, nil, "")
}

// ParseFS reads the profile called name in fsys, and the files that its options name
// from fsys, as paths relative to the directory of the profile. It reads nothing that
// is not in fsys: a name that is absolute, or climbs out of the directory with "..",
// is an error (TagFileUnavailable).
func ParseFS(fsys fs.FS, name string) (*Profile, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, errors.NewErr(TagReadFailed, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if cerr := f.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return nil, errors.NewErr(TagReadFailed, err)
	}
	return parse(bytes.NewReader(data), fsys, path.Dir(name))
}

// parse is Parse and ParseFS: fsys is nil for Parse, and dir is the directory of the
// profile in fsys.
func parse(r io.Reader, fsys fs.FS, dir string) (*Profile, error) {
	lines, err := lex(r)
	if err != nil {
		return nil, err
	}
	b := newBuilder(fsys, dir)
	// ignore-unknown-option applies to the whole profile, whatever its place.
	for _, l := range lines {
		if l.name == "ignore-unknown-option" && !l.isBlk {
			b.ignoreUnknown = append(b.ignoreUnknown, l.args...)
		}
	}
	for _, l := range lines {
		if err := b.apply(l, false); err != nil {
			return nil, err
		}
	}
	return b.finish()
}

// splitList splits a list that is separated by colons.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ":") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

const (
	// TagUnsupportedOption: the profile has an option that this library does not
	// implement and cannot skip safely, or one that it does not know. Metadata:
	// "option", "line", "reason".
	TagUnsupportedOption = "UnsupportedOption"
	// TagBadOption: an option has the wrong number of arguments or an argument that is
	// not valid. Metadata: "option", "line", "reason" (it never has the value of an
	// argument, which may be a secret).
	TagBadOption = "BadOption"
	// TagMissingOption: an option that the profile needs is not there (the certificate
	// authority, or the key of a certificate). Metadata: "option".
	TagMissingOption = "MissingOption"
	// TagFileUnavailable: a file that an option names cannot be read: Parse has no file
	// system, the name leaves the directory of the profile, or reading fails. Metadata:
	// "option", "line".
	TagFileUnavailable = "FileUnavailable"
	// TagBadFile: a file or an inline file of the profile is not what its option
	// needs (no certificate in the ca, a key that is not readable or is encrypted, a
	// key file of tls-auth that is not a key). Metadata: "option", "reason".
	TagBadFile = "BadProfileFile"
)

// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, doc/man-sections/client-options.rst (--remote, --remote-random, --connect-timeout, --server-poll-timeout) (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package ovpn

import (
	"context"
	"crypto/rand"
	"encoding/binary"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
)

// Tags of the errors of Profile.Dial.
const (
	// TagNoRemotes: the profile has no remote, so there is no server to connect
	// to. A profile that Parse returned has at least one; this is a Profile that
	// the caller made or emptied.
	TagNoRemotes = "NoRemotes"
	// TagCredentialsMissing: the profile has auth-user-pass with no file
	// (Profile.NeedsCredentials) and Config.Credentials is not set.
	TagCredentialsMissing = "CredentialsMissing"
)

// Dial connects to the first remote of the profile that answers and returns when
// the handshake with it is complete, as openvpn.Dial does. Each remote gets
// ConnectTimeout for the link and the handshake together; when it fails, or the
// time is up, the next remote is tried (in a random order with RemoteRandom). When
// every remote failed, Dial returns the error of the last one, with the metadata
// "remotes_tried" (how many were tried) and "remotes" (how many the profile has).
// When ctx is done, Dial stops at once and returns the error of the remote that it
// was trying.
//
// A profile with auth-user-pass and no file needs Config.Credentials to be set
// before Dial (Profile.NeedsCredentials says so); without it, Dial returns
// TagCredentialsMissing and tries no remote. The Config is shared by the
// connections and is not changed.
func (p *Profile) Dial(ctx context.Context) (*openvpn.Conn, error) {
	return p.dial(ctx, shuffled, openvpn.Dial)
}

// dial is Dial with the order of the remotes and the function that makes one
// connection as parameters, so that the tests choose both. order returns a
// permutation of 0..n-1.
func (p *Profile) dial(
	ctx context.Context,
	order func(n int, random bool) []int,
	dialOne func(ctx context.Context, network, address string, config *openvpn.Config) (*openvpn.Conn, error),
) (*openvpn.Conn, error) {
	if len(p.Remotes) == 0 {
		return nil, errors.New(TagNoRemotes, "the profile has no remote")
	}
	if p.NeedsCredentials && (p.Config == nil || p.Config.Credentials == nil) {
		return nil, errors.New(TagCredentialsMissing, "the profile has auth-user-pass with no file and Config.Credentials is not set")
	}
	timeout := p.ConnectTimeout
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}
	// Deviation: one round through the remotes, not the endless rounds of --connect-retry (SPEC §20 V13).
	var lastErr error
	tried := 0
	for _, i := range order(len(p.Remotes), p.RemoteRandom) {
		r := p.Remotes[i]
		attempt, cancel := context.WithTimeout(ctx, timeout)
		conn, err := dialOne(attempt, r.Network, r.Address, p.Config)
		cancel()
		tried++
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	// The error was tagged by openvpn.Dial; the metadata does not change its route.
	if appErr, ok := errors.FromError(lastErr); ok {
		return nil, appErr.SetMetadata("remotes_tried", tried, "remotes", len(p.Remotes))
	}
	return nil, lastErr
}

// shuffled returns 0..n-1 in the order of the profile, or in a random order when
// random is true (remote-random). If the system has no random bytes, which Go does
// not report any more, the order of the profile stays: the shuffle only spreads the
// load, and a connection is better than none.
func shuffled(n int, random bool) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	if !random {
		return idx
	}
	var b [8]byte
	for i := n - 1; i > 0; i-- {
		if _, err := rand.Read(b[:]); err != nil {
			return idx
		}
		// The modulo bias is far below 2^-50 for a list of remotes.
		j := int(binary.BigEndian.Uint64(b[:]) % uint64(i+1) & 0x7fffffff)
		idx[i], idx[j] = idx[j], idx[i]
	}
	return idx
}

// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"bytes"
	"crypto"
	"hash"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
)

// ControlWrap is a protection of the control channel (OpenVPN's tls-auth,
// tls-crypt and tls-crypt-v2). Make one with NewTLSAuth, NewTLSCrypt or
// NewTLSCryptV2. A ControlWrap holds a key and no connection state, so one
// value may be in the Config of many connections.
type ControlWrap interface {
	// wrapper makes the protection of one connection, with its own packet
	// counters and replay window.
	wrapper(now func() time.Time) (ctrlwrap.Wrapper, error)
}

// KeyDirection is the direction of the keys of a static key file, OpenVPN's
// key-direction: which half of the file this side sends with.
type KeyDirection int

const (
	// KeyDirectionNone uses the first keys of the file in both directions: the
	// profile has no key-direction.
	KeyDirectionNone KeyDirection = iota
	// KeyDirection0 sends with the first keys and receives with the second:
	// key-direction 0, the usual setting of a server.
	KeyDirection0
	// KeyDirection1 sends with the second keys and receives with the first:
	// key-direction 1, the usual setting of a client.
	KeyDirection1
)

// NewTLSAuth makes the protection of tls-auth. key is the contents of the
// static key file (the text between the "OpenVPN Static key V1" lines, as
// `openvpn --genkey tls-auth` writes it). digest is the profile's auth option:
// crypto.SHA1 (OpenVPN's default), SHA256, SHA384 or SHA512.
//
// Draft: "tls-auth".
func NewTLSAuth(key []byte, direction KeyDirection, digest crypto.Hash) (ControlWrap, error) {
	newHash, err := ctrlwrap.HashFor(digest)
	if err != nil {
		return nil, err
	}
	var dir keys.Direction
	switch direction {
	case KeyDirectionNone:
		dir = keys.Bidirectional
	case KeyDirection0:
		dir = keys.Normal
	case KeyDirection1:
		dir = keys.Inverse
	default:
		return nil, errors.New(tagInvalidKeyDirection, "the key direction is not 0, 1 or none", "direction", int(direction))
	}
	k, err := keys.ParseStaticKey(bytes.NewReader(key))
	if err != nil {
		return nil, err
	}
	w := tlsAuthWrap{key: k, dir: dir, newHash: newHash}
	if _, err := w.wrapper(time.Now); err != nil { // the combination of key and digest works
		return nil, err
	}
	return w, nil
}

// NewTLSCrypt makes the protection of tls-crypt. key is the contents of the
// static key file that `openvpn --genkey tls-crypt` writes.
//
// Draft: "tls-crypt".
func NewTLSCrypt(key []byte) (ControlWrap, error) {
	k, err := keys.ParseStaticKey(bytes.NewReader(key))
	if err != nil {
		return nil, err
	}
	return tlsCryptWrap{key: k}, nil
}

// NewTLSCryptV2 makes the protection of tls-crypt-v2. key is the contents of
// the client key file that `openvpn --genkey tls-crypt-v2-client` writes (a
// PEM block, "OpenVPN tls-crypt-v2 client key").
//
// Draft: "tls-crypt-v2".
func NewTLSCryptV2(key []byte) (ControlWrap, error) {
	k, err := keys.ParseTLSCryptV2ClientKey(bytes.NewReader(key))
	if err != nil {
		return nil, err
	}
	return tlsCryptV2Wrap{key: k}, nil
}

type tlsAuthWrap struct {
	key     *keys.StaticKey
	dir     keys.Direction
	newHash func() hash.Hash
}

func (w tlsAuthWrap) wrapper(now func() time.Time) (ctrlwrap.Wrapper, error) {
	return ctrlwrap.NewTLSAuth(w.key, w.dir, w.newHash, now)
}

type tlsCryptWrap struct{ key *keys.StaticKey }

func (w tlsCryptWrap) wrapper(now func() time.Time) (ctrlwrap.Wrapper, error) {
	return ctrlwrap.NewTLSCrypt(w.key, now)
}

type tlsCryptV2Wrap struct{ key *keys.TLSCryptV2ClientKey }

func (w tlsCryptV2Wrap) wrapper(now func() time.Time) (ctrlwrap.Wrapper, error) {
	return ctrlwrap.NewTLSCryptV2(w.key, now)
}

const tagInvalidKeyDirection = "InvalidKeyDirection"

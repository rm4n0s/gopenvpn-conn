// SPDX-License-Identifier: GPL-2.0-only

// Based on OpenVPN 2.7.9, src/openvpn/crypto_epoch.c (Copyright (C) 2024-2026
// OpenVPN Inc, Arne Schwabe); rewritten in Go and changed for gopenvpn-conn,
// 2026-11-22.

package keys

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"github.com/rm4n0s/errors"
)

const (
	// EpochSecretSize is the size of an epoch key: the output of SHA-256.
	EpochSecretSize = sha256.Size
	// MaxEpoch is the highest epoch there can be: it has 16 bits.
	MaxEpoch = 0xffff
	// FirstEpoch is the epoch of the keys that the TLS exporter gives. Epoch 0 does
	// not exist: a packet with it is refused.
	FirstEpoch = 1

	labelPrefix = "ovpn "
)

// EpochKey is the secret of one epoch of one direction: E_n of the draft. The
// data key and the implicit IV of the epoch, and the next epoch key, are derived
// from it.
type EpochKey struct {
	// Epoch is the number of the epoch, from 1.
	Epoch uint16
	// Secret is E_n.
	Secret [EpochSecretSize]byte
}

// FirstEpochKey makes the key of epoch 1 of a direction: the first 32 bytes of
// the cipher key that the TLS exporter gave for that direction.
//
// Draft: "Epoch key generation".
func FirstEpochKey(k *DirectionKey) EpochKey {
	e := EpochKey{Epoch: FirstEpoch}
	copy(e.Secret[:], k.Cipher[:EpochSecretSize])
	return e
}

// Next is the key of the next epoch: E_n+1 = OVPN-Expand-Label(E_n, "datakey upd",
// "", 32). It fails when there is no next epoch (the epoch is 0xffff).
func (e EpochKey) Next() (EpochKey, error) {
	if e.Epoch == MaxEpoch {
		return EpochKey{}, errors.New(tagNoNextEpoch, "there is no epoch after the last one", "epoch", e.Epoch)
	}
	secret, err := ExpandLabel(e.Secret[:], "datakey upd", nil, EpochSecretSize)
	if err != nil {
		return EpochKey{}, err
	}
	n := EpochKey{Epoch: e.Epoch + 1}
	copy(n.Secret[:], secret)
	clear(secret)
	return n, nil
}

// DataKey derives what one epoch encrypts with: K_i = OVPN-Expand-Label(E_i,
// "data_key", "", keySize) and implicit_iv = OVPN-Expand-Label(E_i, "data_iv", "",
// ivSize). The caller clears both when it is done with them.
func (e EpochKey) DataKey(keySize, ivSize int) (key, iv []byte, err error) {
	if key, err = ExpandLabel(e.Secret[:], "data_key", nil, keySize); err != nil {
		return nil, nil, err
	}
	if iv, err = ExpandLabel(e.Secret[:], "data_iv", nil, ivSize); err != nil {
		clear(key)
		return nil, nil, err
	}
	return key, iv, nil
}

// Clear overwrites the secret with zeros.
func (e *EpochKey) Clear() { *e = EpochKey{} }

// ExpandLabel is OVPN-Expand-Label: HKDF-Expand with SHA-256 over the info
// uint16(length), a byte with the length of "ovpn "+label, those bytes, a byte
// with the length of the context, and the context. It is the HKDF-Expand-Label of
// TLS 1.3 with another prefix. The secret must be 32 bytes, the label 1 to 250
// bytes, the context at most 255, and the length at most 255 blocks of 32 bytes
// and 65535.
//
// OpenVPN: crypto_epoch.c ovpn_expand_label. Draft: "Epoch key generation".
func ExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	switch {
	case len(secret) != EpochSecretSize:
		return nil, errors.New(tagExpandLabelArgs, "the secret of OVPN-Expand-Label is not 32 bytes", "len", len(secret))
	case len(label) < 1 || len(label) > 250:
		return nil, errors.New(tagExpandLabelArgs, "the label of OVPN-Expand-Label is not 1 to 250 bytes", "len", len(label))
	case len(context) > 255:
		return nil, errors.New(tagExpandLabelArgs, "the context of OVPN-Expand-Label is longer than 255 bytes", "len", len(context))
	case length < 0 || length > 0xffff:
		return nil, errors.New(tagExpandLabelArgs, "the length of OVPN-Expand-Label does not fit 16 bits", "length", length)
	}
	info := binary.BigEndian.AppendUint16(make([]byte, 0, 2+1+len(labelPrefix)+len(label)+1+len(context)), uint16(length&0xffff))
	info = append(info, byte((len(labelPrefix)+len(label))&0xff))
	info = append(info, labelPrefix...)
	info = append(info, label...)
	info = append(info, byte(len(context)&0xff))
	info = append(info, context...)

	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		return nil, errors.NewErr(tagExpandLabelFailed, err)
	}
	return out, nil
}

const (
	tagNoNextEpoch       = "NoNextEpoch"
	tagExpandLabelArgs   = "ExpandLabelArgumentsInvalid"
	tagExpandLabelFailed = "ExpandLabelFailed"
)

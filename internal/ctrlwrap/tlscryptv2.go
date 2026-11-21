// SPDX-License-Identifier: GPL-2.0-only

package ctrlwrap

import (
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/wire"
)

// WKCWrapper is a Wrapper that appends a wrapped client key to some packets.
type WKCWrapper interface {
	Wrapper

	// WKcLen is the length of the wrapped client key. A CONTROL_HARD_RESET_CLIENT_V3
	// packet and a CONTROL_WKC_V1 packet are that much longer than Overhead says,
	// and a CONTROL_WKC_V1 packet that carries TLS bytes has to leave room for it.
	WKcLen() int
}

// tlsCryptV2 is tls-crypt with the key Kc of a tls-crypt-v2 client key, and the
// wrapped key WKc appended, unencrypted, to the packets that need it.
type tlsCryptV2 struct {
	*tlsCrypt
	wkc []byte
}

// NewTLSCryptV2 returns the Wrapper of a tls-crypt-v2 client: tls-crypt with the
// key Kc of the client key, whose replay packet ids start at
// wire.EarlyNegotiationStart (so that the first reset tells the server that the
// client can resend its wrapped key), and with WKc appended after the packet of
// a CONTROL_HARD_RESET_CLIENT_V3 and of a CONTROL_WKC_V1. WKc is not encrypted:
// the server needs it to find the key that decrypts the rest.
//
// Draft: "Client-specific encryption keys". Which packet is a CONTROL_WKC_V1 is
// for the session to decide (the one after the server's reset when the server
// asks for it): this Wrapper does what the first byte says.
//
// now is the clock (nil is time.Now). NewTLSCryptV2 panics when key is nil.
func NewTLSCryptV2(key *keys.TLSCryptV2ClientKey, now func() time.Time) (WKCWrapper, error) {
	if key == nil {
		panic("ctrlwrap: NewTLSCryptV2 needs a key")
	}
	inner, err := newTLSCrypt(&key.Kc, keys.Inverse, wire.EarlyNegotiationStart, now)
	if err != nil {
		return nil, err
	}
	return &tlsCryptV2{tlsCrypt: inner, wkc: append([]byte(nil), key.WKc...)}, nil
}

func (w *tlsCryptV2) WKcLen() int { return len(w.wkc) }

func (w *tlsCryptV2) Wrap(dst []byte, first byte, sid wire.SessionID, body []byte) ([]byte, error) {
	out, err := w.tlsCrypt.Wrap(dst, first, sid, body)
	if err != nil {
		return dst, err
	}
	if op, _ := wire.SplitFirstByte(first); op == wire.HardResetClientV3 || op == wire.ControlWKCV1 {
		out = append(out, w.wkc...)
	}
	return out, nil
}

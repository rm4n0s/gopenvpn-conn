// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"log/slog"
	"time"
)

// DefaultHandshakeTimeout is how long the handshake may take when
// Config.HandshakeTimeout is zero: OpenVPN's --hand-window.
const DefaultHandshakeTimeout = 60 * time.Second

// Config is the configuration of a client, as tls.Config is for TLS. The zero
// value of a field means its default. A Config is not changed by the library
// and may be shared by connections.
//
// The fields that the later parts of the protocol need (TLS, credentials, data
// ciphers, keepalive, MTU, peer info) are added as the library learns those
// parts.
type Config struct {
	// ControlWrap protects the control channel with a key shared in advance:
	// the value of NewTLSAuth, NewTLSCrypt or NewTLSCryptV2. Nil means no
	// protection, which the servers that are set up for it refuse.
	ControlWrap ControlWrap

	// HandshakeTimeout is how long the handshake may take; zero means
	// DefaultHandshakeTimeout. It is OpenVPN's --hand-window.
	HandshakeTimeout time.Duration

	// Logger gets the events of the connection, with the error of a failure
	// as the attribute "err". It never gets a key, a password or a packet's
	// bytes. Nil means no logs.
	Logger *slog.Logger
}

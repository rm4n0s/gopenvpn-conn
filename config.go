// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"crypto/tls"
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
// The fields that the later parts of the protocol need (credentials, data
// ciphers, keepalive, MTU, peer info) are added as the library learns those
// parts.
type Config struct {
	// TLS is the configuration of the TLS client of the control channel: the
	// server's certificate is verified with it, and its Certificates are the
	// client's. It is required. NewTLSConfig builds one that verifies the
	// server the way OpenVPN does. The library uses a copy, and raises a
	// MinVersion below TLS 1.2 to it.
	TLS *tls.Config

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

	// resetOnly makes the handshake end with the exchange of resets, with no
	// TLS: for the tests of that exchange, which need no certificates.
	resetOnly bool
}

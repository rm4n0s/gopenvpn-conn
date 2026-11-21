// SPDX-License-Identifier: GPL-2.0-only

// Package keys reads the key files of OpenVPN and derives the keys that the
// protocol uses from them: the static key file of tls-auth and tls-crypt, and
// (from step 1.7) the tls-crypt-v2 client key.
//
// Keys are secrets. Nothing in this package puts key bytes into an error, a
// message or a log line.
package keys

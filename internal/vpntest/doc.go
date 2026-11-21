// SPDX-License-Identifier: GPL-2.0-only

// Package vpntest is the in-process peer of the unit tests: links in memory
// (datagrams with loss, duplicates and reordering from a seed, and streams) and
// a small server side made of the packet packages of this module, so that the
// unit tests need no openvpn binary and no privileges.
//
// It is for tests only: it imports "testing", so no program may link it.
//
// The server is written apart from internal/session on purpose: a mistake that
// both made the same way would pass the unit tests, and only the real server
// (internal/servertest) would find it.
package vpntest

// SPDX-License-Identifier: GPL-2.0-only

// Package servertest starts a real OpenVPN server for the tests of
// gopenvpn-conn (SPEC §17). Only tests import it: it imports testing, so no
// program may link it.
//
// A test calls Start, which makes a PKI, starts openvpn 2.7 as a server on the
// loopback with a log file of its own, waits until it is ready, and stops it
// when the test ends. The server needs no root, but it needs a network
// namespace of its own, so the tests run under scripts/vpn-ns.sh; outside it,
// and when openvpn is not installed, Start skips the test.
//
// The package is empty on systems other than Linux.
package servertest

// SPDX-License-Identifier: GPL-2.0-only

// Package ovpn reads OpenVPN client profiles (.ovpn files) and turns them into a
// configuration for package openvpn.
//
// The parser reads only what it is given: Parse takes a profile with its files
// inline, and ParseFS reads the files that a profile names from the fs.FS that the
// caller passes, and from nowhere else. It never runs a command and never reads the
// environment.
//
// This is not OpenVPN's own program and is not affiliated with OpenVPN Inc.
package ovpn

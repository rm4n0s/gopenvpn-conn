#!/usr/bin/env bash
# Fetches the pinned reference sources into reference/ (git-ignored):
#
#   reference/openvpn-rfc  the wire protocol draft
#                          (draft-openvpntech-openvpn-wire-protocol)
#   reference/openvpn      OpenVPN 2.7.9, source and documentation (GPL-2.0)
#
# This project is GPL-2.0-only, so code is ported from OpenVPN 2 (docs/SPEC.md
# §2).  reference/ is still never imported, vendored or committed: ported code
# is rewritten in Go in this repository, each file naming the file it comes
# from, and the draft has no license that allows copying it (IETF Trust terms).
#
# Usage: scripts/fetch-reference.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref="$root/reference"

# The wire protocol draft (draft-openvpntech-openvpn-wire-protocol).
rfc_url="https://github.com/OpenVPN/openvpn-rfc.git"
rfc_commit="a58b36fbfa87e53667929149baf97dfa5d1f1c26" # 2026-11-09

# OpenVPN 2.7.9 (tag v2.7.9).
ovpn_url="https://github.com/OpenVPN/openvpn.git"
ovpn_commit="7b60c2aa34992639691e3a2d651fe27301e2e9d5" # 2026-11-05

# fetch <dir> <url> <commit> <path that must exist afterwards>
fetch() {
	local dir="$1" url="$2" commit="$3" need="$4"
	if [ -d "$dir/.git" ] && [ -e "$dir/$need" ] &&
		[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$commit" ]; then
		echo "up to date: ${dir#"$root"/} ($commit)"
		return
	fi
	rm -rf "$dir"
	mkdir -p "$dir"
	git -C "$dir" init -q
	git -C "$dir" remote add origin "$url"
	git -C "$dir" fetch -q --depth 1 origin "$commit"
	git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
	if [ "$(git -C "$dir" rev-parse HEAD)" != "$commit" ] || [ ! -e "$dir/$need" ]; then
		echo "error: ${dir#"$root"/} is not a full checkout of $commit" >&2
		exit 1
	fi
	echo "fetched: ${dir#"$root"/} ($commit)"
}

fetch "$ref/openvpn-rfc" "$rfc_url" "$rfc_commit" openvpn-wire-protocol.xml
fetch "$ref/openvpn" "$ovpn_url" "$ovpn_commit" src/openvpn

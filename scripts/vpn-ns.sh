#!/usr/bin/env bash
# Runs a command inside a private user and network namespace, where the process
# is root, may make TUN devices, and has its own loopback and no route to
# anything else. Nothing on the machine changes and no real root is needed.
# The tests against the real OpenVPN server run here (SPEC §17).
#
# Usage: scripts/vpn-ns.sh -- command [args...]
#
# The namespace has no internet, so the Go modules are downloaded first.
# GOPENVPN_NS=1 tells internal/servertest that it is inside the namespace.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
	echo "usage: scripts/vpn-ns.sh -- command [args...]" >&2
	exit 2
}

[ "${1:-}" = "--" ] || usage
shift
[ "$#" -gt 0 ] || usage

if ! why="$(unshare -Urn true 2>&1)"; then
	echo "vpn-ns: cannot make a user and network namespace: $why" >&2
	echo "vpn-ns: unprivileged user namespaces must be enabled (sysctl kernel.unprivileged_userns_clone, user.max_user_namespaces)" >&2
	exit 1
fi

go mod download

export GOPENVPN_NS=1
exec unshare -Urn sh -c 'ip link set lo up && exec "$@"' sh "$@"

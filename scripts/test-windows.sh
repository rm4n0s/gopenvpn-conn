#!/usr/bin/env bash
# Runs the unit tests of the module for Windows under Wine: every test binary is
# built with GOOS=windows and run by scripts/wine-exec.sh. Wine is stopped at the
# end (wineserver -k). Needs wine; prints a line and exits with 0 when it is
# missing, so that the checks of machines without it can go on.
#
# Usage: scripts/test-windows.sh [go test flags]
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
root="$PWD"

if ! command -v wine >/dev/null 2>&1; then
	echo "test-windows: wine is not installed; the Windows tests were skipped"
	exit 0
fi

export WINEPREFIX="$root/.wine-test/prefix"
export WINEDEBUG=-all
export WINEARCH=win64
export WINEDLLOVERRIDES="mscoree,mshtml="

stop_wine() {
	timeout -k 5 30 wineserver -k >/dev/null 2>&1 || true
}
trap stop_wine EXIT

# One program makes the prefix; the test binaries that run side by side would
# otherwise make it at the same time.
mkdir -p "$WINEPREFIX"
if ! timeout -k 5 300 wineboot --init >/dev/null 2>&1; then
	echo "test-windows: wine could not make its prefix in $WINEPREFIX" >&2
	exit 1
fi
timeout -k 5 60 wineserver -w >/dev/null 2>&1 || true

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -exec "$root/scripts/wine-exec.sh" "$@" ./...

#!/usr/bin/env bash
# Runs a Windows program under Wine, for `go test -exec`: the Wine prefix is
# .wine-test/prefix in the module root (git-ignored), nothing outside the
# project is touched, and a program that hangs is killed after 10 minutes.
#
# Usage: scripts/wine-exec.sh program.exe [args...]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export WINEPREFIX="$root/.wine-test/prefix"
export WINEDEBUG=-all
export WINEARCH=win64
# Do not offer to download Gecko and Mono: the tests need neither.
export WINEDLLOVERRIDES="mscoree,mshtml="

exec timeout -k 5 600 wine "$@"

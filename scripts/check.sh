#!/usr/bin/env bash
# Runs every check of the Definition of done (CLAUDE.md), in order, and stops
# at the first one that fails. One line per check: OK or FAILED.
#
# Usage: scripts/check.sh
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# gofiles lists the Go files of the module, never those of reference/ (the
# pinned sources of OpenVPN) or of the Wine prefix.
gofiles() {
	find . -name '*.go' -not -path './reference/*' -not -path './.wine-test/*' -not -path './.git/*'
}

# run <name> <command...> runs a command, prints OK or FAILED and, on failure,
# its output; then exits with status 1.
run() {
	local name="$1"
	shift
	local out
	if out="$("$@" 2>&1)"; then
		printf 'OK      %s\n' "$name"
	else
		printf 'FAILED  %s\n' "$name"
		printf '%s\n' "$out"
		exit 1
	fi
}

# gofmt_clean fails and lists the files when gofmt would change any.
gofmt_clean() {
	local files
	files="$(gofiles | xargs -r gofmt -l)"
	if [ -n "$files" ]; then
		printf 'gofmt would change:\n%s\n' "$files"
		return 1
	fi
}

# no_server_left fails when a test server (a tun device named tungo...) is
# still running after the tests.
no_server_left() {
	local left
	left="$(pgrep -af -- '--dev tungo' || true)"
	if [ -n "$left" ]; then
		printf 'openvpn processes left running:\n%s\n' "$left"
		return 1
	fi
}

# cross <goos> <goarch> builds and vets the module for another system.
cross() {
	GOOS="$1" GOARCH="$2" go build ./... && GOOS="$1" GOARCH="$2" go vet ./...
}

run "gofmt" gofmt_clean
run "go vet" go vet ./...
run "golangci-lint" golangci-lint run
run "golangci-lint (tests of the real server)" golangci-lint run --build-tags gopenvpn_server
run "error rules (errcheck)" go run ./internal/tools/errcheck -allow internal/tools/errcheck/errcheck.allow
run "go test -race" go test -race ./...
run "tests against the real server" scripts/vpn-ns.sh -- go test -race -count=1 -p 1 -tags gopenvpn_server ./...
run "no openvpn process left" no_server_left
run "CGO_ENABLED=0 go build" env CGO_ENABLED=0 go build ./...
run "CGO_ENABLED=0 go test" env CGO_ENABLED=0 go test ./...
run "windows/amd64 build and vet" cross windows amd64
run "windows/arm64 build and vet" cross windows arm64
run "darwin/amd64 build and vet" cross darwin amd64
run "darwin/arm64 build and vet" cross darwin arm64

echo "All checks passed."

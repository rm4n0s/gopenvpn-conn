# Implemented steps

The log of the finished steps of `docs/IMPLEMENTATION.md`, newest last. Rule 4 of that file says what an entry has.

## Step 0: the specification and the plan (2026-11-21, tag `step-0`)

Not a step of the plan: the setup that the plan starts from. No library code.

- **What was made:** `CLAUDE.md` (the process and the error handling of `github.com/rm4n0s/glutter`, adapted); `docs/SPEC.md`; `docs/IMPLEMENTATION.md` (30 steps in 5 milestones, written for Claude Sonnet 5.5 at high effort); `scripts/fetch-reference.sh` (the pinned sources of OpenVPN 2.7.9 and the wire protocol draft, into the git-ignored `reference/`).
- **License:** changed from BSD-3-Clause to GPL-2.0-only (`LICENSE`), with `NOTICE` (the copyright, the Apache2 linking exception, the OpenVPN entry) and `third_party/openvpn/` (OpenVPN's `COPYING` and license text).
- **Decisions of the owner, 2026-11-21:** GPL-2.0-only, so that OpenVPN 2's code can be the reference; nothing from minivpn; OpenVPN's code is the reference for the protocol, not a design to translate; gVisor for the userspace network; a modern-only 1.0; a `.ovpn` parser; Linux, Windows and macOS; each finished milestone is tagged with its version without stopping; nothing is pushed until the owner asks.
- **Checks:** none apply yet (there is no Go code). `scripts/fetch-reference.sh` was run twice (fetch, then "up to date").
- **Tried on this machine:** a real OpenVPN 2.7.9 server starts with no root inside `unshare -Urn` (SPEC §21, O4).
- **Still open:** whether there is a Mac for step 5.1.

## Step 1.1: the module and the check script (2026-11-21, tag `step-1.1`)

- **Built:** `go.mod` (`github.com/rm4n0s/gopenvpn-conn`, `go 1.26.3`, `github.com/rm4n0s/errors` v0.2.0), `doc.go` (package `openvpn`), `.golangci.yml` (golangci-lint v2: the standard linters plus `errcheck`, `govet`, `staticcheck`, `unused`, `ineffassign`, `gosec`, `misspell`, and the `gofmt` formatter), `scripts/check.sh`, `/.wine-test/` in `.gitignore`.
- **OpenVPN files used as reference:** none.
- **Checks that ran:** `scripts/check.sh`: gofmt, go vet, golangci-lint 2.15.0, `go test -race`, `CGO_ENABLED=0` build and test, build and vet for windows/amd64, windows/arm64, darwin/amd64, darwin/arm64: all OK. A deliberately misformatted file made it print `FAILED  gofmt` and exit 1.
- **Learned:** the plan said `go 1.27` in `go.mod`; SPEC §18 says the module needs the Go version that `rm4n0s/errors` needs (1.26.3). The plan line was changed to `go 1.26.3`. The Go in use here is 1.27.3.

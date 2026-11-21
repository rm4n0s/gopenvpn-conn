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

## Step 1.2: the error rules checker (2026-11-21, tag `step-1.2`)

- **Built:** `internal/tools/errcheck` (`check.go`, `allow.go`, `main.go`), its fixtures in `testdata/rules/` (nine directories; each marks the lines it expects reported with `// want N`, so the test reads its expectations from the files) and `errcheck.allow` (empty: comments only). `scripts/check.sh` now runs it after golangci-lint. It uses only `go/parser` and `go/ast`: no dependency.
- **Rules enforced:** 1 (`fmt.Errorf`; the standard `errors` package not imported as `stdErrors`), 2 (`errors.New` with fewer than a tag and a message; metadata not in key/value pairs; a non-string key literal; `SetMetadata` chained on `errors.New`; more than one `SetMetadata` chained on `NewErr`/`NewErrf`), 5 (a literal or expression as a tag, also in `&errors.Error{Tag: "..."}`), 6 (a package-level variable made with a constructor; a function literal is allowed), 7 (a function type that returns `*errors.Error`), 8 (a constant named `tag[A-Z]...`/`Tag[A-Z]...` whose value is not the end of a string given to `HasRoute` in a test; constants and `+` are resolved). Rules 3 and 4 are not checkable: the reviewer checks them.
- **Beyond the plan:** an allow entry that silences nothing is reported (a stale entry is itself a problem); the walk skips `reference/`, `testdata/`, `vendor/` and directories starting with `.` or `_`.
- **OpenVPN files used as reference:** none.
- **Checks that ran:** `scripts/check.sh`: all eleven OK. The checker run on this module reports nothing; run on a directory with an `fmt.Errorf` it prints `f.go:3: rule 1: ...` and exits 1. A test fails if a rule has no fixture that is reported for it.
- **Learned:** golangci-lint's `errcheck` made the first version fail on ignored `fmt.Fprintln` errors, so the report is built in a `strings.Builder` and written once by `writeReport`, which returns a tagged error with its own route test. gosec G304 is satisfied by `filepath.Clean` on the path; it was not silenced. The checker follows the rules it checks (its tags `ListDirFailed`, `ParseFailed`, `ReadAllowFailed`, `AllowSyntax`, `WriteFailed` each have a route test).

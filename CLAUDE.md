# CLAUDE.md

Guidance for Claude Code when working in this repository (Go, hosted on GitHub).

The development process and the error handling follow `github.com/rm4n0s/glutter`'s `CLAUDE.md` (the owner's rule, 2026-11-21).

## Project
`gopenvpn-conn` is a Go library that makes an OpenVPN client, with the patterns of the standard library: `openvpn.Client(conn, cfg)` and `openvpn.Dial` the way `crypto/tls` has them, a `*openvpn.Conn` that is a `net.Conn` of IP packets, `vpnnet` with `DialContext`, `Listen` and `ListenPacket` over the tunnel with no root, and `ovpn`, a parser of `.ovpn` profiles. It is pure Go, with no cgo, works on Linux, Windows and macOS, and is licensed GPL-2.0-only.

**`docs/SPEC.md` is the source of truth.** Read the sections that cover a task before starting it. If the code and the spec disagree, or a task needs a decision the spec doesn't make, ask instead of guessing. When a decision changes, update the spec on the same branch.

## License and porting from OpenVPN (SPEC §2)
This repository is **GPL-2.0-only** (the owner's decision, 2026-11-21): `LICENSE` is the text of the GPL version 2, and `NOTICE` has the copyright, the Apache2 linking exception and the OpenVPN entry. The library is derived from the client side of OpenVPN 2, so its sources are, in this order: the code of OpenVPN 2.7.9 in `reference/openvpn` (`src/openvpn/`), its documentation (`doc/`), the wire protocol draft in `reference/openvpn-rfc`, and the observed behavior of the real server.
- **OpenVPN's code is the reference for the protocol, not a design to translate** (the owner's rule, 2026-11-21: C is a very different language from Go, and its bugs are not wanted). Read it to learn what goes on the wire and what a server expects; then write the Go code as a Go programmer would, from that understanding, with the standard library:
  - **Must match OpenVPN** (or the two do not talk): the bytes of every packet, the cryptographic computations, the meaning of messages and options, and the numbers the peer depends on (window sizes, the most acks in a packet, key ids)
  - **Is this library's own design:** types, control flow, buffers, goroutines and timers, error handling, names, the API. Never translate a C function line by line, and never copy its memory handling, its global state or its `#ifdef` branches. What `crypto/tls`, `crypto/cipher` and `net` already do is used, not rewritten
  - **Is not copied:** workarounds for peers outside SPEC §1, dead or legacy paths, and anything that looks like a bug or is unsafe. When OpenVPN's behavior looks wrong, do not copy it: do the correct thing if the server still accepts it (a test against the real server decides), write the difference in SPEC §20, and ask the owner when the correct thing and interoperability pull apart
  - A number that only this side uses (a timeout, a local limit) starts from OpenVPN's default, because it is known to work, and may change for a reason that is written in SPEC §20
- Every Go file starts with `// SPDX-License-Identifier: GPL-2.0-only`. A file written with an OpenVPN file as its reference then names that file and says that this is a changed work, with the date (the GPL asks for it), e.g. `// Based on OpenVPN 2.7.9, src/openvpn/reliable.c (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.`
- A comment on protocol code names its source: `// OpenVPN: ssl_pkt.c tls_wrap_control`, `// Draft: <section title>`, `// OpenVPN doc: <file> <option>`, `// RFC 5705 §4`, or `// Observed: SPEC §21 O<n>`
- A deliberate difference from OpenVPN goes in a `// Deviation:` comment and in SPEC §20
- **Only OpenVPN 2 is a source.** Its license is the one of this repository. Never open or copy from another implementation (OpenVPN 3, minivpn, Wireshark's dissector, or any other) before the owner has decided it and its license has been checked: GPL-3.0 code, for one, cannot go into a GPL-2.0-only work
- `reference/` is git-ignored. Never import, vendor or commit it: the code here is written in Go from it, and the draft has no license that allows copying its text
- Keep `LICENSE`, `NOTICE`, `third_party/openvpn/COPYING` and `third_party/openvpn/COPYRIGHT.GPL` intact. A new dependency needs a license that can be combined with GPL-2.0-only (MIT, BSD, ISC; Apache-2.0 only through the linking exception of `NOTICE`)
- "OpenVPN" is a trademark of OpenVPN Inc: the documentation says "an OpenVPN client library", never that the project is OpenVPN or is endorsed by it

## Commands
- Fetch the reference sources: `scripts/fetch-reference.sh`
- Build: `go build ./...`; `CGO_ENABLED=0 go build ./...` must always work
- Test all: `go test -race ./...` (the race detector needs cgo, so this needs a C compiler)
- Test the cgo-free path: `CGO_ENABLED=0 go test ./...`
- Test one package: `go test ./internal/wire -run TestName -v`
- Tests against the real OpenVPN server (from step 1.1): `scripts/vpn-ns.sh -- go test -race -tags gopenvpn_server ./...` (a private user and network namespace, no root; the tests start and stop `openvpn` themselves)
- Fuzz one target: `go test ./internal/wire -run '^$' -fuzz FuzzParseControl -fuzztime 60s`
- Other systems: `GOOS=windows GOARCH=amd64 go build ./... && GOOS=windows GOARCH=amd64 go vet ./...`, the same for `windows/arm64`, `darwin/amd64` and `darwin/arm64`; from step 4.1 `scripts/test-windows.sh` (the unit tests under Wine)
- Vet: `go vet ./...`
- Lint: `golangci-lint run`
- Format: `gofmt -w .`
- Error rules check (SPEC §14, from step 1.1): `go run ./internal/tools/errcheck -allow internal/tools/errcheck/errcheck.allow`; a new violation is fixed, or accepted in that file with a reason
- Every check of the Definition of done at once (from step 1.1): `scripts/check.sh`
- After changing dependencies: `go mod tidy`

## Definition of done
Before reporting a task as finished, run `gofmt`, `go vet ./...`, `golangci-lint run` and `go test -race ./...`, and fix anything they report. Say so explicitly if any step was skipped or failed. Also:
- `CGO_ENABLED=0 go build ./...` and `CGO_ENABLED=0 go test ./...` pass
- The build and `go vet` pass for `windows/amd64`, `windows/arm64`, `darwin/amd64` and `darwin/arm64`
- From step 1.1 on: the error rules check passes, and `scripts/vpn-ns.sh -- go test -race -tags gopenvpn_server ./...` passes
- From step 4.1 on: `scripts/test-windows.sh` passes
- Every new error Tag has a route test, and every new parser of bytes that come from the network or from a file has a fuzz target that ran for at least 60 seconds
- Every new exported identifier has a doc comment; every Go file has its SPDX line, and code based on an OpenVPN file names it (see "License and porting from OpenVPN")
- `pgrep -a openvpn` and `pgrep -a wine` show nothing left

## Layout
- The module root is package `openvpn`: `Config`, `Client`, `Dial`, `Dialer`, `Conn`, `ConnectionState`, the exported error tags
- `ovpn/` parses `.ovpn` profiles into an `*openvpn.Config`
- `vpnnet/` is the userspace network over a `*openvpn.Conn` (the only package that imports gVisor)
- `internal/wire` (packet formats), `internal/ctrlwrap` (`tls-auth`, `tls-crypt`, `tls-crypt-v2`), `internal/reliable` (the reliability layer), `internal/keys` (key files and key derivation), `internal/ctrlmsg` (the messages inside TLS), `internal/datachan` (the data channel), `internal/session` (the state machine)
- `internal/vpntest` is the in-process peer of the unit tests; `internal/servertest` starts the real `openvpn` (tests only: they import `testing`, so no program may link them)
- `internal/tools/` holds the checkers; `scripts/` holds helper scripts; `examples/<name>/` holds runnable examples (public API only)
- `docs/SPEC.md` is the specification; `docs/IMPLEMENTATION.md` is the step-by-step plan; `docs/IMPLEMENTED.md` logs finished steps
- `reference/` (git-ignored) holds the pinned sources of OpenVPN 2.7.9 and the wire protocol draft; `third_party/openvpn/` holds OpenVPN's license files
- Tests live next to the code (`foo_test.go`); test data lives in `testdata/` of its package

## Go conventions
- Follow the standard library: the names, the shapes and the contracts of `net`, `crypto/tls`, `io`, `io/fs` and `log/slog` (SPEC §4, §5). A deliberate difference goes in a `// Deviation:` comment and in SPEC §20
- Never ignore a returned error; handle it or return it
- Pass `context.Context` as the first parameter of anything that does I/O or waits. Name it `ctx`
- Tests are table-driven. Time in tests is `testing/synctest`, never a real sleep
- No global mutable state and no `init` functions with effects. Package-level read-only values are fine and are never reassigned
- Every goroutine has an owner that stops it: after `Conn.Close` returns, no goroutine of that connection runs
- Prefer the standard library. Allowed dependencies: `github.com/rm4n0s/errors` (MIT), `golang.org/x/crypto` (BSD-3-Clause), and `gvisor.dev/gvisor` (Apache-2.0, through the linking exception of `NOTICE`) in `vpnnet` only. Ask before adding any other
- No cgo, no `unsafe`, no assembly. OS build tags are allowed only where SPEC §18 lists them
- Security rules (SPEC §15): random bytes come from `crypto/rand`; MACs are compared with `hmac.Equal`; a packet is authenticated before anything in it is used; no key, password or token goes into a log line, an error message or error metadata

## Error handling
Use `github.com/rm4n0s/errors` (v0.2.0) for all errors, the way its `AI_GUIDE.md` says. This is a requirement of the project owner: read the whole guide (it is in the module cache, `$(go env GOMODCACHE)/github.com/rm4n0s/errors@v0.2.0/AI_GUIDE.md`) before you write or change code that makes, returns, logs or tests an error, and again when the dependency version changes. SPEC §14 lists the rules with the reasons, and the error rules check enforces them. Never use `fmt.Errorf`, and never import the standard library `errors` package under the name `errors`: this package re-exports `errors.Is`, `errors.As` and `errors.Unwrap`, so a single import covers everything (if `Join` is needed, import the standard one as `stdErrors "errors"`).

**The one deviation (SPEC §5.3, D2).** Where a standard library contract names an exact error value, that value is returned untouched: `io.EOF`, `net.ErrClosed` and `os.ErrDeadlineExceeded` from the `Read`, `Write` and deadline methods of `*openvpn.Conn`, and whatever gVisor's `gonet` returns from the connections of `vpnnet`. Callers and the standard library compare these with `==` or assert `net.Error`. Everything else is tagged.

**Creating errors**
- New failure with a fixed message: `errors.New("Tag", "message", "key", value, ...)`. It always has a tag and a message
  - Tag: short PascalCase name of the thing the function cannot do, e.g. `TLSCryptUnwrapFailed`. Declare it as a constant next to the code that produces it (`const tagTLSCryptUnwrapFailed = "TLSCryptUnwrapFailed"` at the end of the file; exported as `TagX`, with a doc comment, when another package or a user matches on it)
  - Trailing arguments are key/value metadata pairs with string keys. Give all of them in this one call; never chain `SetMetadata` after `errors.New`
- New failure with a formatted message: `errors.NewErrf("Tag", "format %s", arg)`
- Wrapping an error that comes from outside this module (the standard library, `x/crypto`, gVisor): `errors.NewErr("Tag", err)`, once, where it first appears. `NewErr` and `NewErrf` take no metadata: add it with one `.SetMetadata("key", value, "key2", value2)` call. `NewErr(tag, nil)` panics, so call it only inside `if err != nil`
- Call the constructor in the function that fails, never in a helper that builds and returns the error: the route is the call stack at the constructor
- A sentinel for `errors.Is` is a struct literal, `&errors.Error{Tag: TagX}`. Never write `var ErrX = errors.New(...)` at package level: its route is `init`

**Propagating errors**
- Every error is tagged exactly once. If the error came from a function of this module, return it untouched: `return err`
- Functions return the plain `error` interface, never `*errors.Error`
- The error that ends a connection is made once, in the goroutine that found it, and every later `Read` and `Write` returns that same value

**Inspecting errors**
- `appErr, ok := errors.FromError(err)`, then use `appErr.Tag`, `appErr.Metadata`, `appErr.Message`
- Branch on the tag constant or on `errors.Is(err, sentinel)`, never on a string literal, `Message` or `Error()`

**Logging errors**
- Log with `slog` and pass the error as the attribute `"err"`: `logger.Error("what failed", "err", err)`. Do not call `ToJson` or `json.Marshal` on an error to log it
- Metadata values must be JSON-serializable

**Testing errors**
- Every failure case gets its own unique Tag and a test that asserts the route, not just that an error occurred:
  ```go
  appErr, ok := errors.FromError(err)
  if !ok {
      t.Fatalf("expected *errors.Error, got %T", err)
  }
  if !appErr.HasRoute("Conn.HandshakeContext->Conn.threeWay.HandshakeTimeout") {
      t.Errorf("unexpected failure path: %s", appErr.Route())
  }
  ```
- A route lists the call chain from outermost to innermost (`Type.Method` or `Func`, joined by `->`, no package names) and ends with the Tag. Print `appErr.Route()` when an assertion fails

## Git and GitHub
- Never commit or push directly to `main`; work on a branch named `feat/...` or `fix/...`
- **Exception:** if `docs/IMPLEMENTATION.md` exists, follow its Rules section for the steps it lists. Each step is done on its own branch, one at a time, and a finished step (the whole Definition of done passing) is merged into the local `main` by a fast-forward merge, without a PR, after its entry is added to `docs/IMPLEMENTED.md` on that branch. **A finished milestone is tagged with its version, without stopping** (the owner's rule, 2026-11-21): when the last step of a milestone is merged, that commit gets the version tag that rule 5 of `docs/IMPLEMENTATION.md` gives (`v0.1.0`, `v0.2.0`, `v0.3.0`, `v1.0.0-rc.1`, `v1.0.0`), and the next milestone starts in the same turn. Nothing is pushed to GitHub by a step: `main` and the tags are pushed when the owner asks. Never commit work for a step directly on `main`. Everything not covered by that file still follows the rule above
- **Tags:** after a finished step is merged into the local `main`, tag its commit with an annotated tag `step-<id>` (e.g. `step-2.3`); the step counts as finished when the tag is on the local `main`. Never move or delete a tag. When a milestone is finished, make its annotated version tag on that commit, without asking
- Commit messages: imperative mood, e.g. "Add the reliability layer"
- PRs: short description, link the issue (`Closes #123`), keep them small
- No `.github/` directory and no GitHub Actions workflows: never add them. The checks are run locally

## Working through the steps
- The steps start when the owner asks for them (the header of `docs/IMPLEMENTATION.md` says whether they have)
- From then on, never stop to ask for confirmation, and never end a turn with a question such as "Should I start the next step?", until every step in `docs/IMPLEMENTATION.md` is finished. After a step is finished (merged and tagged locally), report it briefly and start the next step in the same turn; the end of a milestone is not a reason to stop: tag its version and start the next milestone
- A step that says it is for another machine (a Mac, a Windows machine) is not done here: report what is finished before it, and stop there

## Don't
- Don't use any implementation other than OpenVPN 2 as a source (see "License and porting from OpenVPN")
- Don't commit `reference/`, secrets, private keys of real deployments, real `.ovpn` profiles or `.env` files. Keys in `testdata/` are made for the tests and say so
- Don't leave processes running: every `openvpn`, `tcpdump` and Wine instance started for a test, a proof or a check runs in its own process group under `timeout -k`, inside the namespace of `scripts/vpn-ns.sh`, and is stopped when it is no longer needed
- Don't touch the network configuration of the machine: no TUN device, address, route, firewall rule or `tc` rule outside the private namespace of `scripts/vpn-ns.sh`, and never `sudo`
- Don't connect to a VPN server on the internet from a test or a check: the tests talk to servers they start themselves on the loopback of the private namespace
- Never look for, list, open or read files outside this project folder. If something outside it is needed, ask the user to provide it. Exceptions: dependency source in the Go module cache, and the scratchpad directory of the session

## Testing notes
- Unit tests run with no `openvpn` binary and no privileges, on every platform: the peer is `internal/vpntest`, in the same process, over `net.Pipe` or a lossy in-memory link
- Tests that need the real server carry the `gopenvpn_server` build tag and run under `scripts/vpn-ns.sh`; they use `internal/servertest`, which makes the certificates and keys in Go, starts `openvpn` on the loopback of the namespace, and skips when `openvpn` is missing. A behavior of the protocol counts as implemented when a test against the real server shows it
- Every error Tag has a route test
- Every parser has a fuzz target, with its corpus in `testdata/fuzz/`
- A fixed issue gets a test that fails before the fix

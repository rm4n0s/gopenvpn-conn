# Implementation plan

Status: **finished, 2026-11-22** (started at the owner's request, 2026-11-21; the setup is tag `step-0`, the last step is `step-5.1`, tag `v1.0.0`). The rule "Working through the steps" of `CLAUDE.md` applies: no stopping between steps.

`docs/SPEC.md` says what is built. This file says in which order, in steps that are small and explicit enough for Claude Sonnet 5.5 at high effort to carry out one at a time (the owner's request, 2026-11-21). `docs/IMPLEMENTED.md` logs what is finished.

## Read this before any step

### What a step tells you
Every step has the same parts:
- **Goal:** what exists when the step is finished.
- **Read:** the sections of `docs/SPEC.md` and the OpenVPN files (under `reference/openvpn/src/openvpn/`) with the functions that matter. Read them before writing code.
- **Facts:** what the bytes look like and which numbers to use, so that you do not have to work them out. They were checked against OpenVPN 2.7.9. If the source says something else, the source is right: use it and write the difference in your `docs/IMPLEMENTED.md` entry.
- **Build:** the files, types and functions to write. Names of unexported things are suggestions; names of exported things come from SPEC §4, and if you change one you change SPEC §4 on the same branch.
- **Tests:** the tests the step must have.
- **Not in this step:** what to leave alone, even if it seems close.
- **Done when:** the checks that must pass, on top of the Definition of done of `CLAUDE.md`.

### How to use OpenVPN's code
OpenVPN's code is the reference for the protocol. It is not a design to translate (SPEC §2, D6).
1. Read the C to learn **what goes on the wire** and **what a server expects**. Take notes in your own words.
2. Close the C. Write the Go from your notes, the way a Go programmer would: small types, slices with bounds checks, `encoding/binary`, `crypto/*`, errors as values, no global state.
3. **Must match OpenVPN:** packet bytes, cryptographic computations, the meaning of messages and options, numbers the peer depends on. **Is your own design:** everything else.
4. **Never** translate a C function line by line, and never copy its buffer handling, its `#ifdef` branches, its global variables, or a workaround for a peer that SPEC §1 does not cover.
5. If something in OpenVPN looks like a bug or is unsafe, do not copy it. Do the correct thing, check with a test that the real server still accepts it, and write it in SPEC §20 as a deviation. If the correct thing does not interoperate, stop and ask the owner.

### The procedure of every step
1. `git switch main && git switch -c feat/step-<id>-<short-name>`.
2. Read `CLAUDE.md`, the step, the SPEC sections it names, and (if the step makes errors) `$(go env GOMODCACHE)/github.com/rm4n0s/errors@v0.3.1/AI_GUIDE.md`.
3. If `reference/` is empty, run `scripts/fetch-reference.sh`. Read the OpenVPN functions the step names.
4. Write the tests and the code. Every Go file starts with `// SPDX-License-Identifier: GPL-2.0-only`; a file based on an OpenVPN file names it on the next line (the exact form is in `CLAUDE.md`).
5. Run `scripts/check.sh` (from step 1.1 on) and fix everything it reports. Do not weaken a test or a check to make it pass.
6. Add the step's entry to `docs/IMPLEMENTED.md` (rule 4 below). Update `docs/SPEC.md` if the step changed or learned something.
7. Commit on the branch (imperative message, e.g. "Add the reliability layer").
8. `git switch main && git merge --ff-only feat/step-<id>-<short-name> && git tag -a step-<id> -m "Step <id>: <title>"`.
9. If the step is the last of its milestone, tag the milestone's version on the same commit (rule 5).
10. Report the step in a few lines and start the next one in the same turn, also when the next one is the first step of the next milestone. Do not stop and do not ask whether to go on.

### When you are stuck
- **A test against the real server fails.** Read the server's log first (`internal/servertest` keeps it; raise `--verb` to 7 for that test). The server says why it dropped a packet ("bad packet ID", "packet HMAC authentication failed", "tls-crypt unwrap error", "TLS Error: ..."). Then capture the packets inside the namespace (`tcpdump -i lo -w file udp port <port>`) and compare your bytes with the Facts.
- **The Facts and the source disagree.** The source is right. Say so in your entry.
- **The SPEC does not decide something, or seems wrong.** Do not guess. Ask the owner, with the options you see and the one you recommend.
- **A step is too large.** Split it into `<id>a` and `<id>b` in this file, on the branch, before going on (rule 7).
- **Never** to get unstuck: read another implementation (only OpenVPN 2 is a source), use `sudo`, connect to a server on the internet, skip a check, or mark a failing test as skipped.

### Words used in the steps
- **Link:** the UDP or TCP connection to the server that carries OpenVPN packets.
- **Control channel:** the reliable, ordered stream of control packets that carries TLS. **Data channel:** the encrypted IP packets.
- **Session id:** 8 random bytes each side picks for a connection. **Key id:** a number from 0 to 7 that says which TLS session (and so which data keys) a packet belongs to.
- **Control channel protection** ("wrap"): `tls-auth`, `tls-crypt` or `tls-crypt-v2`, an extra layer of authentication (and encryption) around control packets with a key shared in advance.
- **Tag:** the name of an error (`CLAUDE.md`, "Error handling"). **Route test:** a test that checks, with `HasRoute`, the path of calls that made an error.
- **The real server:** `openvpn` 2.7.9, started by `internal/servertest` inside the namespace of `scripts/vpn-ns.sh`.

## Rules

1. **One step at a time, in order,** each on its own branch. Never commit work for a step on `main`.
2. **Read before writing** (the procedure above, points 2 and 3).
3. **A step is finished** when its "Done when" is true, the whole Definition of done of `CLAUDE.md` passes, and its entry is in `docs/IMPLEMENTED.md` on the branch. Then it is merged by a fast-forward merge, with no PR, and tagged `step-<id>`.
4. **An entry of `docs/IMPLEMENTED.md`** has: the step and its title; the date; what was built (packages and the main types); the OpenVPN files that were the reference; the checks that ran, each with its result; the proof (for a step with a test against the real server: the lines of the server's log that show it); what was learned (new entries of SPEC §21, new deviations of SPEC §20, Facts that were wrong).
5. **A milestone is finished when its last step is merged into the local `main`.** That commit then gets the milestone's version as an annotated tag, at once and without asking (the owner's rule, 2026-11-21), and work goes on with the next milestone in the same turn:

   | Milestone | Last step | Tag | Command |
   |---|---|---|---|
   | M1: the control channel | 1.11 | `v0.1.0` | `git tag -a v0.1.0 -m "v0.1.0: the control channel"` |
   | M2: the tunnel | 2.10 | `v0.2.0` | `git tag -a v0.2.0 -m "v0.2.0: the tunnel"` |
   | M3: profiles and the userspace network | 3.5 | `v0.3.0` | `git tag -a v0.3.0 -m "v0.3.0: profiles and the userspace network"` |
   | M4: hardening and Windows | 4.3 | `v1.0.0-rc.1` | `git tag -a v1.0.0-rc.1 -m "v1.0.0-rc.1: release candidate"` |
   | M5: macOS | 5.1 | `v1.0.0` | `git tag -a v1.0.0 -m "v1.0.0"` |

   The versions before 1.0 say that the API may still change. `v1.0.0-rc.1` is everything of 1.0, checked on Linux and on Windows under Wine; `v1.0.0` is the same code once it is shown to work on a Mac. A fix after a tag gets the next patch number (`v0.2.1`). Never move or delete a tag.
   **Every release, a milestone or a fix, also changes the constant `libraryVersion` in `conn.go` to its version without the `v`** (it is the `IV_VER` that the server sees, SPEC §8.2), and its entry in `docs/IMPLEMENTED.md` ends with the line ``- **Version:** `vX.Y.Z` `` (`TestLibraryVersionIsTheNewestRelease` fails when the two differ), and the status line of `README.md` names the version.
   **Nothing is pushed to GitHub by a step.** Merging and tagging are local; pushing `main` and the tags is done when the owner asks for it.
6. **If a step needs a decision the SPEC does not make,** ask the owner. If a step shows the SPEC is wrong, fix the SPEC on the step's branch and say so in the entry.
7. **If a step turns out too large,** split it in this file, on the branch, before going on.
8. **A step for another machine** (marked so) is not done here: when it is the next step, report what is finished and stop. This is the only place where the work stops by itself; a decision that is the owner's (rule 6) is the other reason to stop.

---

## M1: the control channel (tag `v0.1.0`)

Result: the library completes a TLS handshake with the real server, over UDP and TCP, with each kind of control channel protection.

### Step 1.1: the module and the check script
- **Goal:** an empty Go module that builds, with one script that runs every check.
- **Read:** `CLAUDE.md` (all of it); SPEC §3, §18, §19.
- **Build:**
  - `go.mod`: `module github.com/rm4n0s/gopenvpn-conn`, `go 1.26.3` (the version `github.com/rm4n0s/errors` needs; SPEC §18). `go get github.com/rm4n0s/errors@v0.2.0`.
  - `doc.go`: `package openvpn` with the package comment (two or three sentences from SPEC §1).
  - `.golangci.yml`: the default linters plus `errcheck`, `govet`, `staticcheck`, `unused`, `ineffassign`, `gosec`, `misspell`, `gofmt`. Do not turn off a linter later to hide a finding; fix the finding.
  - `scripts/check.sh` (`set -euo pipefail`), running in this order and stopping at the first failure: `gofmt -l .` (fail if it prints a file), `go vet ./...`, `golangci-lint run`, `go test -race ./...`, `CGO_ENABLED=0 go build ./...`, `CGO_ENABLED=0 go test ./...`, then `go build ./...` and `go vet ./...` for `GOOS=windows GOARCH=amd64`, `windows/arm64`, `darwin/amd64`, `darwin/arm64`. Print one line per check with OK or FAILED.
  - `.gitignore`: add `/.wine-test/`.
- **Tests:** none yet (a module with no tests passes `go test`).
- **Not in this step:** any type of SPEC §4.
- **Done when:** `scripts/check.sh` prints OK for every check.

### Step 1.2: the error rules checker
- **Goal:** a program that fails when code breaks the error rules, so that later steps cannot break them by accident.
- **Read:** SPEC §14.1; the whole `AI_GUIDE.md` of `github.com/rm4n0s/errors`.
- **Build:** `internal/tools/errcheck/main.go`, using `go/parser` and `go/ast` (no dependency). It walks every `.go` file of the module except `reference/` and reports, as `file:line: rule N: text`:
  - rule 1: a call to `fmt.Errorf`; an import of `"errors"` (the standard package) without the alias `stdErrors`.
  - rule 2: `errors.New` with fewer than two arguments; a chain `errors.New(...).SetMetadata(...)`; more than one `.SetMetadata` chained on one constructor.
  - rule 5: a first argument of `errors.New`, `errors.NewErr` or `errors.NewErrf` that is a string literal instead of a constant.
  - rule 6: a package-level `var` whose value is a call to `errors.New`, `errors.NewErr` or `errors.NewErrf`.
  - rule 7: a function whose result type is `*errors.Error`.
  - rule 8: a constant whose name starts with `tag` or `Tag` and that appears in no `_test.go` file of the module inside a string passed to `HasRoute` (compare by the constant's string value).
  - `-allow file`: lines `path:rule:reason` that silence one rule in one file. The file starts empty: `internal/tools/errcheck/errcheck.allow`.
  - Exit status 1 when anything is reported.
  - Add it to `scripts/check.sh`: `go run ./internal/tools/errcheck -allow internal/tools/errcheck/errcheck.allow`.
- **Tests:** `internal/tools/errcheck/main_test.go`, table-driven: for each rule, a small Go source in `testdata/` that breaks it and one that does not, and the expected report.
- **Not in this step:** rules 3 and 4 (a program cannot check them; the reviewer does).
- **Done when:** the checker's own tests pass and `scripts/check.sh` runs it with no report.

### Step 1.3: the real server in the tests
- **Goal:** a test can start the real `openvpn` server with no root, read its log, and stop it.
- **Read:** SPEC §17; `reference/openvpn/doc/man-sections/server-options.rst` and `tls-options.rst` for the options below.
- **Facts:**
  - `unshare -Urn` gives a private user and network namespace in which the process is root and may create TUN devices. Its loopback is down until `ip link set lo up`. It has no internet: Go modules must be downloaded before entering it.
  - This command line starts a server there (tried on this machine, 2026-11-21): `openvpn --mode server --tls-server --dev <name> --topology subnet --server 10.8.0.0 255.255.255.0 --proto udp --local 127.0.0.1 --port <port> --ca ca.crt --cert server.crt --key server.key --dh none --verb 4 --log server.log`. The log says `Initialization Sequence Completed` when it is ready. The server then **requires a client certificate** (OpenVPN's default): the client of a later step presents `pki.ClientCert`. The server refuses `--verify-client-cert none` unless an authentication method is also configured (`--auth-user-pass-verify <script> via-file --script-security 2`, a plugin, or the management interface); steps that need clients with no certificate add both through `Options.Extra`.
  - The tun device of each server has its own name, `tungo<pid>_<n>` (it must begin with `tun`, at most 15 characters), so that test programs that run at the same time in one namespace do not collide. Two servers at once also need different subnets (`Options.Subnet`); `scripts/check.sh` runs the server tests with `-p 1`.
  - The server uses the kernel data channel (DCO) by default; `--disable-dco` turns it off.
- **Build:**
  - `scripts/vpn-ns.sh`: usage `scripts/vpn-ns.sh -- command...`. It runs `go mod download` first, then `exec unshare -Urn sh -c 'ip link set lo up && exec "$@"' sh "$@"`. If `unshare -Urn true` fails, it prints why and exits 1.
  - `internal/servertest` (every file has `//go:build linux`, and the package imports `testing`):
    - `pki.go`: `NewPKI(t) *PKI` makes, with `crypto/ecdsa` (P-256) and `crypto/x509`, a CA, a server certificate (extended key usage server auth, common name `server`) and a client certificate (client auth, common name `client`), written as PEM files into `t.TempDir()`. It also keeps them in memory for building a `tls.Config`.
    - `server.go`: `Start(t, Options) *Server`. `Options` has: `Proto` (`"udp"` or `"tcp"`), `DisableDCO bool`, `Subnet netip.Prefix` (default `10.8.0.0/24`), `Extra []string` (more command line options), `PKI *PKI`. It picks a free port, writes the command line above, starts `openvpn` with `exec.CommandContext` in its own process group (`SysProcAttr{Setpgid: true}`), waits up to 10 seconds for `Initialization Sequence Completed`, and registers `t.Cleanup` to send SIGTERM to the group, wait, then SIGKILL after 3 seconds. `Server` has `Addr()`, `Network()`, `Subnet()`, `TunnelIP()`, `PID()`, `Log()` and `WaitLog(t, substring, timeout)`.
    - `Start` calls `t.Skip` when `openvpn` is not in `PATH` or when the process is not inside a namespace made by `scripts/vpn-ns.sh` (detect it by an environment variable the script sets, `GOPENVPN_NS=1`).
  - Add to `scripts/check.sh`: `scripts/vpn-ns.sh -- go test -race -p 1 -tags gopenvpn_server ./...`, then a check that no process with `--dev tungo` in its command line is left (`pgrep -af -- '--dev tungo'` prints nothing).
- **Tests:** without a server: the PKI (each certificate verifies for its own use only), the command line (`buildArgs`), and that `Start` skips when `openvpn` is missing or the namespace is not there. With `//go:build linux && gopenvpn_server`: `TestStartStop` (the log has `Initialization Sequence Completed`; after cleanup the process is gone), for `udp`, `tcp`, `udp` with `--disable-dco` and the default options; two servers at once; `WaitLog` failing with the log.
- **Not in this step:** any client code.
- **Done when:** `scripts/check.sh` passes; the entry quotes the server's log lines.

### Step 1.4: packet formats
- **Goal:** `internal/wire` turns bytes into packet structs and back, safely.
- **Read:** SPEC §6, §7; draft sections "OpenVPN wire packet format", "General Control channel format", "Control channel wire packet structure", "Acknowledgements"; `ssl_pkt.h` (the opcode constants), `reliable.c` (`reliable_ack_read`, `reliable_ack_write`), `session_id.c`.
- **Facts:**
  - First byte: `opcode<<3 | keyID`. Opcodes: 3 `SOFT_RESET_V1`, 4 `CONTROL_V1`, 5 `ACK_V1`, 6 `DATA_V1`, 7 `HARD_RESET_CLIENT_V2`, 8 `HARD_RESET_SERVER_V2`, 9 `DATA_V2`, 10 `HARD_RESET_CLIENT_V3`, 11 `CONTROL_WKC_V1`. Any other opcode is refused.
  - A plain control packet after the first byte: own session id (8 bytes); ack count (1 byte, at most 8); that many packet ids (4 bytes each, big endian); the peer's session id (8 bytes, present only when the ack count is not 0); the packet id (4 bytes; `ACK_V1` has none); the payload (the rest; `ACK_V1` has none).
  - `DATA_V2` after the first byte: peer id (3 bytes, big endian), then the encrypted part. `DATA_V1` has no peer id.
  - Over TCP every packet has a 2-byte big-endian length before it, not counting itself.
- **Build:** `internal/wire/`:
  - `opcode.go`: `type Opcode uint8`, the constants, `IsControl()`, `IsData()`, `String()`; `SplitFirstByte(b byte) (Opcode, keyID uint8)`, `FirstByte(op Opcode, keyID uint8) byte`.
  - `control.go`: `type SessionID [8]byte`; `type Control struct { Opcode; KeyID uint8; SessionID; Acks []uint32; RemoteSessionID SessionID; PacketID uint32; Payload []byte }`; `ParseControlBody(op Opcode, body []byte) (Control, error)` for the part after the session id (the wraps of steps 1.5 to 1.7 put bytes between the session id and it); `AppendControlBody(dst []byte, c *Control) []byte`.
  - `stream.go`: `ReadFrame(r io.Reader, buf []byte) ([]byte, error)` and `AppendFrame(dst, packet []byte) []byte` for TCP.
  - Every parse error is tagged (`tagPacketTooShort`, `tagTooManyAcks`, `tagUnknownOpcode`, `tagFrameTooLarge`).
- **Tests:** table-driven round trips for every opcode; each error with its route test; `FuzzParseControlBody` and `FuzzReadFrame` (the property: no panic, and what parses re-encodes to the same bytes).
- **Not in this step:** any HMAC or encryption; any network I/O.
- **Done when:** the tests pass and each fuzz target ran 60 seconds with no finding.

### Step 1.5: the static key file, the replay id, and `tls-auth`
- **Goal:** control packets can be authenticated with a `tls-auth` key.
- **Read:** SPEC §7.1, §15; draft "HMAC authentication of control channel packets", "OpenVPN mixed timestamp/packet counter format", appendix "OpenVPN Static key file format"; `crypto.c` (`read_key_file`, `key_direction_state_init`), `ssl_pkt.c` (`swap_hmac`, `tls_wrap_control`, `read_control_auth`), `packet_id.c` (`packet_id_test`, `packet_id_add`).
- **Facts:**
  - The static key file is text: a line `-----BEGIN OpenVPN Static key V1-----`, 256 bytes as hexadecimal (any number of bytes per line), `-----END OpenVPN Static key V1-----`. Everything outside the two lines is ignored. The 256 bytes are four parts of 64: cipher key 0, HMAC key 0, cipher key 1, HMAC key 1.
  - `key-direction`: with no direction, both sides use HMAC key 0 for sending and receiving. With direction `1` (what a client normally has), the client sends with HMAC key 1 and receives with HMAC key 0. With `0`, the opposite. The HMAC key is the first N bytes of the 64, N being the output size of the hash (20 for SHA-1, 32 for SHA-256, 64 for SHA-512). SHA-1 is the default.
  - On the wire: first byte, own session id (8), HMAC (N bytes), replay packet id (4, big endian), time (4, big endian, seconds), then the control body of step 1.4.
  - The HMAC is computed over: replay packet id, time, first byte, own session id, control body, in that order (so: not the order on the wire).
  - The replay packet id starts at 1 and grows by one for every packet sent, retransmissions included. The time is the clock at the first packet sent, and stays the same in every packet after it (it only changes if the id ever wraps). The receiver treats (time, id) as one 64-bit counter with the time as the high half.
  - Receiving: verify the HMAC first, with `hmac.Equal`. Then check the counter against a window (OpenVPN's default: 64 ids back, 15 seconds). Accept it into the window only after the HMAC verified.
- **Build:**
  - `internal/keys/static.go`: `type StaticKey [256]byte`; `ParseStaticKey(r io.Reader) (*StaticKey, error)`; `type Direction int` (`Bidirectional`, `Normal`, `Inverse`); methods that return the cipher and HMAC key for sending and for receiving.
  - `internal/replay/window.go`: a sliding window over a 64-bit counter: `Check(id uint64) bool` (not a replay and not too old) and `Accept(id uint64)`. Write it as a bitmap, in your own way.
  - `internal/ctrlwrap/`: `type Wrapper interface { Wrap(dst []byte, first byte, sid wire.SessionID, body []byte) ([]byte, error); Unwrap(packet []byte) (body []byte, err error); Overhead() int }`; `NewPlain()`; `NewTLSAuth(key *keys.StaticKey, dir keys.Direction, newHash func() hash.Hash, now func() time.Time)`.
- **Tests:** a key made by `openvpn --genkey tls-auth` (checked in under `testdata/`, with a comment that it is a test key) parses; wrap then unwrap gives the body back for each hash and direction; one flipped bit anywhere is refused (`tagHMACMismatch`); a repeated packet is refused (`tagReplay`); route tests; `FuzzParseStaticKey`, `FuzzTLSAuthUnwrap`.
- **Not in this step:** `tls-crypt`; talking to a server (step 1.10 checks these bytes against the real one).
- **Done when:** the tests pass and the fuzz targets ran.

### Step 1.6: `tls-crypt`
- **Goal:** control packets can be encrypted and authenticated with a `tls-crypt` key.
- **Read:** SPEC §7.1; draft "Encrypting control channel packets (tls-crypt)"; `tls_crypt.c` (`tls_crypt_init_key`, `tls_crypt_wrap`, `tls_crypt_unwrap`), `tls_crypt.h` (the comment at the top and the `TLS_CRYPT_OFF_*` constants); OpenVPN's test `tests/unit_tests/openvpn/test_tls_crypt.c`.
- **Facts:**
  - The key file is the static key file of step 1.5. `tls-crypt` always uses direction: a client sends with cipher key 1 and HMAC key 1 and receives with cipher key 0 and HMAC key 0. The cipher key is the first 32 bytes (AES-256), the HMAC key the first 32 bytes (HMAC-SHA256).
  - On the wire: first byte (1), own session id (8), replay packet id (4), time (4), tag (32), ciphertext.
  - Tag = HMAC-SHA256(HMAC key, first byte ‖ session id ‖ replay packet id ‖ time ‖ plaintext). The plaintext is the control body of step 1.4.
  - Ciphertext = AES-256-CTR(cipher key, IV = the first 16 bytes of the tag, plaintext).
  - Receiving: decrypt with the IV from the received tag, compute the tag over the result, compare with `hmac.Equal`, and only then check the replay counter and use the plaintext.
- **Build:** `ctrlwrap.NewTLSCrypt(key *keys.StaticKey, now func() time.Time)`, the same `Wrapper` interface.
- **Tests:** the cases of `test_tls_crypt.c` that apply to wrap and unwrap, written as your own tests (it mostly checks round trips and refusals, with few fixed outputs: where it has a fixed output, use it); round trip with empty, short and maximum-size bodies; flipped bits in each field; replay; route tests; `FuzzTLSCryptUnwrap`. The byte-exact check against OpenVPN is step 1.10, where the real server must accept these packets.
- **Not in this step:** `tls-crypt-v2`.
- **Done when:** the tests pass.

### Step 1.7: `tls-crypt-v2`
- **Goal:** the client side of `tls-crypt-v2`: its key file, and the wrapped key that goes on two kinds of packet.
- **Read:** SPEC §7.1; `reference/openvpn/doc/tls-crypt-v2.txt` (all of it); draft "Client-specific encryption keys"; `tls_crypt.c` (`tls_crypt_v2_load_client_key`, `tls_crypt_v2_init_client_key`), `ssl_pkt.c` (`tls_wrap_control`), `ssl.c` (`parse_early_negotiation_tlvs`, `control_packet_needs_wkc`), `ssl_pkt.h` (`EARLY_NEG_*`, `TLV_TYPE_EARLY_NEG_FLAGS`).
- **Facts:**
  - The client key file is PEM with the label `OpenVPN tls-crypt-v2 client key`. Its bytes are `Kc` (256 bytes, used exactly like a `tls-crypt` key) followed by `WKc` (the wrapped key, opaque to the client).
  - `WKc` is appended, unencrypted, after the `tls-crypt` output of a `CONTROL_HARD_RESET_CLIENT_V3` packet and of a `CONTROL_WKC_V1` packet. No other packet carries it.
  - Early negotiation: with `tls-crypt-v2` the client's replay packet id counter starts at `0x0f000000` instead of 0, so its packets carry `0x0f000001`, `0x0f000002`, and so on (`tls_session_init` in `ssl.c`). The top byte `0x0f` in the reset packet tells the server that the client can resend `WKc`.
  - The server's `HARD_RESET_SERVER_V2` may then have a payload of TLVs: type (2 bytes), length (2 bytes), value. Type `0x0001` with length 2 is a flags field; bit `0x0001` means "send `WKc` again": the client's next packet (the one that acks the server's reset) must be `CONTROL_WKC_V1` instead of `CONTROL_V1` or `ACK_V1`.
  - A `CONTROL_WKC_V1` packet plus `WKc` must still fit the largest control packet (1250 bytes).
- **Build:** `internal/keys/tlscryptv2.go`: `ParseTLSCryptV2ClientKey(r io.Reader) (*TLSCryptV2ClientKey, error)` with `Kc *StaticKey` and `WKc []byte`; `ctrlwrap.NewTLSCryptV2(key, now)`, which appends `WKc` for the two opcodes; `wire.ParseEarlyNegotiation(payload []byte) (resendWKc bool, err error)`.
- **Tests:** a key made by `openvpn --genkey tls-crypt-v2-server` and `--genkey tls-crypt-v2-client` (under `testdata/`, marked as test keys) parses; the two opcodes carry `WKc` and no other does; the TLV parser with unknown types, short input, wrong length; route tests; fuzz targets for the key file and the TLV.
- **Not in this step:** dynamic `tls-crypt` (step 2.9).
- **Done when:** the tests pass.

### Step 1.8: the reliability layer
- **Goal:** `internal/reliable` delivers control payloads in order over a link that loses, repeats and reorders packets.
- **Read:** SPEC §7.2, §16; draft "Message Packet IDs", "Acknowledgements"; `reliable.h` (the comments and constants), `reliable.c` (`reliable_send`, `reliable_send_purge`, `reliable_mark_active_incoming`, `reliable_wont_break_sequentiality`, `copy_acks_to_mru`, `reliable_ack_write`).
- **Facts:**
  - Each side numbers its control packets 0, 1, 2, ... with no gaps. A retransmission has the same id. `ACK_V1` packets have no id and are never acked.
  - The sender keeps at most 6 packets that are sent and not yet acked. The receiver keeps at most 12 packets that arrived ahead of the next expected one, and drops a packet further ahead.
  - Acks name single ids (no "everything up to n"). An `ACK_V1` carries up to 8; other control packets may carry acks too. To make lost acks harmless, OpenVPN repeats recently acked ids in later packets while there is room; do the same.
  - Retransmission: 2 seconds after sending, then the wait doubles each time, up to 128 seconds. Also at once when three packets sent later were acked and this one was not.
  - The peer's session id that goes with the acks is the one learned from the peer's first packet.
- **Build:** `internal/reliable/`, with no I/O and no goroutine: a type the session drives. Suggested shape:
  - `type Sender`: `CanSend() bool`; `Queue(op wire.Opcode, payload []byte) (id uint32)`; `Ack(id uint32)`; `Due(now time.Time) []Outgoing` (what must be sent or resent now); `NextDeadline() (time.Time, bool)`.
  - `type Receiver`: `Receive(id uint32, payload []byte) (deliver [][]byte, accepted bool)` (returns the payloads that are now in order); `PendingAcks(max int) []uint32`.
  - Timing takes `now` as a parameter; the tests give it.
- **Tests:** table-driven, with a scripted link: in order; loss of each single packet; duplicates; reordering inside and beyond the window; lost acks; the retransmission times (2, 4, 8, ... up to 128 seconds); the fast retransmission after three later acks; the send window of 6 blocks the seventh packet. Property test: with a random link (fixed seeds), every payload is delivered exactly once, in order.
- **Not in this step:** sockets, goroutines, TLS.
- **Done when:** the tests pass under `-race`.

### Step 1.9: `Conn`, the in-process peer, and the three-way handshake
- **Goal:** `openvpn.Client` and `openvpn.PacketClient` exist and complete the reset exchange with a peer inside the test process.
- **Read:** SPEC §4.1, §5, §7.3, §14.2, §16; draft "[OPCODE ID 7]", "[OPCODE ID 8]", "[OPCODE ID 10]"; `ssl.c` (`tls_session_init`, `session_move_pre_start`, `tls_process_state`), `wip/control_channel.txt` in `reference/openvpn-rfc` ("Session establishment").
- **Facts:**
  - Client → server: `HARD_RESET_CLIENT_V2` (`V3` with `tls-crypt-v2`), key id 0, a random session id, no acks, packet id 0, no payload.
  - Server → client: `HARD_RESET_SERVER_V2`, the server's session id, an ack for id 0 with the client's session id, packet id 0.
  - Client → server: an ack for the server's id 0 (in an `ACK_V1`, on the first `CONTROL_V1`, or in a `CONTROL_WKC_V1` when step 1.7's flag asks). Then TLS bytes travel in `CONTROL_V1` packets (step 1.11).
  - A packet with a session id that is not the peer's is dropped. A packet that fails its wrap is dropped. Neither ends the connection (SPEC §15 rule 7).
- **Build:**
  - `internal/vpntest/link.go`: an in-memory datagram link, a pair of `net.Conn` with message boundaries, with optional loss, duplication and reordering from a seed; and a stream pair (`net.Pipe`).
  - `internal/vpntest/server.go`: a small server side made of the packages of steps 1.4 to 1.8: it answers the reset and (from step 1.11) runs TLS. It exists so that unit tests need no `openvpn`. It can be told to misbehave (stay silent, answer with a wrong session id, send a bad wrap).
  - Package `openvpn`: `Config` (the fields this step needs: `ControlWrap`, `HandshakeTimeout`, `Logger`), `ControlWrap` with `NewTLSAuth`, `NewTLSCrypt`, `NewTLSCryptV2`, `Client`, `PacketClient`, `Conn` with `HandshakeContext`, `Close`, `LocalAddr`, `RemoteAddr`, `NetConn`. Inside: one goroutine that reads the link, a mutex-protected state, timers from the `time` package. `HandshakeContext` returns after the reset exchange for now.
  - `internal/session` may be one package or folded into `openvpn`; choose what keeps the public package small.
  - Exported tags: `TagHandshakeTimeout`, `TagLinkFailed`.
- **Tests** (with `testing/synctest`, no real sleeping): the handshake completes over the datagram link and over the stream link, with each of the four wraps; with 30% loss it still completes; a silent server gives `TagHandshakeTimeout` after `HandshakeTimeout`; a cancelled context returns an error for which `errors.Is(err, context.Canceled)` is true; a wrong session id is ignored; after `Close`, no goroutine of the connection runs (compare `runtime.NumGoroutine` before and after, inside the synctest bubble) and `HandshakeContext` returns `net.ErrClosed`; route tests.
- **Not in this step:** `Dial`, `Dialer` (step 1.10); TLS; `Read` and `Write`.
- **Done when:** the tests pass under `-race`.

### Step 1.10: the handshake against the real server
- **Goal:** `openvpn.Dial` reaches the real server and the reset exchange works with every wrap, over UDP and TCP.
- **Read:** SPEC §4.1, §6, §17; `reference/openvpn/doc/man-sections/tls-options.rst` (`--tls-auth`, `--tls-crypt`, `--tls-crypt-v2`).
- **Facts:**
  - Server options for the wraps: `--tls-auth ta.key 0`, `--tls-crypt tc.key`, `--tls-crypt-v2 server.key`. The key files are made with `openvpn --genkey tls-auth ta.key`, `--genkey tls-crypt tc.key`, `--genkey tls-crypt-v2-server server.key`, `--tls-crypt-v2 server.key --genkey tls-crypt-v2-client client.key`.
  - The server answers a first reset **statelessly** (an HMAC based reset challenge) and keeps no state, so it logs nothing for it at `--verb 4`; at `--verb 7` it logs `Reset packet from client, sending HMAC based reset challenge`. The line `TLS: Initial packet from ...` (the start of TLS) comes only after the client has sent its third packet, the one that acks the server's reset. With a wrong key the server answers nothing and logs, at `--verb 7`, `Authenticate/Decrypt packet error: packet HMAC authentication failed` and `TLS Error: incoming packet authentication failed from ...`. A server started by `internal/servertest` takes `--verb 7` through `Options.Extra`.
- **Build:** `Dial` and `Dialer` (SPEC §4.1): `network` is `udp`, `udp4`, `udp6`, `tcp`, `tcp4`, `tcp6`; UDP uses a connected socket and `PacketClient`, TCP uses `Client`. `internal/servertest`: helpers that make the key files with the real `openvpn` and add the server options.
- **Tests** (`//go:build linux && gopenvpn_server`): a table of {udp, tcp} × {no wrap, `tls-auth` SHA-1, `tls-auth` SHA-256, `tls-crypt`, `tls-crypt-v2`}: `Dial` with a context of 10 seconds gets past the reset exchange (the third packet is sent) and the server's log has `TLS: Initial packet from`. One case with a wrong `tls-crypt` key: `TagHandshakeTimeout`, and the server's log (verb 7) says why.
- **Not in this step:** TLS (the test stops after the reset exchange; give the test a way to stop there, for example an unexported hook, not an exported option).
- **Done when:** every row of the table passes; the entry quotes one server log line per wrap.

### Step 1.11: TLS over the control channel
- **Goal:** the TLS handshake completes with the real server.
- **Read:** SPEC §8.1, §15; draft "Control message framing", "[OPCODE ID 4] CONTROL_V1"; `ssl.c` (`write_outgoing_tls_ciphertext`, `read_incoming_tls_ciphertext`).
- **Facts:**
  - TLS runs as a client over the control channel. The TLS bytes are the payloads of `CONTROL_V1` packets, in order. They are cut so that no packet is over 1250 bytes with its wrap; the receiver just concatenates the payloads.
  - Go's `crypto/tls` needs a `net.Conn`. Give it an internal one whose `Write` queues bytes into the reliability layer (blocking while the send window is full) and whose `Read` returns the bytes the reliability layer delivered.
  - `tls.Config`: `MinVersion: tls.VersionTLS12`. Leave `NextProtos` empty. OpenVPN servers do not need SNI; set `ServerName` only for certificate verification.
  - The test server requires a client certificate (step 1.3): the client's `tls.Config` has `Certificates: []tls.Certificate{pki.ClientCert}`.
  - Verifying an OpenVPN server certificate is usually not by host name: the tests verify against the CA and check the certificate's extended key usage. Use `tls.Config.VerifyConnection` or `VerifyPeerCertificate` with `InsecureSkipVerify` only in the helper that builds such a config, and verify the chain yourself there with `x509.Certificate.Verify`. Never leave a path where nothing is verified.
- **Build:** the internal `net.Conn` adapter; `Config.TLS`; `HandshakeContext` now finishes after `tls.Conn.HandshakeContext`; `ConnectionState().TLS`; exported tag `TagTLSHandshakeFailed`; a helper in `openvpn` that builds the verifying `tls.Config` from a CA pool and options (step 3.2 uses it for profiles).
- **Tests:** unit (with `internal/vpntest` running `crypto/tls` as the server): TLS 1.3 and 1.2 complete, also with 30% loss; a server certificate from another CA gives `TagTLSHandshakeFailed`. Real server: TLS 1.3 completes and the log has `Control Channel: TLSv1.3`; with `--tls-version-max 1.2` on the server it completes with 1.2; a client that trusts another CA gets `TagTLSHandshakeFailed`.
- **Not in this step:** anything inside TLS (the key exchange message is step 2.1). After TLS completes, the real server waits for that message; the test ends there.
- **Done when:** the tests pass; the entry quotes the server's `Control Channel:` lines.
- **Finishes M1:** tag `v0.1.0` on the merged commit (rule 5), then start step 2.1.

---

## M2: the tunnel (tag `v0.2.0`)

Result: `openvpn.Dial` returns a `*Conn` that carries IP packets to and from the real server and lives through renegotiations.

### Step 2.1: the key exchange message and the peer info
- **Goal:** after TLS, the client sends its key exchange message, reads the server's, and the server accepts the client's credentials.
- **Read:** SPEC §8.2; draft "Key exchange message", "Peerinfo"; `ssl.c` (`key_method_2_write`, `key_method_2_read`, `push_peer_info`, `write_string`, `key_source2_randomize_write`), `ssl.h` (the `IV_PROTO_*` constants).
- **Facts:**
  - To run clients with a user name and password and no client certificate, start the server with `--verify-client-cert none --auth-user-pass-verify <script> via-file --script-security 2 --username-as-common-name` through `Options.Extra`; the server refuses `--verify-client-cert none` alone. With a client certificate (the default of the test server) the user name and password may be sent as well.
  - Each control message is written to TLS in one `Write` (one TLS record).
  - The client's message, in order: 4 zero bytes; 1 byte `2`; 48 random bytes; 32 random bytes; 32 random bytes; then four strings: the options string, the user name, the password, the peer info. A string is: length (2 bytes, big endian, **counting the NUL at the end**), the bytes, a NUL. An absent user name or password is the empty string: length 1 and one NUL byte.
  - The server's message is the same without the 48 random bytes.
  - The random bytes are not used by this library (the data keys come from the TLS exporter, step 2.4) but must be random.
  - The options string is a comma-separated description of the configuration, e.g. `V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client`. The server only compares it and warns. Find what the real client sends by running `openvpn` as a client against the test server with `--verb 7` and reading both logs; send the same form with this library's values (SPEC §20, V1).
  - The peer info is lines `NAME=value\n`. OpenVPN's client sends `IV_VER`, `IV_PLAT` (`linux`, `win`, `mac`), `IV_TCPNL=1`, `IV_MTU`, `IV_NCP=2` (when both AES-128-GCM and AES-256-GCM are offered), `IV_CIPHERS` (colon-separated), `IV_PROTO` (a decimal number, the sum of the bits).
  - `IV_PROTO` bits: 1 `DATA_V2` (value 2), 2 request push (4), 3 TLS exporter (8), 4 `AUTH_PENDING` keywords (16), 7 exit in the control channel (128), 8 `AUTH_FAILED,TEMP` (256), 9 dynamic `tls-crypt` (512), 10 epoch format (1024), 11 `dns` option (2048). In this step send bits 1, 2 and 3 only. Each later step adds its bit when it implements the feature.
  - `IV_VER` and `IV_PLAT`: SPEC §8.2 says they are decided here. Try `IV_VER=` the version of this library with a prefix that cannot be mistaken for OpenVPN's (for example `gopenvpn-conn 0.2.0`), check in the server's log that it accepts it and still pushes `key-derivation`/`protocol-flags` in step 2.2, and write the result in SPEC §8.2 and §21. If the server needs a number at the start, ask the owner before imitating OpenVPN's own version.
- **Build:** `internal/ctrlmsg/keyexchange.go`: `AppendClientKeyExchange(dst []byte, m *ClientKeyExchange) ([]byte, error)`, `ParseServerKeyExchange(b []byte) (*ServerKeyExchange, error)`; `peerinfo.go`; `Config.Credentials`, `Config.DataCiphers`, `Config.PeerInfo`; `type Credentials struct{ Username, Password string }`. Passwords are never logged and never put in error metadata.
- **Tests:** unit: byte-exact encoding against a hand-written expected value; the string rules (NUL counted; too long refused); `FuzzParseServerKeyExchange`. Real server: with `--auth-user-pass-verify <script> via-file --script-security 2 --username-as-common-name` and a script that accepts one user and password, the server's log shows `peer info: IV_PROTO=...` and the user name it authenticated; with a wrong password the server sends `AUTH_FAILED` (the client surfaces it as `TagAuthFailed` in step 2.3; here it is enough that the test sees the server's log line).
- **Not in this step:** reading `PUSH_REPLY`; data keys.
- **Done when:** the tests pass; the entry quotes the `peer info` lines from the server's log.

### Step 2.2: `PUSH_REQUEST`, `PUSH_REPLY` and `ConnectionState`
- **Goal:** the client asks for its settings and exposes what the server pushed.
- **Read:** SPEC §4.1, §9; draft "PUSH_REQUEST", "PUSH_REPLY", "Pushed configuration options"; `push.c` (`send_push_request`, `incoming_push_message`, `process_incoming_push_msg`, `process_incoming_push_reply`), `forward.c` (`check_push_request`); `reference/openvpn/doc/man-sections/vpn-network-options.rst` and `client-options.rst` for the meaning of each option.
- **Facts:**
  - Text messages are one TLS record each, ending with a NUL byte.
  - The client sends `PUSH_REQUEST` after the key exchange and again every 5 seconds until a reply arrives.
  - The reply is `PUSH_REPLY,option,option,...`. A long reply comes in parts: a part that ends with `push-continuation 2` is followed by more; the last part ends with `push-continuation 1` (or has none).
  - Options and their arguments are separated by spaces, e.g. `ifconfig 10.8.0.2 255.255.255.0`, `route-gateway 10.8.0.1`, `topology subnet`, `ping 10`, `ping-restart 60`, `peer-id 0`, `cipher AES-256-GCM`, `protocol-flags cc-exit tls-ekm dyn-tls-crypt`, `tun-mtu 1500`, `dhcp-option DNS 10.8.0.1`, `ifconfig-ipv6 fd00::1000/64 fd00::1`.
  - With `topology subnet`, `ifconfig` is address then netmask. With `net30` or `p2p` it is local address then peer address.
- **Build:** `internal/ctrlmsg/push.go`: the splitter of parts, the option tokenizer, and one table that maps each option name to "used", "ignored" or "refused" (SPEC §9) with its parser; `ConnectionState` and `Route` (SPEC §4.1, with `net/netip` types); `HandshakeContext` now returns when the reply has been processed; exported tag `TagUnsupportedPushedOption` (metadata `option`).
- **Tests:** unit, table-driven, one row per option of the "used" group, including malformed arguments (tagged error, with a route test); the multi-part reply; an unknown option is kept in `PushedOptions` and logged; `compress lz4` is refused; `FuzzParsePushReply`. Real server: with `--push "route 192.168.50.0 255.255.255.0"`, `--push "dhcp-option DNS 10.8.0.1"`, `--keepalive 10 60` and `--server-ipv6 fd00::/64`, `ConnectionState` has the addresses (IPv4 and IPv6), the gateway, the route, the DNS server and the ping timers; a server with enough `--push` options to need two parts.
- **Not in this step:** using the options (data keys are step 2.4, ping is step 2.7).
- **Done when:** the tests pass.

### Step 2.3: the messages that end a session
- **Goal:** `AUTH_FAILED`, `HALT`, `RESTART` and `AUTH_PENDING` are understood.
- **Read:** SPEC §9, §14.2, §14.3; draft "AUTH_FAILED", "RESTART and HALT", "AUTH_PENDING"; `push.c` (`receive_auth_failed`, `server_pushed_signal`, `receive_auth_pending`, `parse_auth_pending_keywords`).
- **Facts:**
  - `AUTH_FAILED`, `AUTH_FAILED,message`, `AUTH_FAILED,SESSION:message`, `AUTH_FAILED,TEMP:message`, `AUTH_FAILED,TEMP[backoff 42,advance no]:message`.
  - `HALT,message` and `RESTART,message`; after the comma, `RESTART` may have flags in square brackets (`[P]`, `[N]`, `[PN]`).
  - `AUTH_PENDING` or `AUTH_PENDING,timeout 120`: the server needs more time; the client keeps waiting, up to that timeout and never past the context of the handshake.
- **Build:** parsers in `internal/ctrlmsg/`; the session ends with `TagAuthFailed` (metadata: `reason`, `temporary`, `backoff` in seconds, `advance`), `TagServerHalt` (`reason`), `TagServerRestart` (`reason`, `flags`). Add `IV_PROTO` bits 4 and 8.
- **Tests:** unit: each form, with `internal/vpntest` sending it during the handshake and after it; the error is the same value from every later call (SPEC §14.2); route tests. Real server: a wrong password gives `TagAuthFailed`.
- **Not in this step:** reconnecting; answering a challenge.
- **Done when:** the tests pass.

### Step 2.4: data keys and the data channel, in memory
- **Goal:** `internal/datachan` encrypts and decrypts data packets with keys from the TLS exporter. No sockets yet.
- **Read:** SPEC §8.3, §10, §15; draft "OpenVPN Key", "Data channel key generation", "AEAD encrypted data channel packet", "Replay protection"; `ssl.c` (`generate_key_expansion_tls_export`, `init_key_contexts`), `crypto.c` (`openvpn_encrypt_aead`, `openvpn_decrypt_aead`, `key_ctx_update_implicit_iv`, `crypto_check_replay`), `ssl_ncp.c` (`check_pull_client_ncp`); OpenVPN's test `tests/unit_tests/openvpn/test_crypto.c`.
- **Facts:**
  - Key material: `tls.ConnectionState.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)`. It fails unless the TLS session is 1.3 or has Extended Master Secret; then the session ends with a tag.
  - The 256 bytes are four parts of 64, in this order: cipher key client→server, HMAC key client→server, cipher key server→client, HMAC key server→client. The client encrypts with the first pair and decrypts with the second.
  - The AEAD key is the first 16, 24 or 32 bytes of the cipher key (AES-128/192/256-GCM) or 32 (CHACHA20-POLY1305). The implicit IV is the first 8 bytes of the HMAC key.
  - The server must have pushed `key-derivation tls-ekm` or `protocol-flags` containing `tls-ekm`; otherwise `TagKeyDerivationUnsupported`. The pushed `cipher` must be one the client offered; otherwise `TagCipherNegotiationFailed`.
  - `DATA_V2` packet: first byte (`9<<3 | keyID`), peer id (3 bytes), packet id (4 bytes, big endian), tag (16 bytes), ciphertext.
  - Nonce (12 bytes): packet id (4 bytes) then the implicit IV (8 bytes). Additional data: first byte, peer id, packet id (8 bytes in all). Go's `AEAD.Seal` returns ciphertext then tag: move the tag in front.
  - `DATA_V1` (when no `peer-id` was pushed): first byte (`6<<3 | keyID`), packet id, tag, ciphertext; the additional data is the packet id only.
  - Packet ids start at 1 and grow by one. The receiver uses the window of step 1.5 (64 back, 15 seconds) and accepts an id into the window only after the packet authenticated.
- **Build:** `internal/keys/datakeys.go` (the split of the 256 bytes); `internal/datachan/`: `type Cipher` (name, key size, constructor); `NewSender`, `NewReceiver` with `Seal(dst, plaintext []byte) ([]byte, error)` and `Open(dst, packet []byte) ([]byte, error)` that reuse buffers; counters of dropped packets by reason. Add `golang.org/x/crypto` for `chacha20poly1305`.
- **Tests:** round trip for the four ciphers, `DATA_V1` and `DATA_V2`; a known-answer test built from `test_crypto.c`'s AEAD vectors if it has fixed ones (if it only does round trips, say so in the entry and rely on step 2.5); a flipped bit in each field is refused; a replay is refused; the packet id never repeats; a benchmark with `ReportAllocs` showing zero allocations per packet for `Seal` and `Open`; `FuzzOpen`.
- **Not in this step:** the epoch format (step 2.6); `Conn.Read`/`Write` (step 2.5).
- **Done when:** the tests pass.

### Step 2.5: IP packets through the real server
- **Goal:** `Conn.Read` and `Conn.Write` carry IP packets.
- **Read:** SPEC §4.1, §5.1, §10; `forward.c` (`process_incoming_link_part2`, `process_outgoing_tun`: only to see what is done to a packet around encryption).
- **Facts:**
  - What is encrypted is the IP packet itself, with nothing before it (no compression byte, because compression is refused).
  - The server answers ICMP echo requests sent to its tunnel address (`10.8.0.1` with `--server 10.8.0.0 255.255.255.0`).
  - A decrypted packet that is exactly the 16 ping bytes of step 2.7 is not an IP packet; until step 2.7, drop it.
- **Build:** `Conn.Read`, `Conn.Write` (message semantics, SPEC §5.1), `ConnectionState().Cipher`, `PeerID`, `MTU`; `internal/vpntest/ippkt.go`: helpers that build and parse an IPv4 ICMP echo with correct checksums.
- **Tests:** unit, with `internal/vpntest` echoing packets: write then read; a buffer smaller than the packet; a packet larger than the MTU is refused with a tag. Real server: a table of {udp, tcp} × {AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305} × {DCO, `--disable-dco`}: an echo request written to the `Conn` is answered within 2 seconds, 100 times in a row. If the kernel data channel cannot work inside the namespace, say so in SPEC §21 and run those rows with `--disable-dco` only.
- **Not in this step:** deadlines and the error contract (step 2.8).
- **Done when:** the table passes; the entry has the server's log line that names the data cipher.

### Step 2.6: the epoch data format
- **Goal:** the newer AEAD format with 64-bit packet ids and epoch keys.
- **Read:** SPEC §10; draft "OpenVPN epoch data channel keys" (all of its subsections), "AEAD encrypted data channel packet with extended packet id and epoch keys"; `crypto_epoch.c` (all of it; it is short), `crypto.c` (the epoch branches of `openvpn_encrypt_aead` and `openvpn_decrypt_aead`), `ssl.c` (`init_epoch_keys`, `should_trigger_renegotiation`).
- **Facts:**
  - Used when the server's `protocol-flags` has `aead-epoch`. The client offers it with `IV_PROTO` bit 10.
  - The epoch 1 key of each direction is the first 32 bytes of that direction's cipher key from step 2.4.
  - `OVPN-Expand-Label(secret, label, context, length)` is HKDF-Expand with SHA-256 over the info: length (2 bytes), a byte with the length of `"ovpn " + label`, those bytes, a byte with the length of the context, the context. Use `crypto/hkdf`.
  - Next epoch key: `OVPN-Expand-Label(E_n, "datakey upd", "", 32)`. Data key of an epoch: `OVPN-Expand-Label(E_n, "data_key", "", key size)`. Implicit IV: `OVPN-Expand-Label(E_n, "data_iv", "", 12)`.
  - Packet: first byte, peer id (3), packet id (8 bytes: epoch in the high 16 bits, counter in the low 48), ciphertext, tag (16 bytes, **at the end**). Nonce: the 8 packet id bytes followed by 4 zero bytes, XORed with the 12-byte implicit IV. Additional data: first byte, peer id, packet id.
  - The sender moves to the next epoch before its usage limit: for AES-GCM, when the packets sent plus the 16-byte blocks encrypted reach 2^36 − 1 (OpenVPN moves earlier, with a margin; use its margin); CHACHA20-POLY1305 has no such limit, only the 48-bit counter.
  - The receiver keeps the current epoch's key, the previous one, and a window of future ones (16 in OpenVPN 2.7.9's tests; confirm the default in `crypto_epoch.c` and `ssl.c`). A packet from an epoch further ahead is dropped. After a packet of a higher epoch authenticates, the receiver moves forward and the sender follows to at least that epoch.
  - When the send epoch reaches `0xF000`, a renegotiation is due (step 2.9).
- **Build:** `internal/keys/epoch.go`; the epoch sender and receiver in `internal/datachan/`, behind the same interface as step 2.4; a test-only way to set a small usage limit.
- **Tests:** the fixed vectors of `test_crypto.c` for `ovpn_expand_label` and the epoch keys; round trips; moving through 20 epochs with a small limit, with reordered packets across the boundary, losing none; a far-future epoch is dropped; replay per epoch. Real server: the echo test of step 2.5 with the server's log showing the epoch format in use.
- **Not in this step:** renegotiation.
- **Done when:** the tests pass.

### Step 2.7: keepalive
- **Goal:** an idle tunnel stays up, and a dead one is noticed.
- **Read:** SPEC §11.1; `ping.c`; `reference/openvpn/doc/man-sections/link-options.rst` (`--ping`, `--ping-restart`, `--keepalive`).
- **Facts:**
  - The ping is a data packet whose plaintext is these 16 bytes: `2a 18 7b f3 64 1e b4 cb 07 ed 2d 0a 98 1f c7 48`.
  - Send one when nothing was sent on the link for `PingInterval`. A received ping is dropped after it counts as "something was received".
  - When nothing authentic was received for `PingTimeout`, the session ends with `TagPingTimeout`.
  - The values come from the pushed `ping` and `ping-restart`; `Config.PingInterval` and `Config.PingTimeout` apply when the server pushes none. Zero means off.
- **Build:** the two timers in the session; `Config.PingInterval`, `Config.PingTimeout`; `TagPingTimeout`.
- **Tests:** unit under `testing/synctest`: pings are sent at the interval only when idle; a ping is not returned by `Read`; silence for `PingTimeout` gives `TagPingTimeout` from `Read` and `Write`; route test. Real server with `--keepalive 1 3`: an idle `Conn` is still usable after 10 seconds; when the test kills the server, `Read` returns `TagPingTimeout` within 5 seconds.
- **Done when:** the tests pass.

### Step 2.8: `Close`, exit, deadlines and the error contract
- **Goal:** `*Conn` behaves as SPEC §5 says a `net.Conn` does.
- **Read:** SPEC §5 (all of it), §11.2, §14.2, §16; draft "EXIT"; `sig.c` (`process_explicit_exit_notification_init`), `push.c` (`receive_exit_message`), `occ.c` and `occ.h` (the exit message of the data channel).
- **Facts:**
  - When the server's `protocol-flags` has `cc-exit` (the client offers it with `IV_PROTO` bit 7), `Close` sends the control message `EXIT`.
  - Otherwise, over UDP only, the older notification is a data packet whose plaintext is the 16 bytes `28 7f 34 6b d4 ef 7a 81 2d 56 b8 d3 af c5 45 9c` followed by one byte `06`.
  - The server sends `EXIT` when it shuts down and `cc-exit` is on: `Read` then returns `io.EOF`.
  - `Close` must not hang: bound the wait for the `EXIT` to be acked (1 second), then close the link.
- **Build:** `Close`; `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`; the table of SPEC §5.3 exactly: `io.EOF`, `net.ErrClosed`, `os.ErrDeadlineExceeded` returned as those values, not wrapped.
- **Tests:** unit: each row of the SPEC §5.3 table compared with `==`; `errors.As(err, &netErr)` and `netErr.Timeout()` for the deadline; a deadline set in the past unblocks a `Read` in progress; `Read`, `Write` and `Close` from many goroutines under `-race`; `Close` twice; no goroutine left after `Close`; `io.Copy(io.Discard, conn)` returns `nil` when the server sends `EXIT`. Real server: after `Close`, the server's log shows the client's exit within 2 seconds (not after its ping timeout); stopping the server gives `io.EOF`.
- **Done when:** the tests pass.

### Step 2.9: renegotiation
- **Goal:** the session replaces its keys without losing packets.
- **Read:** SPEC §7.1 (dynamic `tls-crypt`), §11.3; draft "[OPCODE ID 3] CONTROL_SOFT_RESET_V1", "Data channel key rotation"; `ssl.c` (`key_state_soft_reset`, `tls_session_soft_reset`, `should_trigger_renegotiation`, `lame_duck_must_die`, `auth_deferred_expire_window`, `tls_select_encryption_key`, `tls_get_limit_aead`), `tls_crypt.c` (`tls_session_generate_dynamic_tls_crypt_key`), `auth_token.c` (the client side only: how the token replaces the password).
- **Facts:**
  - Either side starts with `CONTROL_SOFT_RESET_V1` carrying the next key id: 0 is only the first session; then 1, 2, ..., 7, then 1 again. The other side answers with its own `SOFT_RESET_V1`. Under that key id, a new reliability state (packet ids from 0), a new TLS handshake, and the key exchange of step 2.1 run. No `PUSH_REQUEST` is sent; the pushed options stay.
  - While it runs, data keeps flowing under the old key id. Both sides must handle control packets of two key ids at once.
  - When the new session is ready, its data keys are installed for **decryption** at once. The client starts **encrypting** with them after a delay: the smaller of the handshake window (60 seconds) and half of `RenegotiateAfter`.
  - The old key stays for decryption until it is retired: OpenVPN's transition window is 3600 seconds by default; a still newer key replaces it earlier.
  - It is due: `RenegotiateAfter` after the current key was established (3600 seconds by default); when a 32-bit packet id reaches `0xFF000000`; for AES-GCM without the epoch format, when packets plus blocks reach 7/8 of 2^36 − 1, counted for each direction; with the epoch format, when the send epoch reaches `0xF000`.
  - If the server pushed `auth-token`, the client sends the token as the password in renegotiations (and the pushed `auth-token-user`, base64, as the user name if there was one) and does not call `Credentials` again.
  - With `dyn-tls-crypt` in `protocol-flags` (the client offers `IV_PROTO` bit 9), the control packets of renegotiated sessions are wrapped in `tls-crypt` form with a key made from the TLS exporter: 256 bytes for the label `EXPORTER-OpenVPN-dynamic-tls-crypt`, laid out like a static key, XORed byte by byte with the configured `tls-auth` or `tls-crypt` key data when there is one, and used with the client's direction (as in step 1.6), with a fresh replay counter. Read `tls_session_generate_dynamic_tls_crypt_key` and `xor_key2` in `tls_crypt.c`, and find in `ssl.c` which TLS session's exporter is used and from which packet on the new wrap applies; write both in your own words in SPEC §7.1.
- **Build:** key slots in the session (active, retiring, next); the second control channel state by key id; `Config.RenegotiateAfter`; the triggers; a test-only way to lower the limits and the delay.
- **Tests:** unit under `testing/synctest`: the client starts it; the server starts it; both at once; the key id sequence 0, 1, ..., 7, 1; a stream of packets across it with none lost; a failed renegotiation is retried and, when the old key expires, the session ends with its tag; the auth token replaces the password. Real server with `--reneg-sec 3`: a stream of 10 echo packets a second for 40 seconds loses none; the same with the client's `RenegotiateAfter` at 3 seconds and the server's at its default; with `tls-crypt` and `tls-crypt-v2` so that the dynamic key is used (the server's log says so).
- **Not in this step:** reconnecting after the session ended.
- **Done when:** the tests pass; the entry quotes the server's renegotiation log lines.

### Step 2.10: the public API, examples and documentation
- **Goal:** package `openvpn` is ready for users.
- **Read:** SPEC §4.1, §16; the documentation of `crypto/tls` (as the model for doc comments).
- **Build:** review every exported identifier against SPEC §4.1 and fix either the code or the SPEC; doc comments on all of them; `example_test.go` with `ExampleDial` (compiled, not run: no server); `examples/ping/main.go` (flags: server address, CA, certificate, key; sends an ICMP echo through the tunnel and prints the reply); a benchmark of `Conn.Write`/`Conn.Read` through `internal/vpntest` with `ReportAllocs`.
- **Tests:** a test that fails when an exported identifier of the module has no doc comment (with `go/doc`); the leak test of SPEC §17: 200 connections opened and closed, goroutines and heap back to the start.
- **Done when:** the tests pass; `examples/ping` builds for the three systems and works against the real server (run it once inside `scripts/vpn-ns.sh` by hand with a server started by a small test helper, and put its output in the entry); the benchmark shows 0 allocations per packet.
- **Finishes M2:** tag `v0.2.0` on the merged commit (rule 5), then start step 3.1.

---

## M3: profiles and the userspace network (tag `v0.3.0`)

Result: a program gives a `.ovpn` file and does `http.Get` through the VPN, with no root.

### Step 3.1: the grammar of profiles
- **Goal:** `ovpn` turns the text of a profile into a list of options with their arguments.
- **Read:** SPEC §12, §15 rule 11; `options_parse.c` (`parse_line`, `read_config_file`, `check_inline_file`); `reference/openvpn/doc/man-sections/inline-files.rst`; OpenVPN's test `tests/unit_tests/openvpn/test_options_parse.c`.
- **Facts:**
  - One option per line: a name and arguments separated by spaces or tabs. A leading `--` on the name is allowed. A line whose first non-space character is `#` or `;` is a comment; a `#` or `;` later on a line also starts a comment unless it is inside quotes.
  - Double quotes group words and allow backslash escapes (`\\`, `\"`, `\ `). Single quotes group words with no escapes. Outside quotes a backslash escapes the next character.
  - Inline file: a line `<name>`, then lines, then `</name>`. The text between is the argument of option `name`.
  - `<connection>` ... `</connection>` holds options for one remote.
- **Build:** `ovpn/lex.go`: `type Line struct { Name string; Args []string; Inline string; LineNo int }`; a tokenizer over `io.Reader` with a limit on line length and on total size; `TagSyntax` (metadata `line`).
- **Tests:** table-driven from the cases of `test_options_parse.c` plus: unterminated quote; unterminated inline block; CRLF line ends; a UTF-8 byte order mark; a very long line; `FuzzLex`.
- **Not in this step:** what the options mean.
- **Done when:** the tests pass.

### Step 3.2: options to `Config`
- **Goal:** `ovpn.Parse` and `ovpn.ParseFS` return a `Profile` with a usable `*openvpn.Config`.
- **Read:** SPEC §4.2, §12; the `doc/man-sections/*.rst` entry of every option in the tables of SPEC §12; `options.c` only where the man page leaves a question (search for the option's name in `add_option`).
- **Facts:**
  - `remote host [port] [proto]`; the defaults come from `port` (1194) and `proto` (`udp`). Several `remote` lines are tried in order; `remote-random` shuffles them.
  - `tls-auth file [direction]`, or `<tls-auth>` inline with a separate `key-direction`.
  - `auth-user-pass [file]`: the file has the user name on the first line and the password on the second.
  - `remote-cert-tls server`: the server certificate must have the extended key usage "TLS Web Server Authentication". `verify-x509-name name [type]`: `type` is `subject` (the whole subject), `name` (the common name; the default), or `name-prefix`. `peer-fingerprint`: SHA-256 fingerprints of the server certificate, with `:` between bytes.
  - `data-ciphers` is colon-separated. `cipher X` adds X to the offer when X is an AEAD cipher this library has.
  - `setenv opt name args...` means: apply the option if it is known, ignore it if not. `ignore-unknown-option name...` lists options to skip when unknown.
- **Build:** `ovpn/options.go`: the three tables of SPEC §12 as data (name, group, parser); `Parse`, `ParseFS`; `Profile` (SPEC §4.2) with `Ignored []string` and `NeedsCredentials bool`; `TagUnsupportedOption` (metadata `option`, `line`). File options are read only through the `fs.FS` given to `ParseFS`; with `Parse`, a file option that is not inline is an error.
- **Tests:** one row per option of each table; a profile with every supported option; a refused option reports its name and line; an unknown option is refused, and accepted with `ignore-unknown-option`; `ParseFS` with `testing/fstest.MapFS` reads the files and nothing else; `FuzzParse`.
- **Not in this step:** dialing.
- **Done when:** the tests pass.

### Step 3.3: `Profile.Dial`
- **Goal:** a profile connects.
- **Read:** SPEC §4.2; `reference/openvpn/doc/man-sections/client-options.rst` (`--connect-timeout`, `--remote-random`, `--server-poll-timeout`).
- **Facts:** each remote gets `connect-timeout` (120 seconds by default) for the link and the handshake together; on failure the next remote is tried; when all failed, the error of the last one is returned, with the number of remotes tried in its metadata.
- **Build:** `Profile.Dial(ctx)`.
- **Tests:** unit: the order of the remotes; `remote-random` with a fixed seed; the first remote dead, the second alive. Real server: a profile written by the test (inline CA, certificate, key, `tls-crypt`, `auth-user-pass` file through `ParseFS`) connects and passes the echo test; the same profile is accepted by the real `openvpn` client too (run it with `--dev null --ifconfig-noexec --route-noexec` for a few seconds and look for `Initialization Sequence Completed` in its log), which shows that the parser reads what OpenVPN reads.
- **Done when:** the tests pass.

### Step 3.4: `vpnnet`
- **Goal:** TCP and UDP connections through the tunnel, with no root.
- **Read:** SPEC §4.3, §5.3, §13, §19; the documentation of `gvisor.dev/gvisor/pkg/tcpip/stack`, `.../link/channel`, `.../adapters/gonet`, `.../network/ipv4`, `.../network/ipv6`, `.../transport/tcp`, `.../transport/udp`, `.../transport/icmp` (in the module cache after `go get`).
- **Facts:**
  - `go get gvisor.dev/gvisor@go` (the `go` branch is the one made for Go modules). Record the version in the entry.
  - Make a `stack.Stack` with IPv4, IPv6, TCP, UDP and ICMP; one NIC whose link endpoint is a `channel.Endpoint` with the MTU of `ConnectionState`; add the addresses of `ConnectionState().Addrs`; add default routes for IPv4 and IPv6 to that NIC.
  - Two goroutines move packets: one reads the `*openvpn.Conn` and injects each packet into the endpoint (IPv4 or IPv6 by the first nibble); one takes outgoing packets from the endpoint and writes them to the `Conn`. Both stop at `Close`.
  - `gonet.DialContextTCP`, `gonet.DialUDP`, `gonet.ListenTCP` give `net.Conn`, `net.PacketConn` and `net.Listener`.
  - gVisor's types must not appear in the API of `vpnnet`.
- **Build:** `vpnnet.New`, `Options`, `Net.DialContext` (`tcp`, `tcp4`, `tcp6`, `udp`, `udp4`, `udp6`; an IP literal address only, until step 3.5), `Net.Listen`, `Net.ListenPacket`, `Net.Close`.
- **Tests:** unit: two `Net`s joined back to back through `internal/vpntest` exchange TCP and UDP data. Real server: the test process is in the same namespace as the server, so it can listen on the server's tunnel address: a TCP echo listener on `10.8.0.1:<port>` (made with the ordinary `net` package) is reached through `Net.DialContext`, 1 MiB goes each way and comes back equal; the same over UDP; the same over IPv6; a `Net.Listen` listener is reached from the ordinary `net` package dialing the client's tunnel address; when the `Conn` is closed, a blocked `Read` on a `vpnnet` connection returns an error; no goroutine left after `Close`.
- **Not in this step:** DNS.
- **Done when:** the tests pass under `-race`.

### Step 3.5: DNS, HTTP and throughput
- **Goal:** `http.Get` through the VPN by host name.
- **Read:** SPEC §13; the documentation of `net.Resolver` (the `PreferGo` and `Dial` fields).
- **Facts:** `&net.Resolver{PreferGo: true, Dial: func(ctx, network, address) { return n.DialContext(ctx, network, <a pushed DNS server>:53) }}` sends every query through the tunnel; try the pushed servers in order.
- **Build:** `Net.Resolver`; `Net.DialContext` resolves host names with it; `examples/http/main.go` (a profile path and a URL; prints the status and the size of the body); a benchmark that sends 100 MiB through `vpnnet` and the real server and reports MB/s.
- **Tests:** real server: a small DNS server (written in the test with `net.ListenPacket`, answering one name with the server's tunnel address) listens on `10.8.0.1:53`; the server pushes `dhcp-option DNS 10.8.0.1`; an `httptest`-style HTTP server listens on `10.8.0.1`; `http.Client{Transport: &http.Transport{DialContext: n.DialContext}}` gets the page by name.
- **Done when:** the tests pass; the entry has the benchmark's number.
- **Finishes M3:** tag `v0.3.0` on the merged commit (rule 5), then start step 4.1.

---

## M4: hardening and Windows (tag `v1.0.0-rc.1`)

Result: everything of 1.0, shown to hold under bad networks and over time, on Linux and on Windows under Wine.

### Step 4.1: Windows under Wine
- **Goal:** the unit tests pass on Windows, as far as Wine can show it.
- **Read:** SPEC §18.
- **Facts:** `GOOS=windows go test -exec <script> ./...` builds each test binary for Windows and runs it with the script. Wine needs a prefix: use `.wine-test/prefix` in the module root (git-ignored), `WINEDEBUG=-all`, and stop it afterwards with `wineserver -k`.
- **Build:** `scripts/wine-exec.sh` (sets the prefix and runs `wine "$@"` under `timeout -k 5 600`); `scripts/test-windows.sh [go test flags]` (`GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -exec "$PWD/scripts/wine-exec.sh" "$@" ./...`, then `wineserver -k`); add it to `scripts/check.sh`, skipping with a clear line when `wine` is missing.
- **Tests:** the existing unit tests. Then try the tests against the real server with the client under Wine: start Wine inside `scripts/vpn-ns.sh`. If it works, add it to `scripts/check.sh`. If it does not, write in SPEC §18 what failed and leave it out; do not spend more than this step on it.
- **Done when:** `scripts/test-windows.sh` passes; `pgrep -a wine` prints nothing afterwards; SPEC §18 says what was and was not shown.

### Step 4.2: faults and long runs
- **Goal:** proof that the library holds under bad networks and over time.
- **Read:** SPEC §15, §17.
- **Facts:** inside the namespace, `tc qdisc add dev lo root netem loss 10% delay 20ms reorder 25% duplicate 5%` degrades the loopback, and `tc qdisc del dev lo root` restores it.
- **Build:** tests with the tag `gopenvpn_soak` (not part of `scripts/check.sh`; run by hand for this step and listed in `CLAUDE.md` under Commands).
- **Tests:** with `netem` as above: the handshake completes over UDP and TCP; `vpnnet` moves 10 MiB each way intact; ten renegotiations lose no connection. Every fuzz target for 10 minutes. The leak test with 1000 connections. One hour with `--reneg-sec 5`, a steady stream of echo packets, none lost and memory flat.
- **Done when:** all of them pass; the entry has the numbers. Every finding is fixed, with a test that fails before the fix.

### Step 4.3: the README and the review of the SPEC
- **Goal:** a user can start from the README, and the SPEC matches the code.
- **Build:** `README.md`: what the library is (an OpenVPN client library for Go; not affiliated with OpenVPN Inc); a short example of each layer (the tunnel, `vpnnet` with `net/http`, a profile); what 1.0 supports and does not (from SPEC §1); the license (GPL-2.0-only: a program that uses the library and is distributed must be distributed under the GPL-2.0 as a whole); how to run the tests. Then read the SPEC section by section next to the code and fix every difference, in the SPEC when the code is right and in the code when the SPEC is right (ask the owner when unsure which).
- **Done when:** the examples in the README compile (keep them as `example_test.go` functions and copy them); the entry lists every SPEC change.
- **Finishes M4:** tag `v1.0.0-rc.1` on the merged commit (rule 5). The next step is for the Mac: report and stop (rule 8).

---

## M5: macOS (tag `v1.0.0`)

### Step 5.1 (for the Mac): macOS
- **For the agent on the Mac**, if the owner has one for this project. On the Linux machine this step is not done: after step 4.3 and its tag, report and stop (rule 8). If the owner has no Mac, they say how macOS is checked and this step changes.
- **Goal:** the library is shown to work on macOS.
- **Read:** SPEC §18.
- **Tests:** `go test -race ./...` on macOS; `examples/ping` and `examples/http` against a server the Mac can reach (the owner provides it).
- **Done when:** they pass; the entry has the output. A failure is fixed on a `fix/...` branch with a test that fails before the fix, and the checks of the Linux machine are run again there before the tag.
- **Finishes M5:** tag `v1.0.0` on the merged commit (rule 5).

---

## After 1.0

SPEC §22 lists what comes next. Each becomes a milestone here, in steps of this form, when the owner asks for it.

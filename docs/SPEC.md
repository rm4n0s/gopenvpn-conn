# gopenvpn-conn: specification

Status: **merged into `main` at the owner's request, 2026-11-21 (tag `step-0`).** Nothing here is implemented yet. `docs/IMPLEMENTATION.md` is the plan that implements it.

This file is the source of truth. If the code and this file disagree, or a task needs a decision this file doesn't make, ask instead of guessing. When a decision changes, this file changes on the same branch.

## 1. Purpose and scope

`gopenvpn-conn` is a Go library that makes an OpenVPN client. A program gives it a configuration (a Go struct, or a `.ovpn` profile) and gets back a connection to an OpenVPN server that it uses with the types of the standard library.

It has three layers, each usable without the ones above it:

1. **The tunnel** (package `openvpn`, the module root): `*openvpn.Conn`, a `net.Conn` whose `Read` returns one IP packet from the VPN and whose `Write` sends one. No root, no change to the machine.
2. **The userspace network** (package `vpnnet`): `DialContext`, `Listen`, `ListenPacket` and a `*net.Resolver` over a tunnel, made by a TCP/IP stack inside the program. No root, no change to the machine. Only the connections of the program go through the VPN. `http.Transport{DialContext: n.DialContext}` is the usual use.
3. **The system tunnel** (package `tun`, after 1.0): a TUN device with the addresses and routes of the VPN, so that the whole machine uses it. Needs root or administrator rights.

and `ovpn`, the parser of `.ovpn` profiles.

**1.0 is a modern client** (the owner's decision, 2026-11-21):

| In 1.0 | Not in 1.0 (§22) |
|---|---|
| UDP and TCP to the server, IPv4 and IPv6 | HTTP and SOCKS proxies (a custom dial function can do it) |
| TLS 1.2 and 1.3 through `crypto/tls` | TLS below 1.2 |
| `tls-auth`, `tls-crypt`, `tls-crypt-v2`, and no control channel protection | |
| AES-128/192/256-GCM and CHACHA20-POLY1305, both AEAD packet formats (the 32-bit one and the epoch one) | CBC, CFB and OFB ciphers, `--auth` on the data channel |
| Cipher negotiation, keys from the TLS exporter | The old key derivation (servers before 2.6) |
| Certificates, `auth-user-pass`, `auth-token` | Challenge/response, `AUTH_PENDING` with web authentication, PKCS#11 |
| Pushed options, keepalive, renegotiation, exit notification | `PUSH_UPDATE`, compression, `fragment`, static-key mode, `--dev tap`, peer-to-peer mode |
| The tunnel, the userspace network and the profile parser, on Linux, Windows and macOS | The system tunnel (TUN) |

The reference server is OpenVPN 2.7.9, and a server from 2.6 on is expected to work.

## 2. License, sources and porting

- **D1.** The repository is **GPL-2.0-only** (the owner's decision, 2026-11-21, replacing BSD-3-Clause), because the library is derived from the code of OpenVPN 2, whose license is the GPL version 2 and no later version. `LICENSE` is the license text. `NOTICE` has the copyright, the Apache2 linking exception that OpenVPN's `COPYING` grants and lets a derived work extend (the owner confirmed it for this library, 2026-11-21: it is what lets `vpnnet` use gVisor), and the OpenVPN entry. `third_party/openvpn/` keeps OpenVPN's `COPYING` and license text.
- A program that uses this library and is distributed must be distributed under the GPL-2.0 as a whole. MIT and BSD libraries combine with it as they are.
- **Sources, in this order:** (1) the code of OpenVPN 2.7.9, `reference/openvpn/src/openvpn/`; (2) its documentation, `reference/openvpn/doc/`; (3) the wire protocol draft, `reference/openvpn-rfc/openvpn-wire-protocol.xml` (a work in progress: where it and the code disagree, the code wins and §21 says so); (4) the observed behavior of the real server.
- **Only OpenVPN 2 is a source.** Nothing is copied from minivpn (the owner's rule, 2026-11-21; it is also GPL-3.0, which cannot go into a GPL-2.0-only work), OpenVPN 3, or any other implementation, unless the owner decides it and the license is checked.
- **D6. OpenVPN's code is the reference for the protocol, not a design to translate** (the owner's rule, 2026-11-21: C is a very different language from Go, and OpenVPN's bugs are not wanted).
  - **Must match OpenVPN:** the bytes of every packet, the cryptographic computations, the meaning of messages and options, and the numbers the peer depends on (window sizes, the most acks in a packet, key ids). Without these the two do not talk.
  - **Is this library's own design:** types, control flow, buffers, goroutines and timers, error handling, names and the API (§4). OpenVPN is one event loop over global option structures in C; this library is Go types. No C function is translated line by line. TLS, the ciphers, the HMAC and the sockets come from the standard library.
  - **Is not copied:** workarounds for peers outside §1, dead or legacy paths, and anything that looks like a bug or is unsafe. When OpenVPN's behavior looks wrong, the library does the correct thing if the real server still accepts it (a test decides), §20 records the difference, and the owner decides when the correct thing and interoperability pull apart.
  - A number that only this side uses (a timeout, a local limit) starts from OpenVPN's default and may change for a reason written in §20.
- Every Go file starts with `// SPDX-License-Identifier: GPL-2.0-only`. A file written with an OpenVPN file as its reference names that file and says that this is a changed work, with the date (GPL-2.0 §2a).
- `reference/` is git-ignored and pinned by `scripts/fetch-reference.sh`. It is never imported, vendored or committed.
- Opcodes 12 to 14 of the draft (`CONTROL_V2`, `CONTROL_WKC_V2`, `CONTROL_AUX_V1`) and bit 13 of `IV_PROTO` are not in OpenVPN 2.7.9 (`P_LAST_OPCODE` is 11). They are out of scope until a released server has them.

## 3. Packages

| Package | What it has | May import |
|---|---|---|
| `openvpn` (module root) | `Config`, `Client`, `PacketClient`, `Dial`, `Dialer`, `Conn`, `ConnectionState`, the exported tags | `internal/*` |
| `ovpn` | The profile parser | `openvpn` |
| `vpnnet` | The userspace network | `openvpn`, gVisor |
| `tun` (after 1.0) | TUN devices, addresses, routes | `openvpn` |
| `internal/wire` | Opcodes, headers, ack arrays, TCP framing, the TLV of the early negotiation: pure functions from bytes to structs and back | nothing of the module |
| `internal/keys` | The static key file, the `tls-crypt-v2` client key, the key derivation, the epoch keys | `internal/wire` |
| `internal/ctrlwrap` | `tls-auth`, `tls-crypt`, `tls-crypt-v2` wrap and unwrap, with their replay protection | `wire`, `keys`, `replay` |
| `internal/replay` | The packet id windows | |
| `internal/reliable` | The reliability layer | `wire` |
| `internal/ctrlmsg` | What goes inside TLS: the key exchange message, peer info, `PUSH_REPLY`, `AUTH_FAILED` and the other text messages | |
| `internal/datachan` | Data channel encryption and decryption, key slots | `wire`, `keys`, `replay` |
| `internal/session` | The state machine of one connection: the link, the reader and the loop goroutines, handshake, negotiation, keepalive, renegotiation | all of the above |
| `internal/vpntest` | The in-process peer of the unit tests (a small server made of the same packet code, with faults: loss, reordering, duplicates, wrong messages) | tests only |
| `internal/servertest` | Starts the real `openvpn` for the tests of the `gopenvpn_server` tag | tests only |
| `internal/tools/errcheck` | The checker of §14 | |

The public packages never show a type of `internal/`, of gVisor or of `x/crypto` in their API.

## 4. Public API

The shapes follow `crypto/tls` and `net`. The names below are the plan; a step may adjust a name and then updates this section.

### 4.1 Package `openvpn`

```go
// Config is the configuration of a client, as tls.Config is for TLS.
// The zero value of a field means its default. A Config is not changed
// by the library and may be shared by connections.
type Config struct {
	TLS              *tls.Config   // the control channel: RootCAs, Certificates, ServerName, VerifyPeerCertificate, MinVersion; required (NewTLSConfig builds one that verifies as OpenVPN does)
	ControlWrap      ControlWrap   // nil, or NewTLSAuth, NewTLSCrypt, NewTLSCryptV2 (an interface: only these make one)
	Credentials      func(ctx context.Context) (Credentials, error) // auth-user-pass; nil means none
	DataCiphers      []string      // default AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305; AES-192-GCM is also supported
	HandshakeTimeout time.Duration // default 60s (--hand-window)
	RenegotiateAfter time.Duration // default 1h (--reneg-sec); negative disables
	PingInterval     time.Duration // --ping; a pushed value wins
	PingTimeout      time.Duration // --ping-restart; a pushed value wins
	MTU              int           // default 1500 (--tun-mtu)
	PeerInfo         map[string]string // UV_ variables (--setenv UV_x)
	Logger           *slog.Logger  // nil means no logs
}

func Client(conn net.Conn, config *Config) *Conn       // conn is a stream (TCP framing)
func PacketClient(conn net.Conn, config *Config) *Conn // conn is a connected datagram socket

func Dial(ctx context.Context, network, address string, config *Config) (*Conn, error)

type Dialer struct {
	NetDialer   *net.Dialer
	DialContext func(ctx context.Context, network, address string) (net.Conn, error) // replaces NetDialer when set
	Config      *Config
}
func (d *Dialer) Dial(ctx context.Context, network, address string) (*Conn, error)

// Conn is one session with a server. It implements net.Conn:
// Read returns one IP packet, Write sends one.
type Conn struct{ /* ... */ }
func (c *Conn) HandshakeContext(ctx context.Context) error
func (c *Conn) Read(b []byte) (int, error)
func (c *Conn) Write(b []byte) (int, error)
func (c *Conn) Close() error
func (c *Conn) LocalAddr() net.Addr  // of the link to the server
func (c *Conn) RemoteAddr() net.Addr // of the link to the server
func (c *Conn) SetDeadline(t time.Time) error
func (c *Conn) SetReadDeadline(t time.Time) error
func (c *Conn) SetWriteDeadline(t time.Time) error
func (c *Conn) ConnectionState() ConnectionState
func (c *Conn) NetConn() net.Conn

// ConnectionState is what was negotiated and what the server pushed.
type ConnectionState struct {
	HandshakeComplete bool
	TLS               tls.ConnectionState
	Cipher            string         // e.g. "AES-256-GCM"
	PeerID            uint32
	Addrs             []netip.Prefix // ifconfig, ifconfig-ipv6
	Gateway           netip.Addr     // route-gateway
	Routes            []Route
	RedirectGateway   bool
	DNSServers        []netip.Addr
	SearchDomains     []string
	MTU               int
	PingInterval      time.Duration
	PingTimeout       time.Duration
	PushedOptions     []string       // every pushed option, as received
}
```

- The constructors of `ControlWrap` take the contents of the key file (what a profile has inline): `NewTLSAuth(key []byte, direction KeyDirection, digest crypto.Hash) (ControlWrap, error)` with `KeyDirectionNone`, `KeyDirection0`, `KeyDirection1` and the digests SHA-1, SHA-256, SHA-384 and SHA-512; `NewTLSCrypt(key []byte) (ControlWrap, error)`; `NewTLSCryptV2(clientKey []byte) (ControlWrap, error)`. A `ControlWrap` holds a key and no connection state: every `Client` makes the protection of its own connection from it, so a `Config` is shared safely. `DefaultHandshakeTimeout` is 60 seconds. `Client` and `PacketClient` cannot return an error, so a `Config` that cannot be used (a negative timeout) makes the `Conn` fail at birth: `HandshakeContext` returns the error and `Close` closes the link.
- `Config.Credentials` is called once per connection, when the key exchange starts, with a context that ends with the connection (so a prompt can stop); it returns a `Credentials{Username, Password}`. The server takes at most 127 bytes of each; a longer one is refused by the client before anything is sent. `Config.MTU` is zero for 1500, and between 576 and 9000. `Config.PeerInfo` has names that start with `UV_` and have only letters, digits and underscores, values with no newline and no NUL, at most 32 variables, 64 bytes a name and 256 a value. `DataCiphers` names are not case sensitive and are sent in capitals. A `Config` that breaks one of these makes the `Conn` fail at birth, with the invalid-config error that names the field in its metadata (`field`), and never a value.
- `Config.TLS` is required: a `Config` without it (and not built for the tests of the exchange of resets) makes the `Conn` fail at birth with the invalid-config error, because a client that does not verify the server is not made by accident. The library works on a copy of the `tls.Config` and raises a `MinVersion` below TLS 1.2 to TLS 1.2. `NewTLSConfig(TLSOptions{RootCAs, Certificates, RemoteCertTLSServer, MinVersion}) *tls.Config` builds the configuration of OpenVPN's profile options: the chain must lead to `RootCAs` (the system's when nil), the name in the certificate is not compared with the address, and with `RemoteCertTLSServer` the certificate needs the server auth usage. It sets `InsecureSkipVerify` only to turn off the name check of `crypto/tls`, and verifies the chain itself in `VerifyConnection`, which runs on every handshake. Later versions add `verify-x509-name` and the fingerprints to `TLSOptions`.
- `network` is `"udp"`, `"udp4"`, `"udp6"`, `"tcp"`, `"tcp4"` or `"tcp6"`.
- `Dial` returns after the handshake: the tunnel is up and `ConnectionState` is complete. `Client` and `PacketClient` return at once; the handshake runs at `HandshakeContext` or at the first `Read` or `Write`, as with `tls.Conn`.
- One `Conn` is one session. Renegotiations happen inside it and the caller does not see them. When the session ends (the server says so, the keepalive times out, the link fails), `Read` and `Write` return the error and the caller dials again. A client that reconnects by itself is after 1.0 (§22).
- `Close` tells the server (§11.2), stops every goroutine of the connection and closes the link.

### 4.2 Package `ovpn`

```go
type Profile struct {
	Config  *openvpn.Config
	Remotes []Remote     // in the order to try them
	// ... what the profile says that is not part of Config (connect timeouts, remote-random)
}
type Remote struct{ Network, Address string }

func Parse(r io.Reader) (*Profile, error)             // inline files only
func ParseFS(fsys fs.FS, name string) (*Profile, error) // file options are read from fsys
func (p *Profile) Dial(ctx context.Context) (*openvpn.Conn, error) // tries the remotes
```

### 4.3 Package `vpnnet`

```go
func New(conn *openvpn.Conn, opts *Options) (*Net, error)
func (n *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error)
func (n *Net) Listen(network, address string) (net.Listener, error)
func (n *Net) ListenPacket(network, address string) (net.PacketConn, error)
func (n *Net) Resolver() *net.Resolver // asks the DNS servers of the VPN, through the VPN
func (n *Net) Close() error
```

## 5. Standard library contracts

### 5.1 `*openvpn.Conn` as a `net.Conn`
- Message semantics, like a connected `*net.UDPConn`: one `Read` is one IP packet. A buffer that is too small gets the start of the packet and the rest is dropped; `ConnectionState().MTU` is the size that is always enough. One `Write` is one IP packet; a packet larger than the MTU is an error.
- `Read`, `Write` and `Close` may be called from different goroutines at the same time. Deadlines behave as `net.Conn` says, and a deadline in the past unblocks a call in progress.
- The data channel is unreliable: `Write` returning `nil` does not mean the packet arrived.

### 5.2 Context
A context that is done stops `Dial`, `HandshakeContext` and the dial functions of `vpnnet`. The context of a dial does not bound the life of the connection.

### 5.3 Errors of the contracts (D2)
The owner's error package tags every error (§14). Three values are the exception, because callers and the standard library compare them with `==` or assert `net.Error` (`io.Copy` and `io.ReadAll` stop on `err == io.EOF`; `net/http` asserts `err.(net.Error)` for timeouts):

| Value, returned untouched | When |
|---|---|
| `io.EOF` | `Read`, after the server ended the session with `EXIT` |
| `net.ErrClosed` | Any method after `Close` |
| `os.ErrDeadlineExceeded` | `Read` or `Write` when its deadline passes |

The connections, listeners and resolver of `vpnnet` return what gVisor's `gonet` returns (`*net.OpError` and the like), untouched, for the same reason. Every other error of the module is a tagged `*errors.Error`, and `errors.Is` still finds a cause such as `context.Canceled` through it.

## 6. Link and framing

- Source: `socket.c`; Draft "OpenVPN wire packet format".
- UDP: one datagram is one packet. TCP: each packet has a 16-bit length before it, in network byte order.
- The first byte is the opcode (the high 5 bits) and the key id (the low 3 bits).
- A packet that is too short, too long or has an unknown opcode is dropped and counted; it never ends the session (anyone can send one).
- The largest control packet is 1250 bytes (`TLS_MTU_DEFAULT`, `--max-packet-size`).

## 7. Control channel

### 7.1 Protection (`internal/ctrlwrap`; source `tls_crypt.c`, `ssl_pkt.c`, `packet_id.c`)
- **None:** the plain control packet.
- **`tls-auth`:** an HMAC (SHA-1 by default; SHA-256, SHA-512 by `--auth`) over the pseudo packet of the draft, with a 64-bit replay id (packet id, then time). `key-direction` selects the keys.
- **`tls-crypt`:** HMAC-SHA256 as a synthetic IV and AES-256-CTR, with the same replay id.
- **`tls-crypt-v2`:** `tls-crypt` with the client key `Kc`; the wrapped key `WKc` is appended to `CONTROL_HARD_RESET_CLIENT_V3` and, when the server asks with the early negotiation flag, to `CONTROL_WKC_V1`.
- **Dynamic `tls-crypt`** (`protocol-flags dyn-tls-crypt`): renegotiations use a key from the TLS exporter (`EXPORTER-OpenVPN-dynamic-tls-crypt`).
- A packet is authenticated first; its replay id is checked next; only then is anything in it used. A packet that fails is dropped silently.

### 7.2 Reliability (`internal/reliable`; source `reliable.c`, `ssl.c`)
- Each control packet has a 32-bit id, starting at 0, with no gaps; a retransmission keeps its id. Acks are single ids, up to 8 in a packet, sent in `ACK_V1` or on other packets.
- The numbers the peer depends on are OpenVPN's: 6 packets in the send window, 12 in the receive window. The retransmission starts from OpenVPN's timing: after 2 seconds (`--tls-timeout`), doubling each time up to 128 seconds, and at once when three later packets were acked.
- TLS bytes are cut into control packets so that no packet is larger than the limit of §6.
- Acknowledgements: a received packet is acknowledged when it is new and less than 12 ahead of the next expected id, and also when it is a copy of one already taken (its acknowledgement may have been lost). A packet more than 11 ahead, or one that arrives when 8 acknowledgements wait unsent, is dropped without an acknowledgement; the peer sends it again. Each outgoing packet repeats the most recently acknowledged ids while there is room (up to 8), as OpenVPN does.
- Ids are compared with serial number arithmetic. A hard reset must have id 0 (the session checks that; the layer does not know opcodes).

### 7.3 Handshake (source `ssl.c`, `ssl_pkt.c`, `session_id.c`)
1. The client sends `CONTROL_HARD_RESET_CLIENT_V2` (`V3` with `tls-crypt-v2`) with a random 64-bit session id.
2. The server answers `CONTROL_HARD_RESET_SERVER_V2` with its session id.
3. The client acks, and TLS starts in `CONTROL_V1` packets.

The handshake has `HandshakeTimeout` to finish, pushed options included.

Until TLS runs (step 1.11) the handshake is complete when the server's reset has arrived and been acknowledged and the client's reset has been acknowledged. With `tls-crypt-v2`, when the server's reset asks for the wrapped key, the acknowledgement travels in an empty `CONTROL_WKC_V1` (packet id 1); step 1.11 replaces that empty packet with the first bytes of TLS. The real server answers the first reset without keeping state (§21 O7), so the third packet is what makes it start a session: in the finished client that packet is the TLS ClientHello, which is a reliable packet and is sent again until it is acknowledged.
- The reader goroutine passes each packet to the loop in a slice of its own (the packets of the control channel are small and rare; the data channel has its own path, §10). A packet of the wrong protection, from another session, of an opcode that a server does not send, with a key id other than 0, or of no use yet, is dropped and counted, never answered (§15 rule 7).

## 8. TLS, key exchange and negotiation

### 8.1 TLS (source `ssl.c`, `ssl_verify.c`; `crypto/tls` does the work)
- `crypto/tls` runs as a client over an internal `net.Conn` that the reliability layer feeds. TLS 1.2 (with Extended Master Secret) and 1.3.
- The caller's `tls.Config` decides the verification. The profile parser builds it for `ca`, `cert`, `key`, `remote-cert-tls server`, `verify-x509-name`, `peer-fingerprint`, `tls-version-min`, `tls-groups` (§12).
- The TLS bytes go in `CONTROL_V1` packets, in order. A packet carries at most `1250 - 48 - 1 - 8 - 41 - 4 - <protection overhead>` bytes (OpenVPN's `tls_mtu` of 1250, the IPv6 and UDP headers, the first byte, the session id, the room for 8 acknowledgements, the packet id): 1108 with `tls-crypt`. The first packet that follows the server's reset is a `CONTROL_WKC_V1` when the server asked for the wrapped key (§7.1), and then carries `max(16, that - len(WKc))` bytes. The packets are cut as the send window of 6 has room: what `crypto/tls` writes waits in the loop until then, and the next write is not taken before that.
- The client's TLS runs in a goroutine of its own (`tlsMain`) over an internal `net.Conn` whose `Write` hands the bytes to the loop and whose `Read` returns the bytes that arrived in order. At most 256 KiB of TLS may wait to be read: a packet that would pass the limit is not acknowledged, so the server sends it again when TLS has caught up (§15 rule 6). The TLS goroutine ends when the handshake does, and when the session ends.
- After the handshake, each control message is one TLS record of plain text ending with a NUL byte.

### 8.2 Key exchange (`internal/ctrlmsg`; source `ssl.c` key method 2, `ssl_util.c`)
- The client sends the key method 2 message: random bytes, the options string, the user name and password (when `Credentials` is set), and the peer info.
- Peer info: `IV_VER`, `IV_PLAT`, `IV_PROTO`, `IV_CIPHERS`, `IV_MTU`, and the `UV_` variables of the configuration. `IV_PROTO` has the bits of what is implemented: 1 (`DATA_V2`), 2 (push without request), 3 (TLS exporter), 4 (`AUTH_PENDING` keywords), 7 (exit in the control channel), 8 (`AUTH_FAILED,TEMP`), 9 (dynamic `tls-crypt`), 10 (epoch format), 11 (`dns` option). A bit is added in the step that implements it, not before.
- **Decided in step 2.1** (§21 O16): `IV_VER=gopenvpn-conn <version>` (for example `gopenvpn-conn 0.2.0`; the server turns the space into an underscore for its scripts and reads nothing else of it) and `IV_PLAT=linux`, `win` or `mac`. The server uses neither to choose a protocol. `IV_MTU` is the larger of 1600 (OpenVPN's default) and the tunnel MTU. The other lines are `IV_TCPNL=1`, `IV_NCP=2` (when AES-128-GCM and AES-256-GCM are both offered), `IV_CIPHERS` and `IV_PROTO`, then the `UV_` variables in order of name.
- The options string is built from the configuration in the form of OpenVPN's client, `V4,dev-type tun,link-mtu <mtu+41 or +43 for TCP>,tun-mtu <mtu>,proto <UDPv4|UDPv6|TCPv4_CLIENT|TCPv6_CLIENT>,cipher <first data cipher>,auth [null-digest],keysize <bits>,key-method 2,tls-client`, at most 511 bytes. The server compares it with what it expects and only warns (§20 V1).
- Each control message is written to TLS in one `Write`, and the server's message is read with one `Read`: a message is one TLS record, as OpenVPN reads it. The random fields are from `crypto/rand`. The password is cleared from the message buffer after the write; the strings that `Credentials` returned cannot be cleared.

### 8.3 Negotiation (source `ssl_ncp.c`, `push.c`, `options.c`)
- The server picks the data cipher from `IV_CIPHERS` and pushes it with `cipher`. A cipher that was not offered ends the handshake.
- **D3.** The data keys come from the TLS exporter (`EXPORTER-OpenVPN-datakeys`, 256 bytes; RFC 5705, RFC 8446 §7.5), when the server pushes `key-derivation tls-ekm` or `protocol-flags tls-ekm`. A server that does not is refused in 1.0 with its own tag (§22 has the old derivation).
- `protocol-flags` also turns on `cc-exit`, `dyn-tls-crypt` and `aead-epoch`.

## 9. Pushed options (`internal/ctrlmsg`; source `push.c`, `push_util.c`, `options.c`)

- The client sends `PUSH_REQUEST` at once and repeats it every 5 seconds until the reply is complete; it also announces "push before request" (`IV_PROTO` bit 2), so the server usually answers first. A reply may come in several parts: every part but the last ends with `push-continuation 2`. At most 4096 options are taken over all the parts; a PUSH_REPLY that is longer ends the handshake. `HandshakeContext` returns when the last part has been processed.
- A control message is text and a NUL. The reader ends a message at the NUL, whatever the TLS records are: OpenVPN's servers send one message in one record, but `crypto/tls` cuts a long write into records, and a message of 64 KB or more without a NUL ends the session (`TagControlChannelFailed` is for the TLS session that ends; the too long message has its own unexported tag). Messages that are not yet understood are ignored and logged by name only.
- Each pushed option is in one of three groups, and the tables are in the code with a test per option:
  - **Used:** `ifconfig`, `ifconfig-ipv6`, `route`, `route-ipv6`, `route-gateway`, `redirect-gateway`, `topology`, `dhcp-option DNS`/`DNS6`/`DOMAIN`/`DOMAIN-SEARCH`, `dns`, `tun-mtu`, `ping`, `ping-restart`, `peer-id`, `cipher`, `key-derivation`, `protocol-flags`, `auth-token`, `auth-token-user`, `reneg-sec`, `explicit-exit-notify`.
  - **Ignored, kept in `PushedOptions`:** options that only matter to a system tunnel or to OpenVPN's own program (`block-outside-dns`, `register-dns`, `persist-tun`, `sndbuf`, `rcvbuf`, ...).
  - **Refused, ending the handshake with `TagUnsupportedPushedOption`:** options that change the packet format in a way 1.0 does not implement: `compress` or `comp-lzo` with anything that adds framing, `fragment`, a cipher that is not AEAD.
- An unknown option is ignored, logged at `Warn` by name, and kept in `PushedOptions`. The value of `auth-token` is the exception to "as received": it is a secret, so `PushedOptions` has the word only (§20 V7).
- A pushed `cipher` must be AEAD and supported (AES-128-GCM, AES-192-GCM, AES-256-GCM, CHACHA20-POLY1305), else `TagUnsupportedPushedOption`; and it must be one the client offered, else `TagCipherNegotiationFailed` (metadata `cipher`). `compress` (with any argument or none), `comp-lzo` (with any) and `fragment` are refused; so are malformed arguments, with an unexported tag that names the option. The arguments are split at spaces (no quotes), the options at commas.
- `ifconfig` is two words: with `topology subnet` an address and a netmask, with `net30` (the default when none is pushed) and `p2p` the local and the remote address; the length of the tunnel address is 24 (or whatever the mask says), 30 and 32. `route` takes a network, a netmask, a gateway and a metric; the keywords `default`, `vpn_gateway`, `net_gateway` and `remote_host` are understood (the last two leave the gateway empty).
- `AUTH_FAILED` (with `TEMP` and its `backoff` and `advance` keywords in the metadata), `HALT` and `RESTART` end the session with their tags (§14.3). `AUTH_PENDING` extends the wait up to its `timeout`, within the context of the handshake. **Decided in step 2.3:** the timeout counts from the start of the handshake and never shortens it; one without a time keeps `HandshakeTimeout`; it is cut to the longer of `HandshakeTimeout` and 30 minutes (OpenVPN allows its renegotiation time, an hour by default, but a server that holds a client for an hour in a handshake is not a case of this library); one that comes after the handshake is complete is ignored. These messages are read before the push reply logic and end the session whenever they arrive, during the handshake or after it (§14.2).

## 10. Data channel (`internal/datachan`; source `crypto.c`, `crypto_epoch.c`, `packet_id.c`, `forward.c`)

- **Packets:** `DATA_V2` (opcode, key id, 24-bit peer id) when the server pushed `peer-id`; `DATA_V1` otherwise.
- **AEAD format** (Draft "AEAD encrypted data channel packet"): 32-bit packet id, 16-byte tag before the ciphertext, nonce = packet id then the implicit IV from the key material, the header as additional data.
- **Epoch format** (`aead-epoch`; Draft "... with extended packet id and epoch keys"; `crypto_epoch.c`): 64-bit packet id (16 bits of epoch, 48 of counter), tag at the end, nonce = implicit IV XOR packet id, a new key for each epoch from `OVPN-Expand-Label` (HKDF-SHA256), with OpenVPN's usage limits for AES-GCM and its window of future epochs.
- **Replay protection** (`internal/replay`): OpenVPN's sliding window (64 packets, 15 seconds by default) for UDP, and its stricter order for TCP. A replayed, late or unauthenticated packet is dropped and counted.
- **Never a repeated nonce:** before a packet id can wrap, the session renegotiates (32-bit format) or moves to the next epoch (epoch format); if neither is possible in time, the connection ends with a tag rather than send.
- **Key slots** (`ssl.c`, `ssl_common.h`): the active key, the retiring key (decryption only) and the next key during a renegotiation, selected by the key id of the packet.
- The payload is an IP packet with no extra framing (compression is refused, §9).

## 11. Keepalive, exit, renegotiation

### 11.1 Keepalive (source `ping.c`, `forward.c`)
- When nothing was sent for `PingInterval`, the client sends the 16-byte ping packet on the data channel. A received ping is not given to `Read`.
- When nothing was received for `PingTimeout`, the session ends with `TagPingTimeout`.

### 11.2 Exit (source `sig.c`, `ssl.c`, `occ.c`)
- `Close` sends `EXIT` in the control channel when `cc-exit` was negotiated; otherwise, over UDP, the older exit notification of `--explicit-exit-notify` on the data channel. Then it closes, without waiting for an answer for longer than a short bound.
- `EXIT` from the server ends the session cleanly: `Read` returns `io.EOF`.

### 11.3 Renegotiation (source `ssl.c`)
- Either side starts it with `CONTROL_SOFT_RESET_V1`; a new TLS session runs under the next key id (1 to 7, then 1 again), the key exchange of §8.2 is repeated with the auth token instead of the password when the server pushed one, and new data keys are made.
- It starts after `RenegotiateAfter`, or earlier when the packet id or the AEAD usage limit asks for it.
- The new key becomes the active one after OpenVPN's delay, and the old one stays for decryption during the transition. A renegotiation that fails is tried again; when the old key expires with no new one, the session ends with a tag.

## 12. Profiles (package `ovpn`; source `options.c`, `options_parse.c`, `doc/man-sections/`)

- **Grammar:** OpenVPN's: one option per line, `#` and `;` comments, single and double quotes, backslash escapes, a leading `--` allowed, and inline files (`<ca>...</ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<auth-user-pass>`, `<connection>`).
- **Files:** `Parse` accepts only inline files; `ParseFS` reads file options from the `fs.FS` it is given, and never from anywhere else. The parser never runs a command and never reads the environment.
- **Every option is in one of three tables**, each with a test:
  - **Supported:** what §6 to §11 implement (`client`, `remote`, `proto`, `port`, `remote-random`, `connect-timeout`, `ca`, `cert`, `key`, `tls-auth`, `key-direction`, `tls-crypt`, `tls-crypt-v2`, `auth-user-pass`, `auth`, `data-ciphers`, `cipher` as a fallback offer, `remote-cert-tls`, `verify-x509-name`, `peer-fingerprint`, `tls-version-min`, `tls-groups`, `reneg-sec`, `hand-window`, `tls-timeout`, `ping`, `ping-restart`, `ping-exit`, `keepalive`, `tun-mtu`, `explicit-exit-notify`, `setenv UV_*`, `push-peer-info`, `pull-filter`, `route-nopull`, `auth-nocache`).
  - **Accepted and ignored:** options that mean nothing to a library (`dev tun`, `nobind`, `persist-tun`, `persist-key`, `verb`, `mute`, `resolv-retry`, `user`, `group`, `daemon`, `log`, `script-security`, `mssfix`, `sndbuf`, `rcvbuf`, ...). `Profile` lists the ones that were ignored.
  - **Refused, with the option and the line in the error:** options that 1.0 cannot honor and that would be unsafe or wrong to skip (`secret`, `dev tap`, `fragment`, `compress`/`comp-lzo` with compression on, `http-proxy`, `socks-proxy`, a `cipher` that is not AEAD with no `data-ciphers`, `pkcs12`, `up`/`down` and the other scripts, `plugin`, `management`).
- An option that is in no table is refused, unless the profile has `ignore-unknown-option` for it or it is under `setenv opt`.
- A password is never read from a terminal: `auth-user-pass` with no file makes a `Config` with no credentials and `Profile` says that the profile asks for them.

## 13. Userspace network (package `vpnnet`)

- **D4.** The TCP/IP stack is gVisor's `tcpip` with its `gonet` adapters (Apache-2.0, through the linking exception of `NOTICE`; the owner's decision, 2026-11-21). It is imported only here: a program that uses only `openvpn` does not compile it.
- `New` makes a stack with one interface whose link is the `*openvpn.Conn`, with the addresses, the MTU and the DNS servers of `ConnectionState`. Everything dialed through the `Net` goes into the tunnel; the pushed routes are not needed to decide that.
- TCP and UDP over IPv4 and IPv6, and ICMP echo. `network` and `address` mean what they mean in `net`.
- `Resolver` returns a `*net.Resolver` whose queries go through the tunnel to the DNS servers of the VPN; `DialContext` uses it for host names.
- `Close` closes the stack and its connections. It does not close the `*openvpn.Conn` unless `Options` says so. When the tunnel ends, the connections of the `Net` fail with the errors of §5.3.

## 14. Errors

### 14.1 Rules
All errors use `github.com/rm4n0s/errors` v0.2.0 the way its `AI_GUIDE.md` says (the owner's requirement). `internal/tools/errcheck` checks rules 1 to 8.

1. No `fmt.Errorf`. The standard `errors` package is never imported under the name `errors` (an alias `stdErrors` when `Join` is needed).
2. `errors.New` has a tag and a message; metadata goes in the same call as key/value pairs.
3. An error from outside the module is tagged once, with `NewErr`, where it first appears. An error from a function of the module is returned untouched.
4. A constructor is called in the function that fails, never in a helper that builds the error.
5. A tag is a constant declared next to the code that produces it; exported (`TagX`, documented) when a user of the library may branch on it. Code branches on tags or `errors.Is`, never on messages.
6. A sentinel is a struct literal `&errors.Error{Tag: TagX}`, never a package-level `errors.New`.
7. Functions return `error`, never `*errors.Error`.
8. Every tag has a route test: a test checks with `HasRoute` a route that ends with the tag. `internal/tools/errcheck` accepts any string of a test file that ends with `.Tag`, written out or made of constants, so that a table of routes is a route test.
9. **No secret in an error:** no key, password, token, or decrypted payload in a message or in metadata. Metadata values are JSON-serializable.
10. Errors are logged with `slog` as the attribute `"err"`.
11. The exception of §5.3 is the only place where an untagged error leaves the module.

### 14.2 The error that ends a connection
It is made once, in the goroutine that found the failure, and stored. Every later `Read`, `Write` and `HandshakeContext` returns that same value, so its route shows where the session failed, not who asked.

### 14.3 Exported tags
The list grows with the steps. The ones a caller will branch on: `TagHandshakeTimeout`, `TagTLSHandshakeFailed`, `TagAuthFailed` (metadata: `reason`, `session`, `temporary`, `backoff` in seconds, `advance`), `TagServerHalt` (metadata: `reason`), `TagServerRestart` (metadata: `reason`, `flags`), `TagPingTimeout`, `TagCipherNegotiationFailed`, `TagKeyDerivationUnsupported`, `TagUnsupportedPushedOption` (metadata: `option`), `TagLinkFailed`, `TagKeyExchangeFailed` (metadata: `op`), `TagCredentialsFailed`, `TagDialFailed` (metadata: `network`, `address`), `TagUnsupportedNetwork` (metadata: `network`); in `ovpn`: `TagUnsupportedOption` (metadata: `option`, `line`), `TagSyntax`.

## 15. Security rules

1. Random bytes come from `crypto/rand`.
2. MACs and tags are compared in constant time (`hmac.Equal`, the AEAD's `Open`).
3. A packet is authenticated before anything in it is used, and its replay id is accepted only after it authenticated.
4. A nonce is never used twice with a key (§10).
5. Bytes from the network or from a file are parsed with explicit bounds; every length is checked before it is used; every parser has a fuzz target. No `unsafe`.
6. Buffers that the peer can make grow have a limit (control message reassembly, the reorder window, the pushed options).
7. A packet that anyone could have sent (unauthenticated, replayed, malformed) never ends the session and never costs more than its own processing.
8. No secret in logs or errors (§14.1 rule 9). The logger gets the names and sizes of things, never their bytes.
9. The server's certificate is verified by default. Turning that off takes an explicit setting of the caller's `tls.Config`; the profile parser never does it by itself.
10. Key material is dropped when its key slot ends and when the connection closes.
11. The parser of profiles reads only what it is given (§12).

## 16. Concurrency and lifetime

- A connection owns its goroutines: the reader of the link, the loop (which owns the state and the timers of the control channel) and the TLS handshake (until it ends). They start at the handshake and none runs after `Close` returns; a test checks it.
- No global mutable state. Two connections share nothing but an unchanged `Config`.
- Time is the standard `time` package; the tests run it with `testing/synctest`, so no test sleeps.
- The data path does not allocate per packet in the steady state (a benchmark with `ReportAllocs` holds it).

## 17. Testing

- **Unit tests** need nothing but Go: the peer is `internal/vpntest` in the same process, over `net.Pipe` or an in-memory link with loss, reordering and duplication. They run on every platform, with and without cgo, under the race detector.
- **Tests against the real server** carry the `gopenvpn_server` build tag and run under `scripts/vpn-ns.sh`, which enters a private user and network namespace (`unshare -Urn`), so they need no root and change nothing on the machine. `internal/servertest` makes the certificates and keys in Go, starts `openvpn` 2.7.9 on the loopback of the namespace with the options of the test, reads its log and its management interface, and stops it. They skip when `openvpn` or the namespace is missing. The server runs both with the kernel data channel (DCO) and with `--disable-dco`.
- **A behavior of the protocol counts as implemented when a test against the real server shows it.**
- **Known answers:** what OpenVPN's own unit tests check with fixed vectors (`tests/unit_tests/openvpn/`) is checked with the same vectors.
- **Faults:** `tc netem` on the loopback of the namespace gives loss, delay, reordering and duplication to the tests against the real server.
- **Fuzzing:** a target for every parser, with its corpus in `testdata/fuzz/`.
- **Errors:** every tag has a route test (§14.1 rule 8).
- **Leaks:** a test opens and closes connections many times and checks the goroutines and the heap.
- No test connects to a server on the internet.

## 18. Platforms and build tags

- Linux, Windows and macOS, on amd64 and arm64. The module needs the Go version that `github.com/rm4n0s/errors` needs (1.26.3) or newer.
- `openvpn`, `ovpn`, `vpnnet` and everything under `internal/` except `internal/servertest` are plain Go with no OS build tags, no cgo and no `unsafe`: they behave the same on the three systems.
- OS build tags are allowed only in `internal/servertest` (Linux: namespaces), in `tun` (after 1.0) and in tests that skip by platform.
- How each platform is checked:
  - **Linux:** everything, on this machine.
  - **Windows:** the build and `go vet` for `windows/amd64` and `windows/arm64`; the unit tests under Wine; the tests against the real server with the client under Wine, if Wine can reach the namespace (the step that tries it decides and writes it here).
  - **macOS:** the build and `go vet` for `darwin/amd64` and `darwin/arm64` on this machine; the tests are run on a Mac in a step for that machine.

## 19. Dependencies

| Module | License | Used by | Why |
|---|---|---|---|
| `github.com/rm4n0s/errors` v0.2.0 | MIT | everything | The owner's error package |
| `golang.org/x/crypto` | BSD-3-Clause | `internal/datachan` | `chacha20poly1305` |
| `gvisor.dev/gvisor` | Apache-2.0 | `vpnnet` only | The userspace TCP/IP stack (D4) |

HKDF, AES-GCM, HMAC, SHA-2, TLS and X.509 come from the standard library. Any other dependency is asked for first and needs a license that combines with GPL-2.0-only.

## 20. Decisions and deviations

**Decisions**
- **D1** GPL-2.0-only, with the Apache2 linking exception (§2).
- **D2** The three standard error values are returned untagged (§5.3).
- **D3** 1.0 needs keys from the TLS exporter (§8.3).
- **D4** gVisor is the userspace stack, in `vpnnet` only (§13).
- **D5** One `Conn` is one session; reconnecting is the caller's, until a later version (§4.1).
- **D6** OpenVPN's code is the reference for the protocol, not a design to translate (§2).

**Deviations from OpenVPN** (each also has a `// Deviation:` comment in the code)
- **V1** No options string check: the client sends OpenVPN's options string for compatibility and does not compare the server's (OpenVPN 2.7 removed `--opt-verify`).
- **V2** No scripts, plugins, management interface or environment: a library gives its caller values and errors instead.
- **V3** The profile parser refuses what it cannot honor instead of warning and going on (§12).
- **V4** `internal/wire` parses strictly: an `ACK_V1` with bytes after its acknowledgements is refused (OpenVPN ignores them; no real server sends them), and the opcodes 1, 2 and 12 to 31 are refused (OpenVPN 2.7.9 accepts 3 to 11 only).
- **V5** `internal/keys` refuses a static key file of 128 bytes (one key), which OpenVPN reads for `tls-auth` with no direction. `openvpn --genkey` writes 256 bytes, and a profile with an older key can be given a new one.
- **V6** `internal/reliable` counts, for the fast retransmission, only the first acknowledgement of each later packet. OpenVPN counts every acknowledgement of a later id against the earlier packets, so an id that the peer repeats in each packet (as OpenVPN itself does, §7.2) can bring on a retransmission that no loss asked for. The wire does not change, and the draft's rule ("three packets sent later were acknowledged") is kept as written.
- **V7** `ConnectionState.PushedOptions` and the `Pushed` record keep the word `auth-token` and not its value, where OpenVPN keeps the option as received: a caller that logs the state must not log the token (§15 rule 8). The token itself is kept in memory for the reconnect that §22 has for later.
- **V8** Control messages are cut at the NUL, not at the TLS record (§9). OpenVPN reads one message for each record, so a record that holds half a message breaks it; here it does not. The server sees no difference.
- **V9** A pushed `compress` or `comp-lzo` is refused whatever its argument, `stub` and `no` included: they all add a byte of framing to every data packet, which the data channel of 1.0 does not parse (§22).

## 21. Observations

What the documentation or the draft does not say or says differently from the code, and what was found by running the real server. Each entry names the test that shows it. (Empty until the steps fill it.)

Known before any code, to be confirmed by their steps:
- **O1** The draft shows the acked packet ids as 8 bytes each in one figure and 4 in another; the code uses 4 (`packet_id_type`; read in `reliable_ack_parse`, step 1.4). The real server confirms it in step 1.10.
- **O2** The draft's description of the old key derivation is incomplete; it does not matter for 1.0 (D3).
- **O3** The draft has opcodes 12 to 14; OpenVPN 2.7.9 stops at 11.
- **O4** A real OpenVPN 2.7.9 server starts with no root inside `unshare -Urn`, with a kernel DCO device, on this machine (tried 2026-11-21).
- **O5** The server refuses `--verify-client-cert none` unless an authentication method is configured (`--auth-user-pass-verify`, a plugin or the management interface): `Options error: --verify-client-cert none|optional must be used with --management-client-auth, an --auth-user-pass-verify script, or plugin`. The test server therefore requires a client certificate by default (`internal/servertest`, step 1.3).
- **O6** The server's log has the line `Initialization Sequence Completed` when it is ready, and `UDPv4 link local (bound): [AF_INET]127.0.0.1:<port>` (for TCP, `TCPv4_SERVER link local (bound): ...`) when it listens (step 1.3).
- **O7** The server answers a first reset (`CONTROL_HARD_RESET_CLIENT_V2`) **statelessly**: it sends an HMAC based reset challenge (a `CONTROL_HARD_RESET_SERVER_V2` whose session id is derived from the client's) and keeps no state. At `--verb 4` it logs nothing for that packet; at `--verb 7`: `Reset packet from client, sending HMAC based reset challenge`. `TLS: Initial packet from ...` is logged only after the client's third packet. A packet with a wrong `tls-auth` HMAC gets no answer, and at `--verb 7` the log says `Authenticate/Decrypt packet error: packet HMAC authentication failed` and `TLS Error: incoming packet authentication failed from ...` (step 1.5).
- **O8** The format of `tls-auth` in the plan is exact: first byte, session id, HMAC, packet id (4 bytes), time (4 bytes), body, with the HMAC over packet id, time, first byte, session id and body, and the keys by direction. The real server 2.7.9 accepted and answered it with `--auth` SHA1 (the default), SHA256, SHA384 and SHA512, with `key-direction` 0 on the server and 1 on the client, and with no direction on both (step 1.5, `internal/ctrlwrap/realserver_test.go`).
- **O9** The format of `tls-crypt` in the plan is exact: first byte, session id, packet id (4 bytes), time (4 bytes), tag (32 bytes), body encrypted; the tag is HMAC-SHA256 over first byte, session id, packet id, time and the plaintext (the **wire order**, unlike `tls-auth`, whose HMAC puts the packet id first); the IV is the first 16 bytes of the tag; AES-256-CTR with the first 32 bytes of the cipher key. A client sends with key 1 and receives with key 0. The real server 2.7.9 answered a `tls-crypt` reset (step 1.6, `TestTLSCryptWithRealServer`). A packet with another key gets no answer and the server logs `tls-crypt unwrap error: packet authentication failed` and `TLS Error: tls-crypt unwrapping failed from ...` (verb 7). A `tls-auth` packet sent to a `tls-crypt` server is not answered either.
- **O10** The format of `tls-crypt-v2` in the plan is exact (step 1.7). A client key made by `openvpn --genkey tls-crypt-v2-client` is read by `ParseTLSCryptV2ClientKey`; the first packet is `CONTROL_HARD_RESET_CLIENT_V3` with the wrapped key `WKc` appended after the `tls-crypt` packet, not encrypted. The server answers it statelessly (log, verb 7: `Reset packet from client, sending HMAC based reset challenge`) with a `CONTROL_HARD_RESET_SERVER_V2` whose payload is the early negotiation TLV that asks for `WKc` again, and the client's next packet, `CONTROL_WKC_V1` (ack of the reset, packet id 1, `WKc` appended again), is accepted: the log says `Valid packet (P_CONTROL_WKC_V1) with HMAC challenge from peer (...), accepting new connection.` and the server acks it with an `ACK_V1`.
- **O11** `TLS: Initial packet from` is logged only for a packet that is a hard reset, so it is not in the log of a `tls-crypt-v2` handshake, whose third packet is a `CONTROL_WKC_V1`. A third packet that is a plain `CONTROL_V1` without `WKc` starts no session; a client key made for another server gets no answer to its first packet.
- **O12** Over UDP the server accepts an `ACK_V1` as the third packet for every protection but `tls-crypt-v2`: it logs `Valid packet (P_ACK_V1) with HMAC challenge from peer (...), accepting new connection.` and reads the ack (`P_ACK_V1 kid=0`). Over TCP there is no stateless answer: the server keeps the connection and starts the session at the reset (`TLS: Initial packet from ...`), then reads our `ACK_V1`; with `tls-crypt-v2` it does not ask for the wrapped key again over TCP, so the third packet is an `ACK_V1` there too. In the log of a protected packet the `pid=[ #n ]` is the replay id of `tls-auth` or `tls-crypt` (the `tls-crypt-v2` ids start at 251658241, 0x0f000001), not an acknowledged id (step 1.10, `TestDialWithRealServer`).
- **O13** The server logs `Control Channel: TLSv1.3, cipher ...` (`session_move_active`) only when the key exchange is done, not when the TLS handshake is: the line cannot be used as a proof of step 1.11 and comes with step 2.1. What the server logs at the end of the TLS handshake is `VERIFY OK: depth=1, CN=gopenvpn-conn test CA` and `VERIFY OK: depth=0, CN=client`, the check of our certificate (`TestTLSWithRealServer`).
- **O14** A client without a certificate (TLS 1.2, so that the client sees the refusal) gets different answers by the link: over TCP the server closes the connection, and the client sees it as a failed TLS handshake or as the end of the link (`TagLinkFailed`, cause `io.EOF`), whichever of its goroutines finds it first; over UDP the server stays silent and the client's handshake times out (`TagHandshakeTimeout`). With TLS 1.3 the client's handshake completes before the server looks at the certificate; the refusal comes later and is the key exchange's to see. A client that trusts another authority fails by itself, at once, on both links.
- **O15** The ClientHello of Go's `crypto/tls` (with the hybrid post-quantum key share) is about 1.5 KB and does not fit one control packet: it goes in two, the first a `CONTROL_WKC_V1` of at most `1108 - len(WKc)` bytes for `tls-crypt-v2` over UDP, and the real server puts them back together. A client certificate of 12 KB (a dozen packets, twice the send window) also works with the real server over UDP and TCP.
- **O16** The real server accepts `IV_VER=gopenvpn-conn 0.2.0`, and logs the peer info with the space turned into an underscore (`peer info: IV_VER=gopenvpn-conn_0.2.0`, `UV_FROM=gopenvpn-conn_tests` for the value `gopenvpn-conn tests`): it makes the values safe for the environment of its scripts. With `--auth-user-pass-verify ... via-file --username-as-common-name` and a client certificate it logs `TLS: Username/Password authentication succeeded for username 'alice' [CN SET]`; with a wrong password, `TLS Auth Error: Auth Username/Password verification failed for peer`, and the handshake of the client is not ended by it: the AUTH_FAILED message comes after the server's key exchange message (step 2.3 reads it; O19). The options string of this library, which differs from what the server expects, gets no warning at `--verb 7` that matters and no refusal (`TestKeyExchangeWithRealServer`).
- **O17** A test server must run with `--disable-dco`: inside the private namespace the kernel data channel cannot create its peer (`dco_new_peer: netlink reports error (-28): Operation not permitted`), and the server then answers every client with `AUTH_FAILED` right after the key exchange. The earlier steps never saw it because their `Dial` returned before the server had decided. `servertest` disables DCO by default now (`Options.EnableDCO` turns it on, for a host that can).
- **O18** Because the client announces `IV_PROTO` bit 3 (TLS exporter), the server pushes `key-derivation tls-ekm` (D3) with its first reply, and `tun-ipv6` with `--server-ipv6`; the reply also has `route-gateway`, `topology subnet`, `ping` and `ping-restart` (from `--keepalive`), `ifconfig`, `ifconfig-ipv6 <address>/<bits> <gateway>`, `peer-id`, `cipher` and `tun-mtu`. A reply with more than about 1 KB of options comes in parts, each ending in `push-continuation 2` but the last, which ends in `push-continuation 1` (`TestPushWithRealServer`, `TestPushInPartsWithRealServer`). The server pushes `compress lz4` when asked to (`--push`), which the client refuses.
- **O19** A real server answers a wrong user name or password with a plain `AUTH_FAILED` (no reason, no keywords) as a control message after its key exchange message, over UDP and TCP; the client's key exchange has completed by then, so only the message ends the handshake. The `reason` is empty (`TestKeyExchangeWithRealServer`, step 2.3). The other forms (`SESSION:`, `TEMP[...]`, `HALT`, `RESTART`, `AUTH_PENDING`) are tested with the in-process peer only: the server sends them for a script, plugin or management decision that the test server does not make.

## 22. After 1.0

Not planned in detail; each becomes a milestone in `docs/IMPLEMENTATION.md` when the owner asks for it.
- **Older servers:** the key derivation of servers before 2.6 (`ssl.c`, the OpenVPN PRF); `comp-lzo no` and the compression stubs, which add a framing byte and no compression.
- **System tunnel (`tun`):** Linux (`/dev/net/tun`, netlink), Windows (Wintun, which needs its DLL and administrator rights, on a real Windows machine), macOS (`utun`, on a Mac).
- **Proxies:** `http-proxy`, `socks-proxy`.
- **A reconnecting client:** `connect-retry`, `RESTART` handling, keeping the connections of `vpnnet` over a reconnect.
- **`PUSH_UPDATE`**, **`AUTH_PENDING` with web authentication and challenge/response**, **CBC ciphers**, **peer-to-peer mode**.
- **The draft's `CONTROL_V2` probes and `CONTROL_AUX_V1`**, when a released server has them.

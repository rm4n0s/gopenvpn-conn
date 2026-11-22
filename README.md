# gopenvpn-conn

An OpenVPN client library for Go, with the patterns of the standard library. It is
pure Go (no cgo, no `unsafe` of its own), needs no root and changes nothing on the
machine, and works on Linux, Windows and macOS.

> This is a library that speaks the OpenVPN protocol as a client. It is not
> OpenVPN's own program, it is not affiliated with OpenVPN Inc, and OpenVPN is a
> trademark of OpenVPN Inc.

**Status: release candidate of 1.0 (`v1.0.0-rc.1`).** The tunnel (package `openvpn`), the
profile parser (`ovpn`) and the userspace network (`vpnnet`) are complete and were run
against a real OpenVPN 2.7.9 server on Linux, and, under Wine, on Windows. macOS is checked
by building and vetting for it; its tests are for a Mac. `docs/SPEC.md` is the
specification, `docs/IMPLEMENTATION.md` the plan, and `docs/IMPLEMENTED.md` the log of
what is done and how it was shown to work.

## Three layers

Each layer works without the ones above it.

| Package | What it gives |
|---|---|
| `openvpn` | The tunnel: `openvpn.Dial` returns a `*openvpn.Conn`, a `net.Conn` whose `Read` returns one IP packet from the VPN and whose `Write` sends one |
| `ovpn` | The parser of `.ovpn` profiles: a profile becomes a `Config` and a list of remotes, and `Profile.Dial` connects |
| `vpnnet` | A userspace network over a `Conn`: `DialContext`, `Listen`, `ListenPacket` and a `*net.Resolver` that go through the VPN, with no TUN device and no root; only the connections of the program use the VPN |

### A web page through the VPN, from a profile

```go
profile, err := ovpn.ParseFS(os.DirFS("/etc/openvpn/client"), "work.ovpn")
if err != nil {
	log.Fatal(err)
}
conn, err := profile.Dial(ctx) // tries the remotes of the profile in order
if err != nil {
	log.Fatal(err)
}
n, err := vpnnet.New(conn, &vpnnet.Options{CloseConn: true})
if err != nil {
	log.Fatal(err)
}
defer n.Close()

// The name is looked up through the VPN, with the DNS servers that the server
// pushed, and the connection goes through it too.
client := &http.Client{Transport: &http.Transport{DialContext: n.DialContext}}
resp, err := client.Get("http://intranet.example.com/")
```

`ovpn.ParseFS` reads the files that the profile names (`ca`, `cert`, `key`, `tls-crypt`,
`auth-user-pass`) from the directory of the profile and from nowhere else. A profile
with `auth-user-pass` and no file leaves the password to the program: set
`profile.Config.Credentials`. Options that the library cannot honor are refused with an
error that names the option and its line (`profile.Ignored` lists the ones that were
accepted and do nothing). `vpnnet` listens too: `n.Listen("tcp", ":8080")` is reached by
the other machines of the VPN at the client's tunnel address. See `ovpn/example_test.go`,
`vpnnet/example_test.go` and `examples/http`:

```
go run ./examples/http -profile client.ovpn -url http://intranet.example.com/
```

### The tunnel on its own

`openvpn.Dial` works as `tls.Dial` does.

```go
config := &openvpn.Config{
	// The server's certificate must lead to the CA, as in an OpenVPN profile.
	TLS: openvpn.NewTLSConfig(openvpn.TLSOptions{
		RootCAs:             roots,
		Certificates:        []tls.Certificate{cert},
		RemoteCertTLSServer: true,
	}),
	ControlWrap: wrap, // openvpn.NewTLSCrypt(key), NewTLSAuth, NewTLSCryptV2; nil for none
}
conn, err := openvpn.Dial(ctx, "udp", "vpn.example.com:1194", config)
if err != nil {
	log.Fatal(err)
}
defer conn.Close()

state := conn.ConnectionState() // the address, routes, DNS servers and MTU the server pushed
packet := make([]byte, state.MTU)
n, err := conn.Read(packet) // one IP packet
```

`openvpn.Client(conn, config)` and `openvpn.PacketClient(conn, config)` do the same over
a connection that you made (a stream, or a connected datagram socket), as `tls.Client`
does. Deadlines, `Close` and the errors of `Read` and `Write` follow `net.Conn`:
`io.EOF` when the server leaves, `net.ErrClosed` after `Close`, `os.ErrDeadlineExceeded`
for a deadline. Every other error is tagged, so a program can branch on it with
`errors.FromError` (the tags are the `Tag...` constants of the packages). See
`example_test.go` and `examples/ping`, which sends ICMP echo requests through the
tunnel:

```
go run ./examples/ping -server vpn.example.com:1194 -ca ca.crt -cert client.crt -key client.key -tls-crypt ta.key
```

A `Conn` is one session: when it ends (the server says so, the keepalive times out, the
link fails) `Read` and `Write` return the error and the program dials again.

## What it supports

The target of 1.0 is a modern client; the reference server is OpenVPN 2.7.9, and servers
from 2.6 on are expected to work.

| Supported | Not in 1.0 |
|---|---|
| UDP and TCP, IPv4 and IPv6 | HTTP and SOCKS proxies (a custom dial function can do it) |
| TLS 1.2 and 1.3 through `crypto/tls` | TLS below 1.2 |
| `tls-auth`, `tls-crypt`, `tls-crypt-v2`, or no protection of the control channel; dynamic `tls-crypt` at renegotiations | |
| AES-128/192/256-GCM and CHACHA20-POLY1305, with both AEAD packet formats (32-bit packet ids and epochs) | CBC, CFB and OFB ciphers |
| Cipher negotiation, data keys from the TLS exporter | The old key derivation (servers before 2.6) |
| Certificates, `auth-user-pass`, `auth-token`, `verify-x509-name`, `peer-fingerprint` | Challenge/response, web authentication, PKCS#11 |
| Pushed options, keepalive, renegotiation without a lost packet, exit notification | `PUSH_UPDATE`, compression, `fragment`, static-key mode, `--dev tap` |
| Profiles: `remote`, `remote-random`, `connect-timeout`, `<connection>` blocks, inline files, `pull-filter`, `route-nopull` | A system TUN device (`tun`, after 1.0) |

A reconnecting client is after 1.0. The userspace network has one known limit under a very
lossy tunnel (SPEC §13, "Known limit"): a TCP connection with both directions saturated
can stall for minutes when about a fifth of the tunnel's packets are lost; put a deadline on
connections on such a link.

## Testing

```
go test -race ./...                       # unit tests: no openvpn binary, no privileges
CGO_ENABLED=0 go test ./...               # the same without cgo
scripts/vpn-ns.sh -- go test -race -tags gopenvpn_server ./...   # against a real OpenVPN server
scripts/test-windows.sh                   # the unit tests for Windows, under Wine
scripts/check.sh                          # every check of the definition of done
```

The unit tests run the client against a server written for the tests, in the same
process, on a fake clock (`testing/synctest`). The tests against the real server need
`openvpn` installed; `scripts/vpn-ns.sh` runs them in a private user and network
namespace, with no root, where the server and the client talk over the loopback. The
soak tests (loss, reordering, an hour of renegotiations) are listed in `CLAUDE.md`.

The `go` line of `go.mod` is 1.27.3, the version that gVisor's `go` branch needs
(SPEC §18).

## License

GPL-2.0-only, with the linking exception for Apache-2.0 code in `NOTICE`. The library is
derived from the client side of OpenVPN 2, which has the same license. **A program that
uses the library and is distributed must be distributed under the GPL-2.0 as a whole.**
See `LICENSE` and `NOTICE`.

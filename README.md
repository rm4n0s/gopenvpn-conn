# gopenvpn-conn

An OpenVPN client library for Go, with the patterns of the standard library. It is
pure Go (no cgo, no `unsafe`), needs no root and changes nothing on the machine, and
works on Linux, Windows and macOS.

> This is a library that speaks the OpenVPN protocol as a client. It is not
> OpenVPN's own program, it is not affiliated with OpenVPN Inc, and OpenVPN is a
> trademark of OpenVPN Inc.

**Status: pre-1.0 (`v0.2.0`).** The tunnel (package `openvpn`) is complete. The
profile parser (`ovpn`) and the userspace network (`vpnnet`) are the next milestone;
this README grows with them. `docs/SPEC.md` is the specification, `docs/IMPLEMENTATION.md`
the plan, and `docs/IMPLEMENTED.md` the log of what is done and how it was shown to work.

## The tunnel

`openvpn.Dial` works as `tls.Dial` does. It returns a `*openvpn.Conn`, a `net.Conn` whose
`Read` returns one IP packet from the VPN and whose `Write` sends one.

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
`errors.FromError` (the tags are the `Tag...` constants of the package). See
`example_test.go` and `examples/ping`, which sends ICMP echo requests through the
tunnel:

```
go run ./examples/ping -server vpn.example.com:1194 -ca ca.crt -cert client.crt -key client.key -tls-crypt ta.key
```

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
| Certificates, `auth-user-pass`, `auth-token` | Challenge/response, web authentication, PKCS#11 |
| Pushed options, keepalive, renegotiation without a lost packet, exit notification | `PUSH_UPDATE`, compression, `fragment`, static-key mode, `--dev tap` |

A `Conn` is one session: when it ends (the server says so, the keepalive times out, the
link fails) `Read` and `Write` return the error and the program dials again.

## Testing

```
go test -race ./...                       # unit tests: no openvpn binary, no privileges
CGO_ENABLED=0 go test ./...               # the same without cgo
scripts/vpn-ns.sh -- go test -race -tags gopenvpn_server ./...   # against a real OpenVPN server
scripts/check.sh                          # every check of the definition of done
```

The unit tests run the client against a server written for the tests, in the same
process, on a fake clock (`testing/synctest`). The tests against the real server need
`openvpn` installed; `scripts/vpn-ns.sh` runs them in a private user and network
namespace, with no root, where the server and the client talk over the loopback.

## License

GPL-2.0-only, with the linking exception for Apache-2.0 code in `NOTICE`. The library is
derived from the client side of OpenVPN 2, which has the same license. **A program that
uses the library and is distributed must be distributed under the GPL-2.0 as a whole.**
See `LICENSE` and `NOTICE`.

// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server && gopenvpn_soak

package vpnnet

// Not part of scripts/check.sh; run by hand in the namespace (CLAUDE.md, Commands):
//
//	scripts/vpn-ns.sh -- go test -tags 'gopenvpn_server gopenvpn_soak' -run Soak -timeout 3h -v ./vpnnet

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// TestSoakNetem moves 10 MiB each way through a TCP connection of vpnnet, with the
// loopback losing a tenth of the packets, delaying, reordering and duplicating them,
// over a tunnel on UDP and on TCP: what arrives is what was sent (compared by hash), and
// the tunnel ends the test alive. The two directions go one after the other: the
// client sends 10 MiB and the server answers with 10 MiB. (Both at once, as an echo
// server does, is the case of SPEC §13 "Known limit": with a fifth of the packets
// lost, the Linux end shrinks its window below what gVisor has sent, drops the
// acknowledgements that follow as out of window, and the connection stands still for
// minutes. It works with 5% loss.)
func TestSoakNetem(t *testing.T) {
	const size = 10 << 20
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			servertest.Netem(t, "loss 10% delay 20ms reorder 25% duplicate 5%")
			n, conn, srv := realNet(t, proto)
			data := payload(size)
			want := sha256.Sum256(data)

			// The server reads 10 MiB, checks its hash and sends 10 MiB back.
			l := listenOnTunnel(t, "tcp4", net.JoinHostPort(srv.TunnelIP().String(), "0"))
			upload := make(chan [sha256.Size]byte, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer closeIgnoringClosed(t, c)
				h := sha256.New()
				if _, err := io.CopyN(h, c, size); err != nil {
					t.Logf("server read: %v", err)
					return
				}
				var got [sha256.Size]byte
				copy(got[:], h.Sum(nil))
				upload <- got
				if _, err := c.Write(data); err != nil {
					t.Logf("server write: %v", err)
				}
			}()

			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
			defer cancel()
			c, err := n.DialContext(ctx, "tcp4", l.Addr().String())
			if err != nil {
				t.Fatalf("DialContext: %v\nserver log:\n%s", err, srv.Log())
			}
			defer closeOrFail(t, c)
			if dl, ok := ctx.Deadline(); ok {
				if err := c.SetDeadline(dl); err != nil {
					t.Fatal(err)
				}
			}
			start := time.Now()
			if _, err := c.Write(data); err != nil {
				t.Fatalf("Write: %v\nserver log:\n%s", err, srv.Log())
			}
			h := sha256.New()
			if got, err := io.CopyN(h, c, size); err != nil {
				t.Fatalf("read %d of %d bytes: %v\nserver log:\n%s", got, size, err, srv.Log())
			}
			var got [sha256.Size]byte
			copy(got[:], h.Sum(nil))
			if got != want {
				t.Error("the 10 MiB that came back are not the 10 MiB that went")
			}
			select {
			case up := <-upload:
				if up != want {
					t.Error("the 10 MiB that the server got are not the 10 MiB that went")
				}
			default:
				t.Error("the server did not get the upload")
			}
			t.Logf("%s tunnel: 10 MiB each way in %v under netem", proto, time.Since(start).Round(100*time.Millisecond))
			// The tunnel is still alive: the Conn did not end.
			if _, err := conn.Write([]byte{0x45}); err != nil {
				t.Errorf("the Conn ended: %v", err)
			}
		})
	}
}

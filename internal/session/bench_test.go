// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// discardLink is the client's end of a link that can be told to throw away what the
// client writes, so that a benchmark of Write measures the client alone.
type discardLink struct {
	net.Conn
	discard atomic.Bool
}

func (d *discardLink) Write(p []byte) (int, error) {
	if d.discard.Load() {
		return len(p), nil
	}
	return d.Conn.Write(p)
}

// benchRig is a session whose handshake is done, over a datagram link.
func benchRig(b *testing.B, epoch bool) (*tlsRig, *discardLink) {
	b.Helper()
	var link *discardLink
	push := vpntest.DefaultPushReply
	if epoch {
		push = epochPush("AES-256-GCM")
	}
	r := newTLSRig(&testing.T{}, tlsOptions{
		rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{PushMessages: []string{push}, Epoch: epoch}},
		wrapLink: func(c net.Conn) net.Conn {
			link = &discardLink{Conn: c}
			return link
		},
	})
	if err := r.session.Handshake(b.Context()); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := r.session.Close(); err != nil {
			b.Error(err)
		}
		r.server.Close()
	})
	return r, link
}

// BenchmarkWrite is Write of one packet of 1400 bytes: the sealing and the write to
// the link, which discards it.
func BenchmarkWrite(b *testing.B) {
	for _, tc := range []struct {
		name  string
		epoch bool
	}{{"32-bit packet ids", false}, {"epochs", true}} {
		b.Run(tc.name, func(b *testing.B) {
			r, link := benchRig(b, tc.epoch)
			link.discard.Store(true)
			packet := make([]byte, 1400)
			packet[0] = 0x45
			b.SetBytes(int64(len(packet)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := r.session.Write(packet); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkRead is Read of one packet of 1400 bytes that the loop has opened. The
// packets come in batches that the server sends while the timer is stopped, so that
// what is counted is the client's: the pool, the channel and the copy.
func BenchmarkRead(b *testing.B) {
	for _, tc := range []struct {
		name  string
		epoch bool
	}{{"32-bit packet ids", false}, {"epochs", true}} {
		b.Run(tc.name, func(b *testing.B) {
			r, _ := benchRig(b, tc.epoch)
			const batch = 256
			payload := make([]byte, 1400)
			payload[0] = 0x45
			buf := make([]byte, 2000)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for done := 0; done < b.N; {
				n := min(batch, b.N-done)
				b.StopTimer()
				for range n {
					if _, err := r.server.SendData(payload); err != nil {
						b.Fatal(err)
					}
				}
				for len(r.session.recv) < n {
					time.Sleep(20 * time.Microsecond)
				}
				b.StartTimer()
				for range n {
					if _, err := r.session.Read(buf); err != nil {
						b.Fatal(err)
					}
				}
				done += n
			}
		})
	}
}

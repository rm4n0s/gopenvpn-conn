// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// *Conn is a net.Conn.
var _ net.Conn = (*Conn)(nil)

func contractConn(t *testing.T, k kind) (*Conn, *vpntest.Server) {
	t.Helper()
	pki := servertest.NewPKI(t)
	link, srv := tlsPairWith(t, k, protections()[0], serverTLS(pki, pki.ServerCert), func(o *vpntest.ServerOptions) {
		o.PushMessages = []string{vpntest.DefaultPushReply + ",protocol-flags cc-exit tls-ekm"}
	})
	cfg := &Config{TLS: NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}})}
	if k.stream {
		return Client(link, cfg), srv
	}
	return PacketClient(link, cfg), srv
}

// TestStandardErrorValues is the table of SPEC §5.3: each of the three values comes
// back as itself, compared with ==, as the standard library compares them.
func TestStandardErrorValues(t *testing.T) {
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			t.Run("io.EOF after the server's EXIT", func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					conn, srv := contractConn(t, k)
					if err := conn.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					srv.SendControl("EXIT")
					if _, err := conn.Read(make([]byte, 10)); err != io.EOF {
						t.Errorf("Read = %v, want io.EOF", err)
					}
					if err := conn.Close(); err != nil {
						t.Errorf("Close after the server's EXIT = %v", err)
					}
				})
			})
			t.Run("io.Copy ends cleanly at the server's EXIT", func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					conn, srv := contractConn(t, k)
					if err := conn.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					for i := range 3 {
						if _, err := srv.SendData([]byte{0x45, byte(i)}); err != nil {
							t.Fatal(err)
						}
					}
					done := make(chan struct{})
					var n int64
					var err error
					go func() { n, err = io.Copy(io.Discard, conn); close(done) }()
					synctest.Wait()
					srv.SendControl("EXIT")
					<-done
					if err != nil || n != 6 {
						t.Errorf("io.Copy = %d, %v, want 6 bytes and nil", n, err)
					}
					if cerr := conn.Close(); cerr != nil {
						t.Errorf("Close = %v", cerr)
					}
				})
			})
			t.Run("net.ErrClosed from every method after Close", func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					conn, _ := contractConn(t, k)
					if err := conn.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					if err := conn.Close(); err != nil {
						t.Fatal(err)
					}
					calls := map[string]func() error{
						"Read":             func() error { _, err := conn.Read(make([]byte, 10)); return err },
						"Write":            func() error { _, err := conn.Write([]byte{0x45}); return err },
						"Close":            conn.Close,
						"SetDeadline":      func() error { return conn.SetDeadline(time.Now()) },
						"SetReadDeadline":  func() error { return conn.SetReadDeadline(time.Now()) },
						"SetWriteDeadline": func() error { return conn.SetWriteDeadline(time.Now()) },
						"HandshakeContext": func() error { return conn.HandshakeContext(t.Context()) },
					}
					for name, call := range calls {
						if err := call(); err != net.ErrClosed {
							t.Errorf("%s after Close = %v, want net.ErrClosed itself", name, err)
						}
					}
				})
			})
			t.Run("os.ErrDeadlineExceeded when a deadline passes", func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					conn, _ := contractConn(t, k)
					closeAtEnd(t, conn)
					if err := conn.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					_, err := conn.Read(make([]byte, 10))
					if err != os.ErrDeadlineExceeded {
						t.Fatalf("Read = %v, want os.ErrDeadlineExceeded itself", err)
					}
					var netErr net.Error
					if !errors.As(err, &netErr) || !netErr.Timeout() {
						t.Errorf("errors.As(%v, net.Error) with Timeout true failed", err)
					}
					if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
						t.Fatal(err)
					}
					if _, err := conn.Write([]byte{0x45}); err != os.ErrDeadlineExceeded {
						t.Errorf("Write = %v, want os.ErrDeadlineExceeded itself", err)
					}
				})
			})
		})
	}
}

func TestCloseStopsEveryGoroutineOfAConn(t *testing.T) {
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				before := vpntest.BubbleGoroutines()
				conn, srv := contractConn(t, k)
				if err := conn.HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Write([]byte{0x45}); err != nil {
					t.Fatal(err)
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
				srv.Close()
				synctest.Wait()
				if after := vpntest.BubbleGoroutines(); after != before {
					t.Errorf("%d goroutines before, %d after Close", before, after)
				}
			})
		})
	}
}

// TestNoLeakAfterManyConnections opens and closes 200 connections (over both links,
// with a packet each way), each in a bubble of its own, and checks that the goroutines
// are the ones of the start and that the heap has not grown by anything near a
// connection each: SPEC §17.
func TestNoLeakAfterManyConnections(t *testing.T) {
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			cycle := func(t *testing.T) {
				pki := servertest.NewPKI(t) // in the bubble: its certificates are valid at the bubble's time
				link, srv := tlsPairWith(t, k, protections()[0], serverTLS(pki, pki.ServerCert), func(o *vpntest.ServerOptions) {
					o.EchoData = true
					o.PushMessages = []string{vpntest.DefaultPushReply + ",protocol-flags cc-exit tls-ekm"}
				})
				cfg := &Config{TLS: NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}})}
				var conn *Conn
				if k.stream {
					conn = Client(link, cfg)
				} else {
					conn = PacketClient(link, cfg)
				}
				if _, err := conn.Write([]byte{0x45, 1, 2, 3}); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 100)
				if _, err := conn.Read(buf); err != nil {
					t.Fatal(err)
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
				srv.Close()
			}
			heap := func() uint64 {
				runtime.GC()
				runtime.GC()
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				return m.HeapAlloc
			}
			for range 5 { // warm up: the first connections allocate what the runtime keeps
				synctest.Test(t, cycle)
			}
			goroutines, before := runtime.NumGoroutine(), heap()
			for range 200 {
				synctest.Test(t, cycle)
			}
			if after := runtime.NumGoroutine(); after != goroutines {
				t.Errorf("%d goroutines before 200 connections, %d after", goroutines, after)
			}
			after := heap()
			var growth uint64
			if after > before {
				growth = after - before
			}
			t.Logf("heap: %d bytes before, %d after", before, after)
			if growth > 2<<20 {
				t.Errorf("the heap grew by %d bytes in 200 connections: about %d bytes each", growth, growth/200)
			}
		})
	}
}

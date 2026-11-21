// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"bytes"
	"context"
	"crypto"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlwrap"
	"github.com/rm4n0s/gopenvpn-conn/internal/keys"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

func readFile(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join("internal", "keys", "testdata", name)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// protection is a control channel protection: the ControlWrap of the Config and
// the server's end of it.
type protection struct {
	name   string
	wrap   func(t testing.TB) ControlWrap
	server func(t testing.TB) ctrlwrap.Wrapper
	v3     bool // the server asks for the wrapped key
}

// must returns v, or panics with err, which the test run reports as a failure.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func staticKey(t testing.TB) *keys.StaticKey {
	return must(keys.ParseStaticKey(bytes.NewReader(readFile(t, "ta.key"))))
}

func v2Key(t testing.TB) *keys.TLSCryptV2ClientKey {
	return must(keys.ParseTLSCryptV2ClientKey(bytes.NewReader(readFile(t, "tls-crypt-v2-client.key"))))
}

func protections() []protection {
	return []protection{
		{
			name:   "none",
			wrap:   func(testing.TB) ControlWrap { return nil },
			server: func(testing.TB) ctrlwrap.Wrapper { return ctrlwrap.NewPlain() },
		},
		{
			name: "tls-auth SHA-1, no direction",
			wrap: func(t testing.TB) ControlWrap {
				return must(NewTLSAuth(readFile(t, "ta.key"), KeyDirectionNone, crypto.SHA1))
			},
			server: func(t testing.TB) ctrlwrap.Wrapper {
				h := must(ctrlwrap.HashFor(crypto.SHA1))
				return must(ctrlwrap.NewTLSAuth(staticKey(t), keys.Bidirectional, h, time.Now))
			},
		},
		{
			name: "tls-auth SHA-256, key-direction 1",
			wrap: func(t testing.TB) ControlWrap {
				return must(NewTLSAuth(readFile(t, "ta.key"), KeyDirection1, crypto.SHA256))
			},
			server: func(t testing.TB) ctrlwrap.Wrapper {
				h := must(ctrlwrap.HashFor(crypto.SHA256))
				return must(ctrlwrap.NewTLSAuth(staticKey(t), keys.Normal, h, time.Now))
			},
		},
		{
			name: "tls-crypt",
			wrap: func(t testing.TB) ControlWrap { return must(NewTLSCrypt(readFile(t, "ta.key"))) },
			server: func(t testing.TB) ctrlwrap.Wrapper {
				return must(ctrlwrap.NewTLSCryptServer(staticKey(t), time.Now))
			},
		},
		{
			name: "tls-crypt-v2",
			wrap: func(t testing.TB) ControlWrap {
				return must(NewTLSCryptV2(readFile(t, "tls-crypt-v2-client.key")))
			},
			server: func(t testing.TB) ctrlwrap.Wrapper {
				return must(ctrlwrap.NewTLSCryptServer(&v2Key(t).Kc, time.Now))
			},
			v3: true,
		},
	}
}

type kind struct {
	name   string
	stream bool
}

var kinds = []kind{{"PacketClient", false}, {"Client", true}}

// pair makes the two ends of a link and a server on the far end.
func pair(t *testing.T, k kind, p protection, fault vpntest.Fault) (client net.Conn, server *vpntest.Server) {
	t.Helper()
	var peer net.Conn
	if k.stream {
		client, peer = vpntest.NewStreamPair()
	} else {
		client, peer = vpntest.NewDatagramPair(vpntest.LinkOptions{})
	}
	wkc := 0
	if p.v3 {
		wkc = len(v2Key(t).WKc)
	}
	server = vpntest.NewServer(t, peer, vpntest.ServerOptions{
		Stream: k.stream, Wrapper: p.server(t), WKcLen: wkc, AskForWKc: p.v3, Fault: fault,
	})
	return client, server
}

func newClient(k kind, link net.Conn, cfg *Config) *Conn {
	if k.stream {
		return Client(link, cfg)
	}
	return PacketClient(link, cfg)
}

func TestHandshake(t *testing.T) {
	for _, k := range kinds {
		for _, p := range protections() {
			t.Run(k.name+"/"+p.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					before := runtime.NumGoroutine()
					link, server := pair(t, k, p, vpntest.NoFault)
					cfg := &Config{ControlWrap: p.wrap(t)}
					conn := newClient(k, link, cfg)
					if err := conn.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					if conn.NetConn() != link {
						t.Error("NetConn is not the connection that was given")
					}
					if conn.LocalAddr() != link.LocalAddr() || conn.RemoteAddr() != link.RemoteAddr() {
						t.Error("the addresses are not those of the link")
					}
					if err := conn.Close(); err != nil {
						t.Fatalf("Close: %v", err)
					}
					if err := conn.HandshakeContext(t.Context()); err != net.ErrClosed {
						t.Errorf("HandshakeContext after Close = %v, want net.ErrClosed", err)
					}
					if err := conn.Close(); err != net.ErrClosed {
						t.Errorf("a second Close = %v, want net.ErrClosed", err)
					}
					server.Close()
					synctest.Wait()
					if after := runtime.NumGoroutine(); after != before {
						t.Errorf("%d goroutines before, %d after Close", before, after)
					}
				})
			})
		}
	}
}

func TestNilConfigIsTheZeroConfig(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link, _ := pair(t, kinds[0], protections()[0], vpntest.NoFault)
		conn := PacketClient(link, nil)
		closeAtEnd(t, conn)
		if err := conn.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestHandshakeTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"the default", 0, DefaultHandshakeTimeout},
		{"the config's", 7 * time.Second, 7 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				link, _ := pair(t, kinds[0], protections()[0], vpntest.Silent)
				conn := PacketClient(link, &Config{HandshakeTimeout: tt.timeout})
				closeAtEnd(t, conn)
				start := time.Now()
				err := conn.HandshakeContext(t.Context())
				appErr, ok := errors.FromError(err)
				if !ok {
					t.Fatalf("expected *errors.Error, got %T: %v", err, err)
				}
				if appErr.Tag != TagHandshakeTimeout {
					t.Errorf("tag = %s, want %s (route %s)", appErr.Tag, TagHandshakeTimeout, appErr.Route())
				}
				if elapsed := time.Since(start); elapsed != tt.want {
					t.Errorf("failed after %v, want %v", elapsed, tt.want)
				}
			})
		})
	}
}

func TestHandshakeCanceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link, _ := pair(t, kinds[0], protections()[0], vpntest.Silent)
		conn := PacketClient(link, nil)
		closeAtEnd(t, conn)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := conn.HandshakeContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("HandshakeContext = %v, want context.DeadlineExceeded", err)
		}
	})
}

func TestConfigCanBeSharedAndIsNotChanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := protections()[4]
		cfg := &Config{ControlWrap: p.wrap(t), HandshakeTimeout: time.Minute}
		want := *cfg
		for i := 0; i < 3; i++ {
			link, _ := pair(t, kinds[0], p, vpntest.NoFault)
			conn := PacketClient(link, cfg)
			if err := conn.HandshakeContext(t.Context()); err != nil {
				t.Fatalf("connection %d: %v", i, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if !reflect.DeepEqual(*cfg, want) {
			t.Error("the Config was changed")
		}
	})
}

func TestInvalidConfig(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link, _ := pair(t, kinds[0], protections()[0], vpntest.NoFault)
		conn := PacketClient(link, &Config{HandshakeTimeout: -time.Second})
		err := conn.HandshakeContext(t.Context())
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != tagInvalidConfig || !appErr.HasRoute("PacketClient->newConn.InvalidConfig") {
			t.Fatalf("HandshakeContext = %v, want an invalid config", err)
		}
		if appErr.Metadata["field"] != "HandshakeTimeout" {
			t.Errorf("metadata = %v", appErr.Metadata)
		}
		if err := conn.Close(); err != nil {
			t.Errorf("Close = %v", err)
		}
		if _, werr := link.Write([]byte("x")); werr != net.ErrClosed {
			t.Errorf("Close left the link open: %v", werr)
		}
	})
}

func TestConstructorErrors(t *testing.T) {
	good := readFile(t, "ta.key")
	garbage := []byte("this is not a key file")
	tests := []struct {
		name  string
		build func() (ControlWrap, error)
		route string
	}{
		{"tls-auth, no key", func() (ControlWrap, error) { return NewTLSAuth(garbage, KeyDirection1, crypto.SHA256) }, "NewTLSAuth->ParseStaticKey"},
		{"tls-auth, md5", func() (ControlWrap, error) { return NewTLSAuth(good, KeyDirection1, crypto.MD5) }, "NewTLSAuth->HashFor.UnsupportedDigest"},
		{"tls-auth, no digest", func() (ControlWrap, error) { return NewTLSAuth(good, KeyDirection1, 0) }, "NewTLSAuth->HashFor.UnsupportedDigest"},
		{"tls-auth, direction 3", func() (ControlWrap, error) { return NewTLSAuth(good, KeyDirection(3), crypto.SHA1) }, "NewTLSAuth.InvalidKeyDirection"},
		{"tls-auth, direction -1", func() (ControlWrap, error) { return NewTLSAuth(good, KeyDirection(-1), crypto.SHA1) }, "NewTLSAuth.InvalidKeyDirection"},
		{"tls-crypt, no key", func() (ControlWrap, error) { return NewTLSCrypt(garbage) }, "NewTLSCrypt->ParseStaticKey"},
		{"tls-crypt, nothing", func() (ControlWrap, error) { return NewTLSCrypt(nil) }, "NewTLSCrypt->ParseStaticKey"},
		{"tls-crypt-v2, no key", func() (ControlWrap, error) { return NewTLSCryptV2(garbage) }, "NewTLSCryptV2->ParseTLSCryptV2ClientKey"},
		{"tls-crypt-v2, a static key", func() (ControlWrap, error) { return NewTLSCryptV2(good) }, "NewTLSCryptV2->ParseTLSCryptV2ClientKey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := tt.build()
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute(tt.route) {
				t.Errorf("unexpected failure path: %s, want %s", appErr.Route(), tt.route)
			}
			if w != nil {
				t.Error("a ControlWrap came with the error")
			}
		})
	}
}

func TestKeyDirectionNames(t *testing.T) {
	// The values are part of the API of a profile reader: key-direction 0 and 1.
	if KeyDirectionNone != 0 || KeyDirection0 != 1 || KeyDirection1 != 2 {
		t.Error("the values of the key directions changed")
	}
}

// closeAtEnd closes c when the test ends; a connection that is closed already is fine.
func closeAtEnd(t testing.TB, c io.Closer) {
	t.Helper()
	t.Cleanup(func() {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Close: %v", err)
		}
	})
}

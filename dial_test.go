// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// dialerOver is a Dialer whose link is made by the test: one end of a link in
// memory, with the server on the other.
func dialerOver(t *testing.T, k kind, p protection, fault vpntest.Fault, cfg *Config) (*Dialer, *[]string) {
	t.Helper()
	var asked []string
	return &Dialer{
		Config: cfg,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			asked = append(asked, network+" "+address)
			link, _ := pair(t, k, p, fault)
			return link, nil
		},
	}, &asked
}

func TestDialer(t *testing.T) {
	tests := []struct {
		network string
		kind    kind
	}{
		{"udp", kinds[0]}, {"udp4", kinds[0]}, {"udp6", kinds[0]},
		{"tcp", kinds[1]}, {"tcp4", kinds[1]}, {"tcp6", kinds[1]},
	}
	for _, tt := range tests {
		for _, p := range protections() {
			t.Run(tt.network+"/"+p.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					before := vpntest.BubbleGoroutines()
					d, asked := dialerOver(t, tt.kind, p, vpntest.NoFault, &Config{ControlWrap: p.wrap(t), resetOnly: true})
					conn, err := d.Dial(t.Context(), tt.network, "vpn.example:1194")
					if err != nil {
						t.Fatal(err)
					}
					if len(*asked) != 1 || (*asked)[0] != tt.network+" vpn.example:1194" {
						t.Errorf("the dial function was asked for %v", *asked)
					}
					if err := conn.Close(); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					// The server of the test is closed by its cleanup, after this
					// function; count only what the connection left behind.
					if after := vpntest.BubbleGoroutines(); after > before+5 {
						t.Errorf("%d goroutines before, %d after Close", before, after)
					}
				})
			})
		}
	}
}

func TestDialFunction(t *testing.T) {
	// Dial uses a net.Dialer: a TCP listener that does not speak OpenVPN gets a
	// connection, and then the handshake times out.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
	}()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = Dial(ctx, "tcp", ln.Addr().String(), &Config{HandshakeTimeout: 300 * time.Millisecond, resetOnly: true})
	appErr, ok := errors.FromError(err)
	if !ok || appErr.Tag != TagHandshakeTimeout {
		t.Fatalf("Dial = %v, want %s", err, TagHandshakeTimeout)
	}
	select {
	case c := <-accepted:
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the listener accepted nothing")
	}
}

// TestDialServerPollTimeout: Config.ServerPollTimeout bounds the making of the link
// and the wait for the first packet of the server, not the handshake.
func TestDialServerPollTimeout(t *testing.T) {
	t.Run("the link is not made in time", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d := Dialer{
				Config: &Config{ServerPollTimeout: 3 * time.Second, resetOnly: true},
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				},
			}
			start := time.Now()
			_, err := d.Dial(t.Context(), "tcp", "vpn.example:1194")
			appErr, ok := errors.FromError(err)
			if !ok || appErr.Tag != TagDialFailed || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Dial = %v, want %s caused by the deadline", err, TagDialFailed)
			}
			if elapsed := time.Since(start); elapsed != 3*time.Second {
				t.Errorf("Dial gave up after %v, want 3s", elapsed)
			}
		})
	})
	for _, k := range kinds {
		t.Run("a server that does not answer, "+k.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := protections()[0]
				d, _ := dialerOver(t, k, p, vpntest.Silent, &Config{ControlWrap: p.wrap(t), resetOnly: true, ServerPollTimeout: 3 * time.Second, HandshakeTimeout: time.Minute})
				start := time.Now()
				network := "udp"
				if k.stream {
					network = "tcp"
				}
				_, err := d.Dial(t.Context(), network, "vpn.example:1194")
				appErr, ok := errors.FromError(err)
				if !ok || appErr.Tag != TagServerPollTimeout || !appErr.HasRoute("Session.loop.ServerPollTimeout") {
					t.Fatalf("Dial = %v, want %s", err, TagServerPollTimeout)
				}
				if elapsed := time.Since(start); elapsed != 3*time.Second {
					t.Errorf("Dial gave up after %v, want 3s", elapsed)
				}
			})
		})
	}
	t.Run("a negative value is refused", func(t *testing.T) {
		if err := (&Config{ServerPollTimeout: -time.Second}).Validate(); err == nil {
			t.Error("a negative ServerPollTimeout is valid")
		}
	})
}

func TestDialUnsupportedNetwork(t *testing.T) {
	for _, network := range []string{"", "unix", "ip", "udp5", "TCP", "tcp "} {
		conn, err := Dial(t.Context(), network, "127.0.0.1:1", nil)
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != TagUnsupportedNetwork || !appErr.HasRoute("Dial->Dialer.Dial.UnsupportedNetwork") {
			t.Errorf("Dial(%q) = %v, want %s", network, err, TagUnsupportedNetwork)
		}
		if conn != nil {
			t.Errorf("Dial(%q) returned a connection", network)
		}
		if ok && appErr.Metadata["network"] != network {
			t.Errorf("Dial(%q): metadata = %v", network, appErr.Metadata)
		}
	}
}

func TestDialFailedToConnect(t *testing.T) {
	t.Run("the dial function fails", func(t *testing.T) {
		d := &Dialer{DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, syscall.ENETUNREACH
		}}
		_, err := d.Dial(t.Context(), "udp", "vpn.example:1194")
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != TagDialFailed || !appErr.HasRoute("Dialer.Dial.DialFailed") || !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatalf("Dial = %v, want %s with ENETUNREACH", err, TagDialFailed)
		}
		if appErr.Metadata["network"] != "udp" || appErr.Metadata["address"] != "vpn.example:1194" {
			t.Errorf("metadata = %v", appErr.Metadata)
		}
	})
	t.Run("a refused connection", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no loopback: %v", err)
		}
		addr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = Dial(t.Context(), "tcp", addr, nil)
		refused := errors.Is(err, syscall.ECONNREFUSED)
		if runtime.GOOS == "windows" {
			// Windows says WSAECONNREFUSED, which is not the value of syscall.ECONNREFUSED:
			// what is left to see is that the dial error of package net is behind the tag.
			var opErr *net.OpError
			refused = errors.As(err, &opErr) && opErr.Op == "dial"
		}
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagDialFailed || !refused {
			t.Fatalf("Dial = %v, want %s with ECONNREFUSED", err, TagDialFailed)
		}
	})
	t.Run("the context is done", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := Dial(ctx, "tcp", "127.0.0.1:1", nil)
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagDialFailed || !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial = %v, want %s with context.Canceled", err, TagDialFailed)
		}
	})
}

func TestDialClosesTheLinkWhenTheHandshakeFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var link net.Conn
		d := &Dialer{
			Config: &Config{HandshakeTimeout: 5 * time.Second, resetOnly: true},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				link, _ = pair(t, kinds[0], protections()[0], vpntest.Silent)
				return link, nil
			},
		}
		start := time.Now()
		conn, err := d.Dial(t.Context(), "udp", "x:1")
		if conn != nil {
			t.Fatal("Dial returned a connection")
		}
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagHandshakeTimeout {
			t.Fatalf("Dial = %v, want %s", err, TagHandshakeTimeout)
		}
		if elapsed := time.Since(start); elapsed != 5*time.Second {
			t.Errorf("Dial failed after %v", elapsed)
		}
		if _, err := link.Write([]byte("x")); err != net.ErrClosed {
			t.Errorf("the link was not closed: Write = %v", err)
		}
	})
}

func TestDialContextOfTheCallerEndsOnlyTheHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, _ := dialerOver(t, kinds[0], protections()[0], vpntest.NoFault, &Config{resetOnly: true})
		ctx, cancel := context.WithCancel(t.Context())
		conn, err := d.Dial(ctx, "udp", "x:1")
		if err != nil {
			t.Fatal(err)
		}
		cancel() // after Dial: the connection goes on
		synctest.Wait()
		if err := conn.HandshakeContext(t.Context()); err != nil {
			t.Errorf("the connection ended with the context of Dial: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

// addressDialer is a Dialer for a name with the addresses that the test gives: the
// lookup returns them, and links[address] makes the link to each (the server on the
// far end is what the test chose). It keeps what was asked of the lookup and of the
// dial function.
func addressDialer(cfg *Config, addrs []string, links map[string]func() (net.Conn, error)) (*Dialer, *[]string) {
	var asked []string
	return &Dialer{
		Config: cfg,
		lookup: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			asked = append(asked, "lookup "+network+" "+host)
			out := make([]netip.Addr, len(addrs))
			for i, a := range addrs {
				out[i] = netip.MustParseAddr(a)
			}
			return out, nil
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			asked = append(asked, network+" "+address)
			return links[address]()
		},
	}, &asked
}

// Over UDP nothing says that a server is at an address before the server answers:
// the dialer of the link "connects" to the first address of a name and stops. Dial
// goes on to the next address when one sends nothing, as OpenVPN does with the
// addresses of a remote.
func TestDialTriesTheAddressesOfAName(t *testing.T) {
	p := protections()[0]
	// A link to a server, made in the bubble of the test that asks for it.
	linkTo := func(t *testing.T, fault vpntest.Fault) func() (net.Conn, error) {
		return func() (net.Conn, error) {
			link, _ := pair(t, kinds[0], p, fault)
			return link, nil
		}
	}
	unreachable := func() (net.Conn, error) { return nil, syscall.ENETUNREACH }
	config := func(t *testing.T) *Config {
		return &Config{ControlWrap: p.wrap(t), resetOnly: true, ServerPollTimeout: 3 * time.Second, HandshakeTimeout: time.Minute}
	}
	t.Run("the third address answers", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, asked := addressDialer(config(t), []string{"192.0.2.1", "2001:db8::2", "192.0.2.3"}, map[string]func() (net.Conn, error){
				"192.0.2.1:1194": linkTo(t, vpntest.Silent), "[2001:db8::2]:1194": unreachable, "192.0.2.3:1194": linkTo(t, vpntest.NoFault),
			})
			start := time.Now()
			conn, err := d.Dial(t.Context(), "udp", "vpn.example:1194")
			if err != nil {
				t.Fatalf("Dial: %v (asked: %v)", err, *asked)
			}
			closeAtEnd(t, conn)
			want := []string{"lookup ip vpn.example", "udp 192.0.2.1:1194", "udp [2001:db8::2]:1194", "udp 192.0.2.3:1194"}
			if !slices.Equal(*asked, want) {
				t.Errorf("asked %v, want %v", *asked, want)
			}
			if elapsed := time.Since(start); elapsed != 3*time.Second {
				t.Errorf("Dial took %v, want the 3s of the address that was silent", elapsed)
			}
		})
	})
	t.Run("no address answers", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, asked := addressDialer(config(t), []string{"192.0.2.1", "192.0.2.2"}, map[string]func() (net.Conn, error){
				"192.0.2.1:1194": linkTo(t, vpntest.Silent), "192.0.2.2:1194": linkTo(t, vpntest.Silent),
			})
			start := time.Now()
			_, err := d.Dial(t.Context(), "udp4", "vpn.example:1194")
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute("Session.loop.ServerPollTimeout") {
				t.Errorf("unexpected failure path: %s", appErr.Route())
			}
			if appErr.Metadata["addresses"] != 2 || appErr.Metadata["addresses_tried"] != 2 {
				t.Errorf("metadata = %v, want 2 addresses, 2 tried", appErr.Metadata)
			}
			if want := []string{"lookup ip4 vpn.example", "udp4 192.0.2.1:1194", "udp4 192.0.2.2:1194"}; !slices.Equal(*asked, want) {
				t.Errorf("asked %v, want %v", *asked, want)
			}
			if elapsed := time.Since(start); elapsed != 6*time.Second {
				t.Errorf("Dial took %v, want 3s for each of the two addresses", elapsed)
			}
		})
	})
	t.Run("no address can be reached", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, _ := addressDialer(config(t), []string{"2001:db8::1", "2001:db8::2"}, map[string]func() (net.Conn, error){
				"[2001:db8::1]:1194": unreachable, "[2001:db8::2]:1194": unreachable,
			})
			_, err := d.Dial(t.Context(), "udp6", "vpn.example:1194")
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute("Dialer.Dial.DialFailed") || !errors.Is(err, syscall.ENETUNREACH) {
				t.Errorf("unexpected failure path: %s (%v)", appErr.Route(), err)
			}
			if appErr.Metadata["address"] != "vpn.example:1194" || appErr.Metadata["addresses_tried"] != 2 {
				t.Errorf("metadata = %v", appErr.Metadata)
			}
		})
	})
	t.Run("a server that answered and failed is the answer", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// The server at the first address is there, and its certificate is of another CA.
			pki, other := servertest.NewPKI(t), servertest.NewPKI(t)
			cfg := &Config{
				TLS:               NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}}),
				ServerPollTimeout: 3 * time.Second,
			}
			d, asked := addressDialer(cfg, []string{"192.0.2.1", "192.0.2.2"}, map[string]func() (net.Conn, error){
				"192.0.2.1:1194": func() (net.Conn, error) {
					link, _ := tlsPair(t, kinds[0], p, serverTLS(other, other.ServerCert))
					return link, nil
				},
				"192.0.2.2:1194": func() (net.Conn, error) {
					t.Error("the next address was tried after a server had answered")
					return nil, syscall.ENETUNREACH
				},
			})
			_, err := d.Dial(t.Context(), "udp", "vpn.example:1194")
			appErr, ok := errors.FromError(err)
			if !ok || appErr.Tag != TagTLSHandshakeFailed {
				t.Fatalf("Dial = %v, want %s", err, TagTLSHandshakeFailed)
			}
			if appErr.Metadata["addresses_tried"] != 1 {
				t.Errorf("metadata = %v, want 1 address tried", appErr.Metadata)
			}
			if len(*asked) != 2 {
				t.Errorf("asked %v", *asked)
			}
		})
	})
	t.Run("the caller gives up at the first address", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, asked := addressDialer(config(t), []string{"192.0.2.1", "192.0.2.2"}, map[string]func() (net.Conn, error){
				"192.0.2.1:1194": linkTo(t, vpntest.Silent), "192.0.2.2:1194": linkTo(t, vpntest.NoFault),
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if _, err := d.Dial(ctx, "udp", "vpn.example:1194"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Dial = %v, want the deadline of the caller", err)
			}
			if len(*asked) != 2 {
				t.Errorf("asked %v, want the lookup and the first address", *asked)
			}
		})
	})
	t.Run("the lookup fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			cause := &net.DNSError{Err: "no such host", Name: "vpn.example", IsNotFound: true}
			d := &Dialer{
				Config: config(t),
				lookup: func(context.Context, string, string) ([]netip.Addr, error) { return nil, cause },
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					t.Error("a link was dialed for a name with no address")
					return nil, syscall.ENETUNREACH
				},
			}
			_, err := d.Dial(t.Context(), "udp", "vpn.example:1194")
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute("Dialer.Dial.DialFailed") || !errors.Is(err, cause) {
				t.Errorf("unexpected failure path: %s (%v)", appErr.Route(), err)
			}
		})
	})
	t.Run("what is not looked up", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			for _, row := range []struct{ network, address string }{
				{"udp", "192.0.2.9:1194"},     // an address
				{"udp", "[2001:db8::9]:1194"}, // an address
				{"tcp", "vpn.example:1194"},   // a stream: the dialer of the link tries the addresses
				{"udp", "vpn.example"},        // no port: the dialer of the link says so
			} {
				var asked []string
				d := &Dialer{
					Config: config(t),
					lookup: func(context.Context, string, string) ([]netip.Addr, error) {
						t.Errorf("%s %s was looked up", row.network, row.address)
						return nil, syscall.ENETUNREACH
					},
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						asked = append(asked, network+" "+address)
						return nil, syscall.ENETUNREACH
					},
				}
				if _, err := d.Dial(t.Context(), row.network, row.address); !errors.Is(err, syscall.ENETUNREACH) {
					t.Errorf("%s %s: Dial = %v", row.network, row.address, err)
				}
				if want := []string{row.network + " " + row.address}; !slices.Equal(asked, want) {
					t.Errorf("the dial function was asked for %v, want %v", asked, want)
				}
			}
		})
	})
}

// With DialContext the name is not looked up: the function gets it as Dial did.
func TestDialContextGetsTheName(t *testing.T) {
	d := &Dialer{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ENETUNREACH }}
	if lookup, _, _ := d.lookupFor("udp", "vpn.example:1194", false); lookup != nil {
		t.Error("a name is looked up though DialContext is set")
	}
	d = &Dialer{}
	if lookup, host, port := d.lookupFor("udp", "vpn.example:1194", false); lookup == nil || host != "vpn.example" || port != "1194" {
		t.Errorf("a name over UDP is not looked up by Dial: %q %q", host, port)
	}
	resolver := &net.Resolver{}
	d = &Dialer{NetDialer: &net.Dialer{Resolver: resolver}}
	if lookup, _, _ := d.lookupFor("udp", "vpn.example:1194", false); lookup == nil {
		t.Error("a name over UDP is not looked up with the resolver of NetDialer")
	}
}

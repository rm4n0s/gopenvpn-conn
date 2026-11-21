// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"context"
	"net"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rm4n0s/errors"

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
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagDialFailed || !errors.Is(err, syscall.ECONNREFUSED) {
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

// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package vpnnet

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
)

// serverIPv6 is the network of the tunnel that the real server gets besides the IPv4
// one, and its own address in it.
const serverIPv6 = "fd00:8::1"

// realNet starts a real server with an IPv4 and an IPv6 tunnel, dials it and makes a
// Net over the Conn. The test process is in the namespace of the server, so it can
// listen on the server's tunnel addresses with the ordinary net package.
func realNet(t *testing.T, proto string) (*Net, *openvpn.Conn, *servertest.Server) {
	t.Helper()
	srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: []string{"--server-ipv6", "fd00:8::/64"}})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	conn, err := openvpn.Dial(ctx, proto, srv.Addr(), &openvpn.Config{
		TLS: openvpn.NewTLSConfig(openvpn.TLSOptions{
			RootCAs: srv.PKI.CAPool, Certificates: []tls.Certificate{srv.PKI.ClientCert}, RemoteCertTLSServer: true,
		}),
	})
	if err != nil {
		t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
	}
	n, err := New(conn, &Options{CloseConn: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := n.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if got := len(conn.ConnectionState().Addrs); got != 2 {
		t.Fatalf("the tunnel has %d addresses, want an IPv4 and an IPv6 one: %v", got, conn.ConnectionState().Addrs)
	}
	return n, conn, srv
}

// tunnelAddr is the address of the client of the family, from what the server pushed.
func tunnelAddr(t *testing.T, conn *openvpn.Conn, v6 bool) netip.Addr {
	t.Helper()
	for _, p := range conn.ConnectionState().Addrs {
		if p.Addr().Is6() == v6 {
			return p.Addr()
		}
	}
	t.Fatalf("no address of the family (IPv6: %v) in %v", v6, conn.ConnectionState().Addrs)
	return netip.Addr{}
}

// listenOnTunnel listens on the server's own tunnel address with the net package. The
// address of an IPv6 interface may not be usable for a moment (duplicate address
// detection), so a failure is tried again for a few seconds.
func listenOnTunnel(t *testing.T, network, address string) net.Listener {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		l, err := net.Listen(network, address)
		if err == nil {
			t.Cleanup(func() { closeIgnoringClosed(t, l) })
			return l
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("listen on %s: %v", address, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func listenPacketOnTunnel(t *testing.T, network, address string) net.PacketConn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		pc, err := net.ListenPacket(network, address)
		if err == nil {
			t.Cleanup(func() { closeIgnoringClosed(t, pc) })
			return pc
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("listen on %s: %v", address, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func closeIgnoringClosed(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("Close: %v", err)
	}
}

// TestRealServerTCP: through the tunnel to a TCP echo server on the server's tunnel
// address, over IPv4 and IPv6, with 1 MiB each way; the tunnel itself over UDP and
// over TCP.
func TestRealServerTCP(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			n, _, srv := realNet(t, proto)
			for _, row := range []struct{ name, network, host string }{
				{"IPv4", "tcp4", srv.TunnelIP().String()},
				{"IPv6", "tcp6", serverIPv6},
			} {
				l := listenOnTunnel(t, row.network, net.JoinHostPort(row.host, "0"))
				echoServer(t, l)
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				c, err := n.DialContext(ctx, row.network, l.Addr().String())
				cancel()
				if err != nil {
					t.Fatalf("%s: DialContext: %v\nserver log:\n%s", row.name, err, srv.Log())
				}
				roundTrip(t, c, payload(1<<20))
				closeOrFail(t, c)
			}
		})
	}
}

// TestRealServerUDP: UDP datagrams to an echo socket of the server, over IPv4 and IPv6.
func TestRealServerUDP(t *testing.T) {
	n, _, srv := realNet(t, "udp")
	for _, row := range []struct{ name, network, host string }{
		{"IPv4", "udp4", srv.TunnelIP().String()},
		{"IPv6", "udp6", serverIPv6},
	} {
		pc := listenPacketOnTunnel(t, row.network, net.JoinHostPort(row.host, "0"))
		go func() {
			buf := make([]byte, 2048)
			for {
				size, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				if _, err := pc.WriteTo(buf[:size], from); err != nil {
					return
				}
			}
		}()
		c, err := n.DialContext(t.Context(), row.network, pc.LocalAddr().String())
		if err != nil {
			t.Fatalf("%s: DialContext: %v", row.name, err)
		}
		if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		for i, size := range []int{1, 100, 1200} {
			msg := payload(size)
			if _, err := c.Write(msg); err != nil {
				t.Fatalf("%s: Write %d: %v", row.name, i, err)
			}
			buf := make([]byte, 2048)
			got, err := c.Read(buf)
			if err != nil || !bytes.Equal(buf[:got], msg) {
				t.Fatalf("%s: datagram %d: read %d bytes, %v", row.name, i, got, err)
			}
		}
		closeOrFail(t, c)
	}
}

// TestRealServerListeners: a listener made with Net.Listen is reached from the net
// package, which dials the client's tunnel address; the same for ListenPacket.
func TestRealServerListeners(t *testing.T) {
	n, conn, _ := realNet(t, "udp")
	for _, v6 := range []bool{false, true} {
		addr := tunnelAddr(t, conn, v6)
		network := map[bool]string{false: "tcp4", true: "tcp6"}[v6]
		l, err := n.Listen(network, netip.AddrPortFrom(addr, 0).String())
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		echoServer(t, l)
		// IPv6 on the server's side needs the address of the tunnel to be usable.
		c := dialWithRetry(t, network, l.Addr().String())
		roundTrip(t, c, payload(1<<20))
		closeOrFail(t, c)
		closeOrFail(t, l)

		pcNetwork := map[bool]string{false: "udp4", true: "udp6"}[v6]
		pc, err := n.ListenPacket(pcNetwork, netip.AddrPortFrom(addr, 0).String())
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		go func() {
			buf := make([]byte, 2048)
			for {
				size, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				if _, err := pc.WriteTo(buf[:size], from); err != nil {
					return
				}
			}
		}()
		uc, err := net.Dial(pcNetwork, pc.LocalAddr().String())
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		if err := uc.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		msg := payload(800)
		if _, err := uc.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		got, err := uc.Read(buf)
		if err != nil || !bytes.Equal(buf[:got], msg) {
			t.Fatalf("datagram: read %d bytes, %v", got, err)
		}
		closeOrFail(t, uc)
		closeOrFail(t, pc)
	}
}

// dialWithRetry dials with the net package; the first connection to an IPv6 address
// of a tunnel can fail until the address has been tested for duplicates.
func dialWithRetry(t *testing.T, network, address string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout(network, address, 3*time.Second)
		if err == nil {
			return c
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("dial %s: %v", address, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestRealServerTunnelEnds: when the Conn is closed, a Read that waits on a connection
// of the Net returns an error, and no goroutine of the Net is left.
func TestRealServerTunnelEnds(t *testing.T) {
	n, conn, srv := realNet(t, "udp")
	l := listenOnTunnel(t, "tcp4", net.JoinHostPort(srv.TunnelIP().String(), "0"))
	echoServer(t, l)
	c, err := n.DialContext(t.Context(), "tcp4", l.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	roundTrip(t, c, []byte("hello"))
	readErr := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 10)); readErr <- err }()
	if err := conn.Close(); err != nil {
		t.Fatalf("Close of the Conn: %v", err)
	}
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("Read returned with no error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the Read did not return after the Conn was closed")
	}
	if err := n.Close(); err != nil {
		t.Errorf("Close of the Net: %v", err)
	}
	if got := netGoroutines(); len(got) != 0 {
		t.Errorf("%d goroutines of the Net after Close", len(got))
	}
}

// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package vpnnet

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"syscall"
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
func realNet(t testing.TB, proto string, extra ...string) (*Net, *openvpn.Conn, *servertest.Server) {
	t.Helper()
	return realNetWith(t, proto, &Options{CloseConn: true}, extra...)
}

// realNetWith is realNet with the options of the Net.
func realNetWith(t testing.TB, proto string, opts *Options, extra ...string) (*Net, *openvpn.Conn, *servertest.Server) {
	t.Helper()
	srv := servertest.Start(t, servertest.Options{Proto: proto, Extra: append([]string{"--server-ipv6", "fd00:8::/64"}, extra...)})
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
	n, err := New(conn, opts)
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
func tunnelAddr(t testing.TB, conn *openvpn.Conn, v6 bool) netip.Addr {
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
func listenOnTunnel(t testing.TB, network, address string) net.Listener {
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

func listenPacketOnTunnel(t testing.TB, network, address string) net.PacketConn {
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

func closeIgnoringClosed(t testing.TB, c io.Closer) {
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

// TestRealServerHTTPByName: the server pushes a DNS server (a small one that this test
// runs on 10.8.0.1:53 with the net package) and the page is served on 10.8.0.1:80;
// an http.Client whose transport dials through the Net gets it by name, so the query
// and the connection both go through the tunnel.
func TestRealServerHTTPByName(t *testing.T) {
	n, _, srv := realNet(t, "udp", "--push", "dhcp-option DNS 10.8.0.1")
	dns := listenPacketOnTunnel(t, "udp4", net.JoinHostPort(srv.TunnelIP().String(), "53"))
	serveDNS(dns, zone{"web.vpn.test": {srv.TunnelIP()}})
	if servers := n.state.DNSServers; len(servers) != 1 || servers[0] != srv.TunnelIP() {
		t.Fatalf("the pushed DNS servers are %v", servers)
	}

	body := payload(2 << 20)
	web := listenOnTunnel(t, "tcp4", net.JoinHostPort(srv.TunnelIP().String(), "80"))
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Host", r.Host)
		if _, err := w.Write(body); err != nil {
			t.Logf("write of the page: %v", err)
		}
	})}
	go func() {
		if err := server.Serve(web); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	})

	client := &http.Client{Transport: &http.Transport{DialContext: n.DialContext}}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://web.vpn.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Get: %v\nserver log:\n%s", err, srv.Log())
	}
	got, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Host") != "web.vpn.test" || !bytes.Equal(got, body) {
		t.Errorf("status %d, host %q, %d bytes (want %d)", resp.StatusCode, resp.Header.Get("X-Host"), len(got), len(body))
	}
	// The same name through the Resolver on its own.
	addrs, err := n.Resolver().LookupHost(ctx, "web.vpn.test")
	if err != nil || len(addrs) != 1 || addrs[0] != srv.TunnelIP().String() {
		t.Errorf("LookupHost = %v, %v", addrs, err)
	}
}

// TestRealServerOwnDNS: the server pushes a DNS server where nothing answers, and
// Options.DNSServers names another one (a small one that this test runs on
// 10.8.0.1:5353). The lookups and the dials by name use the one of the options, through
// the tunnel, and read nothing of the host: "localhost", which /etc/hosts has, is asked
// of the DNS server, which does not know it.
func TestRealServerOwnDNS(t *testing.T) {
	own := netip.AddrPortFrom(netip.MustParseAddr("10.8.0.1"), 5353)
	n, _, srv := realNetWith(t, "udp", &Options{CloseConn: true, DNSServers: []netip.AddrPort{own}},
		"--push", "dhcp-option DNS 10.8.0.9")
	if own.Addr() != srv.TunnelIP() {
		t.Fatalf("the server's tunnel address is %v, the test expects %v", srv.TunnelIP(), own.Addr())
	}
	dns := listenPacketOnTunnel(t, "udp4", own.String())
	serveDNS(dns, zone{"web.vpn.test": {srv.TunnelIP()}})
	if servers := n.state.DNSServers; len(servers) != 1 || servers[0] != netip.MustParseAddr("10.8.0.9") {
		t.Fatalf("the pushed DNS servers are %v", servers)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	addrs, err := n.LookupNetIP(ctx, "ip", "web.vpn.test")
	if err != nil || len(addrs) != 1 || addrs[0] != srv.TunnelIP() {
		t.Fatalf("LookupNetIP = %v, %v\nserver log:\n%s", addrs, err, srv.Log())
	}
	hosts, err := n.LookupHost(ctx, "web.vpn.test")
	if err != nil || len(hosts) != 1 || hosts[0] != srv.TunnelIP().String() {
		t.Errorf("LookupHost = %v, %v", hosts, err)
	}
	_, err = n.LookupNetIP(ctx, "ip", "localhost")
	wantRoute(t, err, "parseResponse."+TagNoSuchHost)

	l := listenOnTunnel(t, "tcp4", net.JoinHostPort(srv.TunnelIP().String(), "7000"))
	echoServer(t, l)
	c, err := n.DialContext(ctx, "tcp", "web.vpn.test:7000")
	if err != nil {
		t.Fatalf("DialContext by name: %v", err)
	}
	roundTrip(t, c, []byte("own dns"))
	closeOrFail(t, c)
}

// BenchmarkThroughput sends 100 MiB through the Net and the real server, up (client to
// server) and down, over a tunnel on UDP and on TCP, and reports MB/s:
//
//	scripts/vpn-ns.sh -- go test -tags gopenvpn_server -run '^$' -bench Throughput -benchtime 1x ./vpnnet
func BenchmarkThroughput(b *testing.B) {
	const size = 100 << 20
	for _, proto := range []string{"udp", "tcp"} {
		for _, direction := range []string{"up", "down"} {
			b.Run(proto+"/"+direction, func(b *testing.B) {
				n, _, srv := realNet(b, proto)
				l := listenOnTunnel(b, "tcp4", net.JoinHostPort(srv.TunnelIP().String(), "0"))
				chunk := payload(64 << 10)
				go func() {
					for {
						c, err := l.Accept()
						if err != nil {
							return
						}
						go func() {
							defer closeIgnoringClosed(b, c)
							if direction == "up" {
								if _, err := io.Copy(io.Discard, c); err != nil {
									b.Logf("discard: %v", err)
									return
								}
								// Everything has arrived: tell the client, so that it stops the clock then.
								if _, err := c.Write([]byte{1}); err != nil {
									b.Logf("done byte: %v", err)
								}
								return
							}
							for sent := 0; sent < size; sent += len(chunk) {
								if _, err := c.Write(chunk); err != nil {
									return
								}
							}
						}()
					}
				}()
				b.SetBytes(size)
				b.ResetTimer()
				for range b.N {
					c, err := n.DialContext(b.Context(), "tcp4", l.Addr().String())
					if err != nil {
						b.Fatalf("DialContext: %v", err)
					}
					if direction == "up" {
						for sent := 0; sent < size; sent += len(chunk) {
							if _, err := c.Write(chunk); err != nil {
								b.Fatalf("Write: %v", err)
							}
						}
						cw, ok := c.(interface{ CloseWrite() error })
						if !ok {
							b.Fatal("the connection has no CloseWrite")
						}
						if err := cw.CloseWrite(); err != nil {
							b.Fatalf("CloseWrite: %v", err)
						}
						if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
							b.Fatalf("waiting for the end of the transfer: %v", err)
						}
					} else if got, err := io.CopyN(io.Discard, c, size); err != nil {
						b.Fatalf("read %d of %d bytes: %v", got, size, err)
					}
					if err := c.Close(); err != nil {
						b.Fatalf("Close: %v", err)
					}
				}
			})
		}
	}
}

// TestRealServerMSS: with a server that does not lower the MSS itself (mssfix 0, as
// a server with the kernel data channel does not: SPEC §21 O32), the SYN of a TCP
// connection of vpnnet arrives with the MSS of ConnectionState (20 less over IPv6),
// so the server's socket sends segments no larger than that, and its packets fit in
// one packet of the link. The MSS that the server's kernel uses is its TCP_MAXSEG,
// which leaves out the room of TCP options such as timestamps.
func TestRealServerMSS(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			n, conn, srv := realNet(t, proto, "--mssfix", "0")
			// 1492 less the link's headers (UDP 28, TCP 40), the data packet's
			// overhead (DATA_V2 4, packet id 4 or 8 in the epoch format, tag
			// 16, and 2 for the length on TCP) and 40: 1400 or 1396 on UDP,
			// 1386 or 1382 on TCP.
			st := conn.ConnectionState()
			want := 1492 - 28 - 24 - 40
			if proto == "tcp" {
				want = 1492 - 40 - 26 - 40
			}
			if slices.ContainsFunc(st.PushedOptions, func(o string) bool {
				return strings.HasPrefix(o, "protocol-flags ") && slices.Contains(strings.Fields(o), "aead-epoch")
			}) {
				want -= 4
			}
			if st.MSS != want {
				t.Fatalf("ConnectionState().MSS = %d, want %d (pushed %q)", st.MSS, want, st.PushedOptions)
			}
			for _, row := range []struct {
				name, network, host string
				limit               int
			}{
				{"IPv4", "tcp4", srv.TunnelIP().String(), want},
				{"IPv6", "tcp6", serverIPv6, want - 20},
			} {
				l := listenOnTunnel(t, row.network, net.JoinHostPort(row.host, "0"))
				accepted := make(chan net.Conn, 1)
				go func() {
					c, err := l.Accept()
					if err != nil {
						t.Errorf("%s: Accept: %v", row.name, err)
						close(accepted)
						return
					}
					accepted <- c
				}()
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				c, err := n.DialContext(ctx, row.network, l.Addr().String())
				cancel()
				if err != nil {
					t.Fatalf("%s: DialContext: %v\nserver log:\n%s", row.name, err, srv.Log())
				}
				sc, ok := <-accepted
				if !ok {
					t.FailNow()
				}
				raw, err := sc.(*net.TCPConn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var maxSeg int
				var serr error
				if err := raw.Control(func(fd uintptr) {
					maxSeg, serr = syscall.GetsockoptInt(int(min(fd, math.MaxInt)), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
				}); err != nil || serr != nil {
					t.Fatalf("%s: TCP_MAXSEG: %v %v", row.name, err, serr)
				}
				if maxSeg > row.limit {
					t.Errorf("%s: the server's socket sends segments of %d bytes, above the MSS of %d", row.name, maxSeg, row.limit)
				}
				t.Logf("%s: the server sends segments of up to %d bytes (MSS %d)", row.name, maxSeg, row.limit)
				closeOrFail(t, sc)
				closeOrFail(t, c)
			}
		})
	}
}

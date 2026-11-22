// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// newNets makes two Nets on two clients of one hub, and closes them when the test
// ends.
func newNets(t *testing.T, ip6 bool) (na, nb *Net, a, b *peer) {
	t.Helper()
	a, b = hub(t, ip6, "1500")
	var err error
	if na, err = New(a.conn, nil); err != nil {
		t.Fatalf("New: %v", err)
	}
	if nb, err = New(b.conn, nil); err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		for _, n := range []*Net{na, nb} {
			if err := n.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}
	})
	return na, nb, a, b
}

// payload is n bytes that are not all alike.
func payload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*7 + i>>8)
	}
	return p
}

// echoServer accepts connections on l and sends back what it reads, until l is closed.
func echoServer(t *testing.T, l net.Listener) {
	t.Helper()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() {
					if err := c.Close(); err != nil {
						t.Logf("echo close: %v", err)
					}
				}()
				if _, err := io.Copy(c, c); err != nil {
					t.Logf("echo: %v", err)
				}
			}()
		}
	}()
}

// roundTrip sends data through c and reads it back, in the way of a person who
// writes and reads at the same time.
func roundTrip(t *testing.T, c net.Conn, data []byte) {
	t.Helper()
	werr := make(chan error, 1)
	go func() {
		_, err := c.Write(data)
		werr <- err
	}()
	got := make([]byte, len(data))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if err := <-werr; err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("the data that came back is not the data that went")
	}
}

func TestTCPEcho(t *testing.T) {
	rows := []struct {
		name, network, listen, dial string
		ip6                         bool
	}{
		{"IPv4", "tcp", "10.8.0.3:7000", "10.8.0.3:7000", false},
		{"IPv4 with tcp4", "tcp4", "10.8.0.3:7000", "10.8.0.3:7000", false},
		{"IPv4 on every address", "tcp", ":7000", "10.8.0.3:7000", false},
		{"IPv6", "tcp", "[fd00:8::3]:7000", "[fd00:8::3]:7000", true},
		{"IPv6 with tcp6", "tcp6", "[fd00:8::3]:7000", "[fd00:8::3]:7000", true},
		{"IPv6 on every address", "tcp6", ":7000", "[fd00:8::3]:7000", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			na, nb, _, _ := newNets(t, row.ip6)
			l, err := nb.Listen(row.network, row.listen)
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer closeOrFail(t, l)
			echoServer(t, l)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			c, err := na.DialContext(ctx, row.network, row.dial)
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer closeOrFail(t, c)
			roundTrip(t, c, payload(1<<20))
			if got, want := c.RemoteAddr().String(), row.dial; got != want {
				t.Errorf("RemoteAddr = %s, want %s", got, want)
			}
		})
	}
}

func closeOrFail(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestUDPExchange(t *testing.T) {
	rows := []struct {
		name, network, listen, dial string
		ip6                         bool
	}{
		{"IPv4", "udp", "10.8.0.3:7001", "10.8.0.3:7001", false},
		{"IPv4 on every address", "udp4", ":7001", "10.8.0.3:7001", false},
		{"IPv6", "udp", "[fd00:8::3]:7001", "[fd00:8::3]:7001", true},
		{"IPv6 on every address", "udp6", ":7001", "[fd00:8::3]:7001", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			na, nb, _, _ := newNets(t, row.ip6)
			pc, err := nb.ListenPacket(row.network, row.listen)
			if err != nil {
				t.Fatalf("ListenPacket: %v", err)
			}
			defer closeOrFail(t, pc)
			c, err := na.DialContext(t.Context(), row.network, row.dial)
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer closeOrFail(t, c)
			for i, msg := range [][]byte{[]byte("hello"), payload(1200), {}} {
				if _, err := c.Write(msg); err != nil {
					t.Fatalf("Write %d: %v", i, err)
				}
				buf := make([]byte, 2000)
				n, from, err := pc.ReadFrom(buf)
				if err != nil || !bytes.Equal(buf[:n], msg) {
					t.Fatalf("ReadFrom %d = %d bytes, %v", i, n, err)
				}
				if _, err := pc.WriteTo(append([]byte("re:"), msg...), from); err != nil {
					t.Fatalf("WriteTo %d: %v", i, err)
				}
				n, err = c.Read(buf)
				if err != nil || !bytes.Equal(buf[:n], append([]byte("re:"), msg...)) {
					t.Fatalf("Read %d = %d bytes, %v", i, n, err)
				}
			}
		})
	}
}

func TestListenerWithPortZero(t *testing.T) {
	na, nb, _, _ := newNets(t, false)
	l, err := nb.Listen("tcp", "10.8.0.3:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closeOrFail(t, l)
	echoServer(t, l)
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok || addr.Port == 0 || addr.IP.String() != "10.8.0.3" {
		t.Fatalf("Addr = %v", l.Addr())
	}
	c, err := na.DialContext(t.Context(), "tcp", addr.String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer closeOrFail(t, c)
	roundTrip(t, c, []byte("through a port that the stack chose"))
}

// TestTunnelEnds: when the Conn ends, the connections of the Net fail, and a Read that
// was blocked comes back.
func TestTunnelEnds(t *testing.T) {
	na, nb, a, _ := newNets(t, false)
	l, err := nb.Listen("tcp", "10.8.0.3:7000")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closeOrFail(t, l)
	echoServer(t, l)
	c, err := na.DialContext(t.Context(), "tcp", "10.8.0.3:7000")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	roundTrip(t, c, []byte("up"))
	pc, err := na.ListenPacket("udp", "10.8.0.2:9")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	readErr := make(chan error, 2)
	go func() { _, err := c.Read(make([]byte, 10)); readErr <- err }()
	go func() { _, _, err := pc.ReadFrom(make([]byte, 10)); readErr <- err }()
	if err := a.conn.Close(); err != nil {
		t.Fatalf("Close of the Conn: %v", err)
	}
	for range 2 {
		if err := <-readErr; err == nil {
			t.Error("a blocked Read of the Net returned with no error")
		}
	}
	if _, err := na.DialContext(t.Context(), "tcp", "10.8.0.3:7000"); !errors.Is(err, net.ErrClosed) {
		t.Errorf("DialContext after the tunnel ended = %v, want net.ErrClosed (what ended the Conn)", err)
	}
	if _, err := na.Listen("tcp", ":1"); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Listen after the tunnel ended = %v", err)
	}
	if _, err := na.ListenPacket("udp", ":1"); !errors.Is(err, net.ErrClosed) {
		t.Errorf("ListenPacket after the tunnel ended = %v", err)
	}
	// Close still works, and the Conn was not the Net's to close.
	if err := na.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
}

func TestClose(t *testing.T) {
	rows := []struct {
		name      string
		closeConn bool
	}{{"the Conn stays open", false}, {"CloseConn", true}}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			a, b := hub(t, false, "1500")
			n, err := New(a.conn, &Options{CloseConn: row.closeConn})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := netGoroutines(); len(got) == 0 {
				t.Error("a Net with no goroutine: the leak check below would show nothing")
			}
			pc, err := n.ListenPacket("udp", ":5")
			if err != nil {
				t.Fatalf("ListenPacket: %v", err)
			}
			l, err := n.Listen("tcp", ":5")
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			readErr := make(chan error, 2)
			go func() { _, _, err := pc.ReadFrom(make([]byte, 10)); readErr <- err }()
			go func() { _, err := l.Accept(); readErr <- err }()
			if err := n.Close(); err != nil {
				t.Fatalf("Close = %v", err)
			}
			if err := n.Close(); err != nil {
				t.Errorf("a second Close = %v", err)
			}
			for range 2 {
				if err := <-readErr; err == nil {
					t.Error("a blocked call of the Net returned with no error")
				}
			}
			// The value of the standard library comes back as it is (SPEC §5.3).
			if _, err := n.DialContext(t.Context(), "tcp", "10.8.0.3:1"); err != net.ErrClosed {
				t.Errorf("DialContext after Close = %v, want net.ErrClosed", err)
			}
			if _, err := n.Listen("tcp", ":1"); err != net.ErrClosed {
				t.Errorf("Listen after Close = %v, want net.ErrClosed", err)
			}
			if _, err := n.ListenPacket("udp", ":1"); err != net.ErrClosed {
				t.Errorf("ListenPacket after Close = %v, want net.ErrClosed", err)
			}
			if got := netGoroutines(); len(got) != 0 {
				t.Errorf("%d goroutines of the Net after Close:\n%s", len(got), strings.Join(got, "\n\n"))
			}
			// The Conn: closed with CloseConn; otherwise open, and its read deadline, which
			// Close used to wake the Net's reader, is gone: a ping to the other client
			// is answered by its stack, and the answer is read.
			request := vpntest.EchoRequest(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.3"), 1, 1, []byte("ping"))
			_, werr := a.conn.Write(request)
			if row.closeConn {
				if !errors.Is(werr, net.ErrClosed) {
					t.Errorf("Write on the Conn after Close of the Net = %v, want net.ErrClosed", werr)
				}
				return
			}
			if werr != nil {
				t.Fatalf("Write on the Conn: %v", werr)
			}
			nb, err := New(b.conn, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer closeOrFail(t, nb)
			buf := make([]byte, 1500)
			size, err := a.conn.Read(buf)
			if err != nil {
				t.Fatalf("Read on the Conn after Close of the Net: %v", err)
			}
			if reply, ok := vpntest.ParseEchoReply(buf[:size]); !ok || reply.Src != netip.MustParseAddr("10.8.0.3") {
				t.Errorf("the packet read is %x", buf[:size])
			}
		})
	}
}

// netGoroutines are the stacks of the goroutines that belong to a Net or to gVisor's
// stack.
func netGoroutines() []string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var out []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "gvisor.dev/gvisor") || strings.Contains(g, "vpnnet.(*Net)") {
			out = append(out, g)
		}
	}
	return out
}

func TestNewErrors(t *testing.T) {
	_, err := New(nil, nil)
	wantRoute(t, err, "New."+TagNilConn)
	// A Conn that has not done its handshake has no address.
	a, _ := hub(t, false, "1500")
	fresh := openvpn.PacketClient(mustLink(), &openvpn.Config{})
	_, err = New(fresh, nil)
	wantRoute(t, err, "New."+TagNotConnected)
	if err := fresh.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Logf("Close: %v", err)
	}
	_ = a
	// The stack refuses the same address twice.
	prefix := netip.MustParsePrefix("10.8.0.2/24")
	_, _, err = newStack(openvpn.ConnectionState{MTU: 1500, Addrs: []netip.Prefix{prefix, prefix}})
	wantRoute(t, err, "newStack."+TagStackSetupFailed)
}

func mustLink() net.Conn {
	c, _ := vpntest.NewDatagramPair(vpntest.LinkOptions{})
	return c
}

func wantRoute(t *testing.T, err error, route string) {
	t.Helper()
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not an *errors.Error", err, err)
	}
	if !appErr.HasRoute(route) {
		t.Errorf("route = %s, want %s", appErr.Route(), route)
	}
}

func TestAddressErrors(t *testing.T) {
	na, _, _, _ := newNets(t, false)
	rows := []struct {
		name, network, address, route string
		call                          string
	}{
		{"dial: unsupported network", "unix", "10.8.0.3:1", "Net.DialContext->parse." + TagUnsupportedNetwork, "dial"},
		{"dial: no port", "tcp", "10.8.0.3", "Net.DialContext->parse." + TagBadAddress, "dial"},
		{"dial: bad port", "tcp", "10.8.0.3:http", "Net.DialContext->parse." + TagBadAddress, "dial"},
		{"dial: port too large", "tcp", "10.8.0.3:65536", "Net.DialContext->parse." + TagBadAddress, "dial"},
		{"dial: a host name", "tcp", "example.com:80", "Net.DialContext->parse." + TagBadAddress, "dial"},
		{"dial: a zone", "tcp", "[fe80::1%eth0]:80", "Net.DialContext->parse." + TagBadAddress, "dial"},
		{"dial: no host", "tcp", ":80", "Net.DialContext->parse." + TagBadAddress, "dial"},
		{"dial: tcp4 with IPv6", "tcp4", "[fd00::1]:80", "Net.DialContext->parse." + TagBadAddress, "dial"},
		{"dial: tcp6 with IPv4", "tcp6", "10.8.0.3:80", "Net.DialContext->parse." + TagBadAddress, "dial"},
		{"listen: a UDP network", "udp", ":80", "Net.Listen." + TagUnsupportedNetwork, "listen"},
		{"listen: a host name", "tcp", "localhost:80", "Net.Listen->parse." + TagBadAddress, "listen"},
		{"listen: not an address of the tunnel", "tcp", "10.9.9.9:80", "Net.Listen." + TagListenFailed, "listen"},
		{"listen packet: a TCP network", "tcp", ":80", "Net.ListenPacket." + TagUnsupportedNetwork, "packet"},
		{"listen packet: a host name", "udp", "localhost:80", "Net.ListenPacket->parse." + TagBadAddress, "packet"},
		{"listen packet: not an address of the tunnel", "udp", "10.9.9.9:80", "Net.ListenPacket." + TagListenFailed, "packet"},
	}
	for _, row := range rows {
		var err error
		switch row.call {
		case "dial":
			_, err = na.DialContext(t.Context(), row.network, row.address)
		case "listen":
			_, err = na.Listen(row.network, row.address)
		default:
			_, err = na.ListenPacket(row.network, row.address)
		}
		if err == nil {
			t.Errorf("%s: no error", row.name)
			continue
		}
		appErr, ok := errors.FromError(err)
		if !ok || !appErr.HasRoute(row.route) {
			t.Errorf("%s: %v; route %v, want %s", row.name, err, routeOf(err), row.route)
		}
	}
	// A port that is taken.
	l, err := na.Listen("tcp", "10.8.0.2:80")
	if err != nil {
		t.Fatal(err)
	}
	defer closeOrFail(t, l)
	_, err = na.Listen("tcp", "10.8.0.2:80")
	wantRoute(t, err, "Net.Listen."+TagListenFailed)
	pc, err := na.ListenPacket("udp", "10.8.0.2:80")
	if err != nil {
		t.Fatal(err)
	}
	defer closeOrFail(t, pc)
	_, err = na.ListenPacket("udp", "10.8.0.2:80")
	wantRoute(t, err, "Net.ListenPacket."+TagListenFailed)
}

func routeOf(err error) string {
	if appErr, ok := errors.FromError(err); ok {
		return appErr.Route()
	}
	return "(not tagged)"
}

func TestDialErrors(t *testing.T) {
	na, _, _, _ := newNets(t, false)
	// Nothing listens: the other side answers with a reset.
	_, err := na.DialContext(t.Context(), "tcp", "10.8.0.3:9")
	wantRoute(t, err, "Net.DialContext."+TagDialFailed)
	// A context that is done.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = na.DialContext(ctx, "tcp", "10.8.0.3:9")
	wantRoute(t, err, "Net.DialContext."+TagDialFailed)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled behind it", err)
	}
	// A deadline that passes before anyone answers: an address that no peer owns.
	ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = na.DialContext(ctx, "tcp", "10.8.0.77:9")
	wantRoute(t, err, "Net.DialContext."+TagDialFailed)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded behind it", err)
	}
	// A UDP conn to a port with no listener still opens: UDP has no connection.
	c, err := na.DialContext(t.Context(), "udp", "10.8.0.3:9")
	if err != nil {
		t.Fatalf("DialContext udp: %v", err)
	}
	closeOrFail(t, c)
}

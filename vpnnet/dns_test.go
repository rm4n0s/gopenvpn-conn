// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rm4n0s/errors"
)

// zone is what a test DNS server knows: the addresses of each name.
type zone map[string][]netip.Addr

// dnsQuestion reads the first question of a query: its name (lower case, no final
// dot), its type, and the end of the question section.
func dnsQuestion(msg []byte) (name string, qtype uint16, end int, ok bool) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:]) != 1 {
		return "", 0, 0, false
	}
	var labels []string
	i := 12
	for {
		if i >= len(msg) {
			return "", 0, 0, false
		}
		size := int(msg[i])
		i++
		if size == 0 {
			break
		}
		if size&0xc0 != 0 || i+size > len(msg) {
			return "", 0, 0, false
		}
		labels = append(labels, strings.ToLower(string(msg[i:i+size])))
		i += size
	}
	if i+4 > len(msg) {
		return "", 0, 0, false
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(msg[i:]), i + 4, true
}

// dnsAnswer is the answer to a query: the A or AAAA records of the name, none for
// another type, and NXDOMAIN for a name that the zone does not have.
func dnsAnswer(z zone, query []byte) []byte {
	name, qtype, end, ok := dnsQuestion(query)
	if !ok {
		return nil
	}
	addrs, known := z[name]
	var records [][]byte
	for _, a := range addrs {
		switch {
		case a.Is4() && qtype == 1:
			b := a.As4()
			records = append(records, b[:])
		case a.Is6() && qtype == 28:
			b := a.As16()
			records = append(records, b[:])
		}
	}
	flags := uint16(0x8180) // a response, recursion desired and available
	if !known {
		flags |= 3 // NXDOMAIN
	}
	out := make([]byte, 12, 512)
	copy(out, query[:2]) // the id
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], 1)
	binary.BigEndian.PutUint16(out[6:], uint16(len(records)&0xffff))
	out = append(out, query[12:end]...)
	for _, r := range records {
		out = append(out, 0xc0, 0x0c) // the name of the question
		out = binary.BigEndian.AppendUint16(out, qtype)
		out = binary.BigEndian.AppendUint16(out, 1) // IN
		out = binary.BigEndian.AppendUint32(out, 60)
		out = binary.BigEndian.AppendUint16(out, uint16(len(r)&0xffff))
		out = append(out, r...)
	}
	return out
}

// serveDNS answers the queries that arrive on pc until it is closed.
func serveDNS(pc net.PacketConn, z zone) {
	go func() {
		buf := make([]byte, 1500)
		for {
			size, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if answer := dnsAnswer(z, buf[:size]); answer != nil {
				if _, err := pc.WriteTo(answer, from); err != nil {
					return
				}
			}
		}
	}()
}

func TestResolver(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, true, []string{"DNS 10.8.0.3"})
	pc, err := nb.ListenPacket("udp", "10.8.0.3:53")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer closeOrFail(t, pc)
	serveDNS(pc, zone{
		"web.vpn.test":  {netip.MustParseAddr("10.8.0.3")},
		"both.vpn.test": {netip.MustParseAddr("10.8.0.3"), netip.MustParseAddr("fd00:8::3")},
		"v6.vpn.test":   {netip.MustParseAddr("fd00:8::3")},
	})
	r := na.Resolver()
	if r != na.Resolver() {
		t.Error("Resolver returns another value each time")
	}
	ctx := t.Context()
	rows := []struct {
		name, network, host string
		want                []string
	}{
		{"an IPv4 name", "ip", "web.vpn.test", []string{"10.8.0.3"}},
		{"both families", "ip", "both.vpn.test", []string{"10.8.0.3", "fd00:8::3"}},
		{"ip4 only", "ip4", "both.vpn.test", []string{"10.8.0.3"}},
		{"ip6 only", "ip6", "both.vpn.test", []string{"fd00:8::3"}},
		{"capital letters", "ip", "WEB.vpn.test", []string{"10.8.0.3"}},
	}
	for _, row := range rows {
		got, err := r.LookupNetIP(ctx, row.network, row.host)
		if err != nil {
			t.Errorf("%s: LookupNetIP(%q, %q): %v", row.name, row.network, row.host, err)
			continue
		}
		var text []string
		for _, a := range got {
			text = append(text, a.String())
		}
		slices.Sort(text)
		slices.Sort(row.want)
		if !slices.Equal(text, row.want) {
			t.Errorf("%s: got %v, want %v", row.name, text, row.want)
		}
	}
	var dnsErr *net.DNSError
	if _, err := r.LookupHost(ctx, "nothing.vpn.test"); !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Errorf("an unknown name gave %v, want a DNS error with IsNotFound", err)
	}
}

func TestResolverWithoutServers(t *testing.T) {
	na, _, _, _ := newNets(t, false)
	if _, err := na.Resolver().LookupHost(t.Context(), "web.vpn.test"); err == nil || !strings.Contains(err.Error(), "no DNS server") {
		t.Errorf("a lookup with no DNS server gave %v", err)
	}
	_, err := na.dialDNS(t.Context(), "udp", "")
	wantRoute(t, err, "Net.dialDNS."+TagNoDNSServers)
	// A DNS server of a family that the tunnel does not have is no server.
	n6, _, _, _ := newNetsDNS(t, false, []string{"DNS6 fd00:8::1"})
	_, err = n6.dialDNS(t.Context(), "udp", "")
	wantRoute(t, err, "Net.dialDNS."+TagNoDNSServers)
}

// TestDNSServerSelection: the Dial function of the resolver starts with the server that
// worked last, leaves one whose read fails for the next, and goes on to the next server
// when a stream connection is refused. (gVisor sends no ICMP error for a closed UDP
// port, so a dead server shows as a timeout; the test makes a read fail by a deadline
// that has passed.)
func TestDNSServerSelection(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, true, []string{"DNS 10.8.0.3", "DNS6 fd00:8::3"})
	z := zone{"web.vpn.test": {netip.MustParseAddr("10.8.0.3")}}
	for _, addr := range []string{"10.8.0.3:53", "[fd00:8::3]:53"} {
		pc, err := nb.ListenPacket("udp", addr)
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		defer closeOrFail(t, pc)
		serveDNS(pc, z)
	}
	remote := func(c net.Conn) string { return c.RemoteAddr().String() }

	c, err := na.dialDNS(t.Context(), "udp", "ignored:53")
	if err != nil {
		t.Fatalf("dialDNS: %v", err)
	}
	if _, ok := c.(net.PacketConn); !ok {
		t.Fatal("the connection of a UDP query is not a net.PacketConn: the resolver would frame it as a stream")
	}
	if got := remote(c); got != "10.8.0.3:53" {
		t.Errorf("the first server is %s", got)
	}
	// The server does not answer: its place goes to the next one.
	if err := c.SetReadDeadline(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 10)); err == nil {
		t.Fatal("Read with a deadline in the past succeeded")
	}
	closeOrFail(t, c)
	if got := na.dnsStart.Load(); got != 1 {
		t.Errorf("dnsStart = %d after a failed read, want 1", got)
	}
	c, err = na.dialDNS(t.Context(), "udp", "ignored:53")
	if err != nil {
		t.Fatalf("dialDNS: %v", err)
	}
	if got := remote(c); got != "[fd00:8::3]:53" {
		t.Errorf("after a failure the server is %s, want the second", got)
	}
	// It answers: it stays the first.
	query := []byte{0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'e', 'b', 3, 'v', 'p', 'n', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	if _, err := c.Write(query); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reply := make([]byte, 512)
	if size, err := c.Read(reply); err != nil || size < len(query) || reply[0] != 0 || reply[1] != 7 {
		t.Fatalf("Read = %d bytes, %v", size, err)
	}
	if got := na.dnsStart.Load(); got != 1 {
		t.Errorf("dnsStart = %d after an answer, want 1", got)
	}
	// A failure of the second one wraps around to the first; a failure of a server that
	// is not the first of the next lookup changes nothing.
	if err := c.SetReadDeadline(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 10)); err == nil {
		t.Fatal("Read with a deadline in the past succeeded")
	}
	closeOrFail(t, c)
	if got := na.dnsStart.Load(); got != 0 {
		t.Errorf("dnsStart = %d after the second server failed, want 0", got)
	}
	na.dnsStart.Store(1)
	old := &dnsConn{n: na, index: 0, count: 2}
	old.note(os.ErrDeadlineExceeded)
	if got := na.dnsStart.Load(); got != 1 {
		t.Errorf("a failure of a server that is not the current one moved dnsStart to %d", got)
	}

	// A stream: the first server refuses the connection (nothing listens on its TCP port 53),
	// and the Dial function goes on to the second.
	na.dnsStart.Store(0)
	l, err := nb.Listen("tcp6", "[fd00:8::3]:53")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closeOrFail(t, l)
	echoServer(t, l)
	c, err = na.dialDNS(t.Context(), "tcp", "ignored:53")
	if err != nil {
		t.Fatalf("dialDNS tcp: %v", err)
	}
	defer closeOrFail(t, c)
	if _, ok := c.(net.PacketConn); ok {
		t.Error("the connection of a TCP query is a net.PacketConn")
	}
	if got := remote(c); got != "[fd00:8::3]:53" {
		t.Errorf("the server of the stream is %s, want the one that listens", got)
	}
}

func TestDialContextByName(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, true, []string{"DNS 10.8.0.3"})
	pc, err := nb.ListenPacket("udp", "10.8.0.3:53")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer closeOrFail(t, pc)
	serveDNS(pc, zone{
		"web.vpn.test":  {netip.MustParseAddr("10.8.0.3")},
		"v6.vpn.test":   {netip.MustParseAddr("fd00:8::3")},
		"dual.vpn.test": {netip.MustParseAddr("10.8.0.3"), netip.MustParseAddr("fd00:8::3")},
	})
	l, err := nb.Listen("tcp", ":7000")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closeOrFail(t, l)
	echoServer(t, l)
	// The name "dual" has an IPv4 and an IPv6 address; a listener answers on one family
	// only, so one of the two ports is refused at the address that comes first, and the
	// next address is tried (which comes first is for the resolver to say).
	l4, err := nb.Listen("tcp4", ":7004")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closeOrFail(t, l4)
	echoServer(t, l4)
	l6, err := nb.Listen("tcp6", ":7006")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closeOrFail(t, l6)
	echoServer(t, l6)
	rows := []struct {
		name, network, address, remote string
	}{
		{"tcp", "tcp", "web.vpn.test:7000", "10.8.0.3:7000"},
		{"tcp4", "tcp4", "web.vpn.test:7000", "10.8.0.3:7000"},
		{"an IPv6 name", "tcp", "v6.vpn.test:7000", "[fd00:8::3]:7000"},
		{"dual, IPv4 listener", "tcp", "dual.vpn.test:7004", "10.8.0.3:7004"},
		{"dual, IPv6 listener", "tcp", "dual.vpn.test:7006", "[fd00:8::3]:7006"},
	}
	for _, row := range rows {
		c, err := na.DialContext(t.Context(), row.network, row.address)
		if err != nil {
			t.Errorf("%s: DialContext: %v", row.name, err)
			continue
		}
		roundTrip(t, c, []byte("by name"))
		if got := c.RemoteAddr().String(); got != row.remote {
			t.Errorf("%s: connected to %s, want %s", row.name, got, row.remote)
		}
		closeOrFail(t, c)
	}
	// A name that does not exist, and a name that has no address of the family.
	_, err = na.DialContext(t.Context(), "tcp", "nothing.vpn.test:7000")
	wantRoute(t, err, "Net.DialContext."+TagResolveFailed)
	_, err = na.DialContext(t.Context(), "tcp4", "v6.vpn.test:7000")
	wantRoute(t, err, "Net.DialContext."+TagResolveFailed)
}

// TestDialContextByNameWithOnlyIPv4 shows that a tunnel with no IPv6 address does not
// try the IPv6 addresses of a name.
func TestDialContextByNameWithOnlyIPv4(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, false, []string{"DNS 10.8.0.3"})
	pc, err := nb.ListenPacket("udp", "10.8.0.3:53")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer closeOrFail(t, pc)
	serveDNS(pc, zone{"v6.vpn.test": {netip.MustParseAddr("fd00:8::3")}})
	_, err = na.DialContext(t.Context(), "tcp", "v6.vpn.test:7000")
	wantRoute(t, err, "Net.DialContext."+TagResolveFailed)
	if got := na.lookupNetwork("tcp"); got != "ip4" {
		t.Errorf("lookupNetwork = %s, want ip4", got)
	}
}

// TestHTTPByName: an HTTP client whose transport dials through the Net gets a page by
// its name, from a server of the other client.
func TestHTTPByName(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, false, []string{"DNS 10.8.0.3"})
	pc, err := nb.ListenPacket("udp", "10.8.0.3:53")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer closeOrFail(t, pc)
	serveDNS(pc, zone{"web.vpn.test": {netip.MustParseAddr("10.8.0.3")}})
	l, err := nb.Listen("tcp", "10.8.0.3:80")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	body := payload(300_000)
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Host", r.Host)
		if _, err := w.Write(body); err != nil {
			t.Logf("write of the page: %v", err)
		}
	})}
	go func() {
		if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("Serve: %v", err)
		}
	}()
	defer func() {
		if err := server.Close(); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	}()
	client := &http.Client{Transport: &http.Transport{DialContext: na.DialContext}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://web.vpn.test/page", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Host") != "web.vpn.test" || len(got) != len(body) {
		t.Errorf("status %d, host %q, %d bytes", resp.StatusCode, resp.Header.Get("X-Host"), len(got))
	}
}

func TestValidHostName(t *testing.T) {
	for _, row := range []struct {
		name string
		ok   bool
	}{
		{"example.com", true}, {"a", true}, {"web-1.vpn_test.", true}, {"UPPER.case", true}, {"1.2.3", true},
		{"", false}, {"a b", false}, {"a/b", false}, {"é.example", false}, {strings.Repeat("a", 254), false},
	} {
		if got := validHostName(row.name); got != row.ok {
			t.Errorf("validHostName(%q) = %v", row.name, got)
		}
	}
}

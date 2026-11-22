// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rm4n0s/errors"
)

// testServer is the address that the test DNS servers have.
var testServer = netip.MustParseAddrPort("10.8.0.3:53")

// newNetWith makes the two Nets of a hub, the first with opts, and returns them.
func newNetWith(t *testing.T, ip6 bool, pushed []string, opts *Options) (na, nb *Net) {
	t.Helper()
	a, b := hubDNS(t, ip6, "1500", pushed)
	var err error
	if na, err = New(a.conn, opts); err != nil {
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
	return na, nb
}

// listenDNS makes a UDP DNS server at addr on n.
func listenDNS(t *testing.T, n *Net, addr string, answer func(query []byte) []byte) {
	t.Helper()
	pc, err := n.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("ListenPacket %s: %v", addr, err)
	}
	t.Cleanup(func() { closeOrFail(t, pc) })
	serveDNSFunc(pc, answer)
}

func strs(addrs []netip.Addr) []string {
	var out []string
	for _, a := range addrs {
		out = append(out, a.String())
	}
	slices.Sort(out)
	return out
}

func TestLookupNetIP(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, true, []string{"DNS 10.8.0.3"})
	listenDNS(t, nb, testServer.String(), func(q []byte) []byte {
		return dnsAnswer(zone{
			"web.vpn.test":  {netip.MustParseAddr("10.8.0.3")},
			"both.vpn.test": {netip.MustParseAddr("10.8.0.3"), netip.MustParseAddr("fd00:8::3")},
			"v6.vpn.test":   {netip.MustParseAddr("fd00:8::3")},
		}, q)
	})
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
		{"a final dot", "ip", "web.vpn.test.", []string{"10.8.0.3"}},
		{"an IPv4 literal", "ip", "192.0.2.7", []string{"192.0.2.7"}},
		{"an IPv6 literal", "ip6", "fd00::1", []string{"fd00::1"}},
		{"a mapped literal", "ip4", "::ffff:192.0.2.7", []string{"192.0.2.7"}},
	}
	for _, row := range rows {
		got, err := na.LookupNetIP(ctx, row.network, row.host)
		if err != nil {
			t.Errorf("%s: LookupNetIP(%q, %q): %v", row.name, row.network, row.host, err)
			continue
		}
		if text := strs(got); !slices.Equal(text, row.want) {
			t.Errorf("%s: got %v, want %v", row.name, text, row.want)
		}
	}
	hosts, err := na.LookupHost(ctx, "both.vpn.test")
	if err != nil || len(hosts) != 2 {
		t.Errorf("LookupHost = %v, %v", hosts, err)
	}

	errRows := []struct {
		name, network, host, route string
	}{
		{"an unknown name", "ip", "nothing.vpn.test", "Net.exchange->Net.queryServer->parseResponse." + TagNoSuchHost},
		// /etc/hosts has "localhost"; the lookup does not read it.
		{"localhost is not read from the host", "ip", "localhost", "parseResponse." + TagNoSuchHost},
		{"no address of the family", "ip4", "v6.vpn.test", "Net.LookupNetIP." + TagNoSuchHost},
		{"a literal of the other family", "ip6", "192.0.2.7", "Net.LookupNetIP." + TagNoSuchHost},
		{"an empty label", "ip", "a..vpn.test", "Net.LookupNetIP->Net.exchange->buildQuery." + TagBadHostName},
		{"a label that is too long", "ip", strings.Repeat("a", 64) + ".test", "buildQuery." + TagBadHostName},
		{"a space", "ip", "a b.test", "Net.LookupNetIP." + TagBadHostName},
		{"an empty name", "ip", "", "Net.LookupNetIP." + TagBadHostName},
		{"a network that is not a lookup", "tcp", "web.vpn.test", "Net.LookupNetIP." + TagUnsupportedLookup},
	}
	for _, row := range errRows {
		_, err := na.LookupNetIP(ctx, row.network, row.host)
		if err == nil {
			t.Errorf("%s: LookupNetIP(%q, %q) succeeded", row.name, row.network, row.host)
			continue
		}
		wantRoute(t, err, row.route)
	}
}

func TestLookupWithoutServers(t *testing.T) {
	na, _, _, _ := newNets(t, false)
	_, err := na.LookupNetIP(t.Context(), "ip", "web.vpn.test")
	wantRoute(t, err, "Net.LookupNetIP->Net.exchange."+TagNoDNSServers)
	// A DNS server of a family that the tunnel does not have is no server.
	n6, _, _, _ := newNetsDNS(t, false, []string{"DNS6 fd00:8::1"})
	_, err = n6.LookupNetIP(t.Context(), "ip", "web.vpn.test")
	wantRoute(t, err, "Net.exchange."+TagNoDNSServers)
}

// TestDNSServersOption: Options.DNSServers replaces the pushed servers, for the lookups
// and for the Resolver; a port of 0 is 53; a server of a family that the tunnel lacks is
// skipped.
func TestDNSServersOption(t *testing.T) {
	// The server pushes 10.8.0.9, where nobody listens; the option names 10.8.0.3:5353.
	na, nb := newNetWith(t, false, []string{"DNS 10.8.0.9"}, &Options{
		DNSServers: []netip.AddrPort{
			netip.MustParseAddrPort("[fd00:8::3]:53"), // no IPv6 in this tunnel: skipped
			netip.MustParseAddrPort("10.8.0.3:5353"),
		},
	})
	listenDNS(t, nb, "10.8.0.3:5353", func(q []byte) []byte {
		return dnsAnswer(zone{"web.vpn.test": {netip.MustParseAddr("10.8.0.3")}}, q)
	})
	if got := na.dnsServers(); len(got) != 1 || got[0] != netip.MustParseAddrPort("10.8.0.3:5353") {
		t.Fatalf("dnsServers = %v", got)
	}
	got, err := na.LookupNetIP(t.Context(), "ip", "web.vpn.test")
	if err != nil || !slices.Equal(strs(got), []string{"10.8.0.3"}) {
		t.Fatalf("LookupNetIP = %v, %v", got, err)
	}
	if got, err := na.Resolver().LookupNetIP(t.Context(), "ip4", "web.vpn.test"); err != nil || !slices.Equal(strs(got), []string{"10.8.0.3"}) {
		t.Errorf("Resolver().LookupNetIP = %v, %v", got, err)
	}
	// DialContext uses them too.
	l, err := nb.Listen("tcp", ":7000")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closeOrFail(t, l)
	echoServer(t, l)
	c, err := na.DialContext(t.Context(), "tcp", "web.vpn.test:7000")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	roundTrip(t, c, []byte("own dns"))
	closeOrFail(t, c)

	// New copied the list: a change of the caller's slice changes nothing.
	own := []netip.AddrPort{netip.MustParseAddrPort("10.8.0.3:5353")}
	nCopy, _ := newNetWith(t, false, nil, &Options{DNSServers: own})
	own[0] = netip.MustParseAddrPort("10.8.0.77:53")
	if got := nCopy.dnsServers(); len(got) != 1 || got[0] != netip.MustParseAddrPort("10.8.0.3:5353") {
		t.Errorf("dnsServers after the caller changed its slice = %v", got)
	}

	// Port 0 is 53, and the pushed servers are used when the option is empty.
	n53, _ := newNetWith(t, false, []string{"DNS 10.8.0.9"}, &Options{DNSServers: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("10.8.0.3"), 0)}})
	if got := n53.dnsServers(); len(got) != 1 || got[0] != testServer {
		t.Errorf("dnsServers with port 0 = %v", got)
	}
	nPushed, _ := newNetWith(t, false, []string{"DNS 10.8.0.9"}, &Options{})
	if got := nPushed.dnsServers(); len(got) != 1 || got[0] != netip.MustParseAddrPort("10.8.0.9:53") {
		t.Errorf("pushed dnsServers = %v", got)
	}
	// Only servers of a family that the tunnel lacks: no server.
	nNone, _ := newNetWith(t, false, []string{"DNS 10.8.0.9"}, &Options{DNSServers: []netip.AddrPort{netip.MustParseAddrPort("[fd00:8::3]:53")}})
	_, err = nNone.LookupNetIP(t.Context(), "ip", "web.vpn.test")
	wantRoute(t, err, "Net.exchange."+TagNoDNSServers)
}

// dnsReply makes a response to query with the flags and, when records is not empty,
// the A record 10.8.0.3 for the name.
func dnsReply(query []byte, flags uint16, a bool) []byte {
	_, _, end, ok := dnsQuestion(query)
	if !ok {
		return nil
	}
	out := make([]byte, 12, 64)
	copy(out, query[:2])
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], 1)
	out = append(out, query[12:end]...)
	if a {
		binary.BigEndian.PutUint16(out[6:], 1)
		out = append(out, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 8, 0, 3)
	}
	return out
}

// TestLookupFailover: a server that answers with an error gives way to the next one
// and is tried after the others for a while, then it has its place again; "no such
// name" is an answer that ends the search.
func TestLookupFailover(t *testing.T) {
	na, nb := newNetWith(t, false, nil, &Options{DNSServers: []netip.AddrPort{
		netip.MustParseAddrPort("10.8.0.3:5301"), // SERVFAIL
		netip.MustParseAddrPort("10.8.0.3:5302"), // answers
		netip.MustParseAddrPort("10.8.0.3:5303"), // says that every name exists
	}})
	var asked [3]atomic.Int32
	count := func(i int, f func(q []byte) []byte) func(q []byte) []byte {
		return func(q []byte) []byte { asked[i].Add(1); return f(q) }
	}
	counts := func() [3]int32 { return [3]int32{asked[0].Load(), asked[1].Load(), asked[2].Load()} }
	listenDNS(t, nb, "10.8.0.3:5301", count(0, func(q []byte) []byte { return dnsReply(q, 0x8182, false) }))
	listenDNS(t, nb, "10.8.0.3:5302", count(1, func(q []byte) []byte {
		return dnsAnswer(zone{"web.vpn.test": {netip.MustParseAddr("10.8.0.3")}}, q)
	}))
	listenDNS(t, nb, "10.8.0.3:5303", count(2, func(q []byte) []byte { return dnsReply(q, 0x8180, true) }))

	got, err := na.LookupNetIP(t.Context(), "ip4", "web.vpn.test")
	if err != nil || !slices.Equal(strs(got), []string{"10.8.0.3"}) {
		t.Fatalf("LookupNetIP = %v, %v", got, err)
	}
	if c := counts(); c != [3]int32{1, 1, 0} {
		t.Errorf("asked %v: want the first and the second asked once", c)
	}
	// The first server failed: for a while the lookups start at the second.
	if _, err := na.LookupNetIP(t.Context(), "ip4", "web.vpn.test"); err != nil {
		t.Fatalf("second LookupNetIP: %v", err)
	}
	if c := counts(); c != [3]int32{1, 2, 0} {
		t.Errorf("asked %v: the second lookup should leave the server that failed for last", c)
	}
	// NXDOMAIN of the server that is asked ends the search: the third would have an answer.
	_, err = na.LookupNetIP(t.Context(), "ip4", "nothing.vpn.test")
	wantRoute(t, err, "parseResponse."+TagNoSuchHost)
	if c := counts(); c != [3]int32{1, 3, 0} {
		t.Errorf("asked %v after a NXDOMAIN: want only the second server asked", c)
	}
	// When the time is over the first server is asked first again: one failure does not
	// move the lookups away from the server that the VPN names first for good.
	na.dnsDown[0].Store(time.Now().Add(-time.Second).UnixNano())
	if _, err := na.LookupNetIP(t.Context(), "ip4", "web.vpn.test"); err != nil {
		t.Fatalf("LookupNetIP after the cool-down: %v", err)
	}
	if c := counts(); c != [3]int32{2, 4, 0} {
		t.Errorf("asked %v after the cool-down: want the first server asked again", c)
	}
	// Every server fails with an error: the last error is returned.
	nbad, nbBad := newNetWith(t, false, nil, &Options{DNSServers: []netip.AddrPort{netip.MustParseAddrPort("10.8.0.3:5301")}})
	listenDNS(t, nbBad, "10.8.0.3:5301", func(q []byte) []byte { return dnsReply(q, 0x8185, false) }) // REFUSED
	_, err = nbad.LookupNetIP(t.Context(), "ip4", "web.vpn.test")
	wantRoute(t, err, "parseResponse."+TagDNSServerError)
}

// TestLookupKeepsTheAddressesOfOneType: a server that says "no such name" for the AAAA
// of a name that has an A (RFC 4074 §4.2) does not make the name unknown: the A
// addresses are the answer. And the other way round.
func TestLookupKeepsTheAddressesOfOneType(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, true, []string{"DNS 10.8.0.3"})
	z := zone{"web.vpn.test": {netip.MustParseAddr("10.8.0.3")}, "six.vpn.test": {netip.MustParseAddr("fd00:8::3")}}
	listenDNS(t, nb, testServer.String(), func(q []byte) []byte {
		name, qtype, _, ok := dnsQuestion(q)
		if !ok {
			return nil
		}
		// NXDOMAIN for the type that the name has no address of.
		if (name == "web.vpn.test" && qtype == typeAAAA) || (name == "six.vpn.test" && qtype == typeA) {
			return dnsReply(q, 0x8183, false)
		}
		return dnsAnswer(z, q)
	})
	for host, want := range map[string]string{"web.vpn.test": "10.8.0.3", "six.vpn.test": "fd00:8::3"} {
		got, err := na.LookupNetIP(t.Context(), "ip", host)
		if err != nil || !slices.Equal(strs(got), []string{want}) {
			t.Errorf("LookupNetIP(ip, %s) = %v, %v; want %s", host, got, err, want)
		}
	}
	// No address of any type: the name does not exist.
	_, err := na.LookupNetIP(t.Context(), "ip", "nothing.vpn.test")
	wantRoute(t, err, "parseResponse."+TagNoSuchHost)
}

// TestLookupErrorWithoutAQuestion: a server may leave the question out of an answer
// that is an error. It is the error that it is, and the next server is asked at once,
// not after the wait for an answer that will not come.
func TestLookupErrorWithoutAQuestion(t *testing.T) {
	na, nb := newNetWith(t, false, nil, &Options{DNSServers: []netip.AddrPort{
		netip.MustParseAddrPort("10.8.0.3:5301"), netip.MustParseAddrPort("10.8.0.3:5302"),
	}})
	listenDNS(t, nb, "10.8.0.3:5301", func(q []byte) []byte {
		return []byte{q[0], q[1], 0x81, 0x85, 0, 0, 0, 0, 0, 0, 0, 0} // REFUSED, no question
	})
	listenDNS(t, nb, "10.8.0.3:5302", func(q []byte) []byte {
		return dnsAnswer(zone{"web.vpn.test": {netip.MustParseAddr("10.8.0.3")}}, q)
	})
	start := time.Now()
	got, err := na.LookupNetIP(t.Context(), "ip4", "web.vpn.test")
	if err != nil || !slices.Equal(strs(got), []string{"10.8.0.3"}) {
		t.Fatalf("LookupNetIP = %v, %v", got, err)
	}
	if took := time.Since(start); took > queryTimeout/2 {
		t.Errorf("the lookup took %v: the error of the first server was waited out", took)
	}
}

// TestDialContextTriesTheNextAddress: a name with two addresses, the first of which
// does not answer. Each address has a part of the time of the context, so the second
// is reached; the whole time used to go to the first.
func TestDialContextTriesTheNextAddress(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, false, []string{"DNS 10.8.0.3"})
	listenDNS(t, nb, testServer.String(), func(q []byte) []byte {
		return dnsAnswer(zone{"web.vpn.test": {netip.MustParseAddr("10.8.0.77"), netip.MustParseAddr("10.8.0.3")}}, q)
	})
	l, err := nb.Listen("tcp", ":7000")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closeOrFail(t, l)
	echoServer(t, l)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	c, err := na.DialContext(ctx, "tcp", "web.vpn.test:7000")
	if err != nil {
		t.Fatalf("DialContext = %v after %v: the second address was not reached", err, time.Since(start))
	}
	defer closeOrFail(t, c)
	if got := c.RemoteAddr().String(); got != "10.8.0.3:7000" {
		t.Errorf("connected to %s", got)
	}
	if took := time.Since(start); took < 2*time.Second || took > 4*time.Second {
		t.Errorf("the dial took %v, want the half of the 5 s that the first address had", took)
	}
}

func TestAttemptContext(t *testing.T) {
	parent, cancel := context.WithTimeout(t.Context(), 9*time.Second)
	defer cancel()
	left := func(ctx context.Context) time.Duration {
		d, ok := ctx.Deadline()
		if !ok {
			return -1
		}
		return time.Until(d).Round(time.Second)
	}
	rows := []struct {
		name   string
		parent context.Context
		left   int
		want   time.Duration
	}{
		{"the last address has all the time", parent, 1, 9 * time.Second},
		{"one of three has a third", parent, 3, 3 * time.Second},
		{"not less than the minimum", parent, 9, attemptMin},
		{"no deadline, the last address", t.Context(), 1, -1},
		{"no deadline, one of two", t.Context(), 2, attemptDefault},
	}
	for _, row := range rows {
		ctx, cancel := attemptContext(row.parent, row.left)
		if got := left(ctx); got != row.want {
			t.Errorf("%s: %v left, want %v", row.name, got, row.want)
		}
		cancel()
	}
}

// TestLookupTruncated: a truncated UDP answer is asked again over TCP.
func TestLookupTruncated(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, false, []string{"DNS 10.8.0.3"})
	listenDNS(t, nb, testServer.String(), func(q []byte) []byte { return dnsReply(q, 0x8380, false) }) // TC
	l, err := nb.Listen("tcp", "10.8.0.3:53")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closeOrFail(t, l)
	streams := 0
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			streams++
			var head [2]byte
			if _, err := io.ReadFull(c, head[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(head[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			reply := dnsReply(q, 0x8180, true)
			framed := binary.BigEndian.AppendUint16(nil, uint16(len(reply)&0xffff))
			if _, err := c.Write(append(framed, reply...)); err != nil {
				return
			}
			if err := c.Close(); err != nil {
				return
			}
		}
	}()
	got, err := na.LookupNetIP(t.Context(), "ip4", "web.vpn.test")
	if err != nil || !slices.Equal(strs(got), []string{"10.8.0.3"}) {
		t.Fatalf("LookupNetIP = %v, %v", got, err)
	}
	if streams != 1 {
		t.Errorf("%d streams, want 1", streams)
	}
}

// TestLookupNoAnswer: a server that never answers ends with the deadline of the context,
// and stray datagrams that are not the answer are ignored.
func TestLookupNoAnswer(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, false, []string{"DNS 10.8.0.3"})
	listenDNS(t, nb, testServer.String(), func(q []byte) []byte {
		wrong := dnsReply(q, 0x8180, true)
		wrong[0] ^= 0xff // the id of another query
		return wrong
	})
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	_, err := na.LookupNetIP(ctx, "ip4", "web.vpn.test")
	wantRoute(t, err, "Net.queryServer."+TagDNSQueryFailed)
}

// TestLookupCanceled: a context that is canceled ends a lookup that waits for an answer,
// well before the time of a try is over.
func TestLookupCanceled(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, false, []string{"DNS 10.8.0.3"})
	listenDNS(t, nb, testServer.String(), func([]byte) []byte { return nil })
	ctx, cancel := context.WithCancel(t.Context())
	timer := time.AfterFunc(50*time.Millisecond, cancel)
	defer timer.Stop()
	start := time.Now()
	_, err := na.LookupNetIP(ctx, "ip", "web.vpn.test")
	wantRoute(t, err, "Net.queryServer."+TagDNSQueryFailed)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("the error %v does not lead to context.Canceled", err)
	}
	if took := time.Since(start); took > queryTimeout/2 {
		t.Errorf("the lookup returned %v after the cancel", took)
	}
	// A context that is done before the lookup.
	_, err = na.LookupNetIP(ctx, "ip", "web.vpn.test")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("a lookup with a context that is done gave %v", err)
	}
}

// TestLookupAfterClose: a closed Net looks nothing up.
func TestLookupAfterClose(t *testing.T) {
	a, _ := hubDNS(t, false, "1500", []string{"DNS 10.8.0.3"})
	n, err := New(a.conn, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := n.LookupNetIP(t.Context(), "ip", "web.vpn.test"); !errors.Is(err, net.ErrClosed) {
		t.Errorf("LookupNetIP after Close = %v, want net.ErrClosed", err)
	}
	if _, err := n.LookupHost(t.Context(), "web.vpn.test"); !errors.Is(err, net.ErrClosed) {
		t.Errorf("LookupHost after Close = %v, want net.ErrClosed", err)
	}
}

// TestLookupStreamRefused: a stream that the server refuses after a truncated answer.
func TestLookupStreamRefused(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, false, []string{"DNS 10.8.0.3"})
	listenDNS(t, nb, testServer.String(), func(q []byte) []byte { return dnsReply(q, 0x8380, false) })
	_, err := na.LookupNetIP(t.Context(), "ip4", "web.vpn.test")
	wantRoute(t, err, "Net.queryStream->Net.DialContext->Net.dialTarget."+TagDialFailed)
}

// TestDialContextNoReachableAddress: the name has an address, but not of a family that the
// tunnel has.
func TestDialContextNoReachableAddress(t *testing.T) {
	na, nb, _, _ := newNetsDNS(t, true, []string{"DNS6 fd00:8::3"})
	listenDNS(t, nb, "[fd00:8::3]:53", func(q []byte) []byte {
		return dnsAnswer(zone{"web.vpn.test": {netip.MustParseAddr("10.8.0.3")}}, q)
	})
	na.has4 = false // before any use: the tunnel is IPv6 only
	_, err := na.DialContext(t.Context(), "tcp4", "web.vpn.test:7000")
	wantRoute(t, err, "Net.DialContext."+TagResolveFailed)
}

func TestParseResponse(t *testing.T) {
	server := testServer
	query, err := buildQuery(0x1234, "web.vpn.test", typeA)
	if err != nil {
		t.Fatal(err)
	}
	// with makes a response to the query and applies change to it.
	with := func(change func(m []byte) []byte) []byte {
		m := dnsReply(query, 0x8180, true)
		return change(m)
	}
	cname := []byte{0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c}
	rows := []struct {
		name   string
		msg    []byte
		route  string // "" for success
		addrs  []string
		trunc  bool
		qtype  uint16
		answer int
	}{
		{name: "an answer", msg: with(func(m []byte) []byte { return m }), addrs: []string{"10.8.0.3"}},
		{name: "the case of the name changed", msg: with(func(m []byte) []byte { m[13] = 'W'; return m }), addrs: []string{"10.8.0.3"}},
		{name: "a CNAME before the address", msg: with(func(m []byte) []byte {
			body := append(append([]byte{}, m[:len(query)]...), cname...)
			binary.BigEndian.PutUint16(body[6:], 2)
			return append(body, m[len(query):]...)
		}), addrs: []string{"10.8.0.3"}},
		{name: "truncated", msg: with(func(m []byte) []byte { m[2] |= 0x02; return m }), trunc: true},
		{name: "another id", msg: with(func(m []byte) []byte { m[1]++; return m }), route: TagBadDNSResponse},
		{name: "a query, not a response", msg: with(func(m []byte) []byte { m[2] &^= 0x80; return m }), route: TagBadDNSResponse},
		{name: "a short message", msg: query[:8], route: TagBadDNSResponse},
		{name: "another question", msg: with(func(m []byte) []byte { m[14] = 'x'; return m }), route: TagBadDNSResponse},
		{name: "two questions", msg: with(func(m []byte) []byte { m[5] = 2; return m }), route: TagBadDNSResponse},
		{name: "a record that is cut off", msg: with(func(m []byte) []byte { return m[:len(m)-3] }), route: TagBadDNSResponse},
		{name: "more records than there are", msg: with(func(m []byte) []byte { m[7] = 3; return m }), route: TagBadDNSResponse},
		{name: "a name that never ends", msg: with(func(m []byte) []byte { m[len(query)] = 5; return m }), route: TagBadDNSResponse},
		{name: "a bad label", msg: with(func(m []byte) []byte { m[len(query)] = 0x80; return m }), route: TagBadDNSResponse},
		{name: "NXDOMAIN", msg: with(func(m []byte) []byte { m[3] |= 3; return m }), route: TagNoSuchHost},
		{name: "SERVFAIL", msg: with(func(m []byte) []byte { m[3] |= 2; return m }), route: TagDNSServerError},
		{name: "REFUSED with no question", msg: []byte{0x12, 0x34, 0x81, 0x85, 0, 0, 0, 0, 0, 0, 0, 0}, route: TagDNSServerError},
		{name: "an answer with no question", msg: []byte{0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}, route: TagBadDNSResponse},
		{name: "NXDOMAIN with no question", msg: []byte{0x12, 0x34, 0x81, 0x83, 0, 0, 0, 0, 0, 0, 0, 0}, route: TagBadDNSResponse},
		{name: "an address of the wrong size", msg: with(func(m []byte) []byte { m[len(m)-5] = 3; return m[:len(m)-1] }), addrs: nil},
	}
	for _, row := range rows {
		got, trunc, err := parseResponse(row.msg, query, typeA, server)
		if row.route != "" {
			if err == nil {
				t.Errorf("%s: no error", row.name)
				continue
			}
			wantRoute(t, err, "parseResponse."+row.route)
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", row.name, err)
			continue
		}
		if trunc != row.trunc || !slices.Equal(strs(got), row.addrs) {
			t.Errorf("%s: got %v truncated=%v, want %v truncated=%v", row.name, strs(got), trunc, row.addrs, row.trunc)
		}
	}
}

func TestParseResponseRoute(t *testing.T) {
	query, err := buildQuery(1, "web.vpn.test", typeA)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = parseResponse([]byte{1, 2, 3}, query, typeA, testServer)
	wantRoute(t, err, "parseResponse."+TagBadDNSResponse)
}

func TestBuildQuery(t *testing.T) {
	q, err := buildQuery(7, "Web.Vpn.", typeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	name, qtype, end, ok := dnsQuestion(q)
	if !ok || name != "web.vpn" || qtype != typeAAAA || end != len(q) || binary.BigEndian.Uint16(q) != 7 || q[2] != 1 {
		t.Errorf("question = %q %d, ok %v, query %x", name, qtype, ok, q)
	}
}

// FuzzParseResponse: no answer from the network makes parseResponse panic, and what it
// accepts has addresses of the right family.
func FuzzParseResponse(f *testing.F) {
	query, err := buildQuery(0x1234, "web.vpn.test", typeA)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(dnsReply(query, 0x8180, true))
	f.Add(dnsReply(query, 0x8380, false))
	f.Add(dnsReply(query, 0x8183, false))
	f.Add(query)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		for _, qtype := range []uint16{typeA, typeAAAA} {
			q, err := buildQuery(0x1234, "web.vpn.test", qtype)
			if err != nil {
				t.Fatal(err)
			}
			addrs, _, err := parseResponse(msg, q, qtype, testServer)
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if (qtype == typeA) != a.Is4() {
					t.Fatalf("type %d gave %v", qtype, a)
				}
			}
		}
	})
}

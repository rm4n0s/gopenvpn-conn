// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/rm4n0s/errors"
)

// Tags of the errors of LookupNetIP and LookupHost.
const (
	// TagNoSuchHost: the DNS server answered that the name does not exist, or that it
	// has no address of the families asked for. Metadata: "host".
	TagNoSuchHost = "NetNoSuchHost"
	// TagBadHostName: the host is not a name that can be asked of a DNS server (an
	// empty label, a label of more than 63 bytes, a character outside letters, digits,
	// hyphen, underscore and dot, or more than 253 bytes). Metadata: "host".
	TagBadHostName = "NetBadHostName"
	// TagUnsupportedLookup: the network of LookupNetIP is not "ip", "ip4" or "ip6".
	// Metadata: "network".
	TagUnsupportedLookup = "NetUnsupportedLookup"
	// TagDNSQueryFailed: a query to a DNS server failed on the way: the connection
	// failed, or no answer came in time. Metadata: "server".
	TagDNSQueryFailed = "NetDNSQueryFailed"
	// TagDNSServerError: the DNS server answered with an error (SERVFAIL, REFUSED, ...).
	// Metadata: "server", "rcode".
	TagDNSServerError = "NetDNSServerError"
	// TagBadDNSResponse: the answer of a DNS server is not a well-formed answer to the
	// query that was sent. Metadata: "reason".
	TagBadDNSResponse = "NetBadDNSResponse"
)

// The types and the one class of DNS that a lookup uses (RFC 1035 §3.2, RFC 3596).
const (
	typeA    = 1
	typeAAAA = 28
	classIN  = 1
)

// The time that one try of a query takes before it is sent again, and the number of tries
// of a server, and the time that a stream (after a truncated answer) may take.
const (
	queryTimeout  = 2 * time.Second
	queryTries    = 2
	streamTimeout = 5 * time.Second
)

// LookupNetIP looks up the addresses of host through the tunnel, at the DNS servers of
// Options.DNSServers, or at the ones that the VPN server pushed when there are none.
// network is "ip", "ip4" or "ip6". It is a DNS client of this package and reads nothing
// of the host: not /etc/hosts, not /etc/resolv.conf, so the answer comes from the DNS
// servers of the VPN alone, and the name is asked as it is given, with no search list
// and no "ndots". host may be an IP address, which is returned as it is.
//
// The servers are tried in order. A server that fails (an error, or no answer in time)
// gives its place to the next one, and is tried after the others for the next half
// minute; "no such name" is an answer, and no other server is asked. ctx bounds the
// lookup. The errors are tagged
// (TagNoSuchHost, TagNoDNSServers, TagDNSQueryFailed, ...); after Close, and after the
// tunnel has ended, the error is the one that ended the Net, as for DialContext.
func (n *Net) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := n.err(); err != nil {
		return nil, err
	}
	var types []uint16
	switch network {
	case "ip":
		types = []uint16{typeA, typeAAAA}
	case "ip4":
		types = []uint16{typeA}
	case "ip6":
		types = []uint16{typeAAAA}
	default:
		return nil, errors.New(TagUnsupportedLookup, "the network of a lookup is ip, ip4 or ip6", "network", network)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if (network == "ip4" && !ip.Is4()) || (network == "ip6" && !ip.Is6()) {
			return nil, errors.New(TagNoSuchHost, "the address is not of the family asked for", "host", host)
		}
		return []netip.Addr{ip}, nil
	}
	if !validHostName(host) {
		return nil, errors.New(TagBadHostName, "the host is not a name that a DNS server can be asked", "host", host)
	}
	var addrs []netip.Addr
	var firstErr error
	for _, t := range types {
		got, err := n.exchange(ctx, host, t)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			// The other type is still asked, also after "no such name": some servers
			// say that for the AAAA of a name that has an A (RFC 4074 §4.2), and the
			// addresses of the one type are the answer then. When no type has an
			// address, a failure is reported before "no such name", which it may hide.
			if firstErr == nil || isTag(firstErr, TagNoSuchHost) {
				firstErr = err
			}
			continue
		}
		addrs = append(addrs, got...)
	}
	if len(addrs) > 0 {
		return addrs, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errors.New(TagNoSuchHost, "the name has no address of the families asked for", "host", host)
}

// LookupHost is LookupNetIP for both families, with the addresses as strings, as
// net.Resolver.LookupHost gives them.
func (n *Net) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := n.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out, nil
}

// isTag tells whether err is one of this module's errors with the tag.
func isTag(err error, tag string) bool {
	appErr, ok := errors.FromError(err)
	return ok && appErr.Tag == tag
}

// exchange asks the DNS servers for the records of qtype of name, in the order of
// dnsOrder. The first answer is the result; a name that does not exist ends the
// search.
func (n *Net) exchange(ctx context.Context, name string, qtype uint16) ([]netip.Addr, error) {
	servers := n.dnsServers()
	if len(servers) == 0 {
		return nil, errors.New(TagNoDNSServers, "no DNS server that the tunnel can reach: none was pushed and Options.DNSServers has none")
	}
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, errors.NewErr(TagDNSQueryFailed, err)
	}
	query, err := buildQuery(binary.BigEndian.Uint16(id[:]), name, qtype)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, idx := range n.dnsOrder(len(servers)) {
		addrs, err := n.queryServer(ctx, servers[idx], query, qtype)
		if err == nil || isTag(err, TagNoSuchHost) {
			n.noteDNS(idx, nil)
			return addrs, err
		}
		if ctx.Err() == nil {
			n.noteDNS(idx, err) // not the server's fault when the caller gave up
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// queryServer sends the query to one server over UDP, again when no answer comes, and
// over a stream when the answer is truncated.
func (n *Net) queryServer(ctx context.Context, server netip.AddrPort, query []byte, qtype uint16) ([]netip.Addr, error) {
	conn, err := n.DialContext(ctx, "udp", server.String())
	if err != nil {
		return nil, err
	}
	defer closeQuietly(conn)
	// A context that ends wakes the read at once.
	stop := context.AfterFunc(ctx, func() { expire(conn) })
	defer stop()
	buf := make([]byte, 4096)
	for try := 0; try < queryTries; try++ {
		if err := conn.SetDeadline(time.Now().Add(queryTimeout)); err != nil {
			return nil, errors.NewErr(TagDNSQueryFailed, err).SetMetadata("server", server.String())
		}
		// Checked after the deadline is set: a context that ended before this line is
		// seen here, and one that ends later moves the deadline to the past.
		if err := ctx.Err(); err != nil {
			return nil, errors.NewErr(TagDNSQueryFailed, err).SetMetadata("server", server.String())
		}
		if _, err := conn.Write(query); err != nil {
			return nil, errors.NewErr(TagDNSQueryFailed, err).SetMetadata("server", server.String())
		}
		for {
			size, err := conn.Read(buf)
			if err != nil {
				if cerr := ctx.Err(); cerr != nil {
					return nil, errors.NewErr(TagDNSQueryFailed, cerr).SetMetadata("server", server.String())
				}
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break // no answer in time: ask again
				}
				return nil, errors.NewErr(TagDNSQueryFailed, err).SetMetadata("server", server.String())
			}
			addrs, truncated, err := parseResponse(buf[:size], query, qtype, server)
			if err != nil {
				if isTag(err, TagBadDNSResponse) {
					continue // not an answer to this query: a stray datagram; keep waiting
				}
				return nil, err
			}
			if truncated {
				return n.queryStream(ctx, server, query, qtype)
			}
			return addrs, nil
		}
	}
	return nil, errors.New(TagDNSQueryFailed, "the DNS server did not answer", "server", server.String())
}

// queryStream is the query over TCP, with the two-byte length of RFC 1035 §4.2.2.
func (n *Net) queryStream(ctx context.Context, server netip.AddrPort, query []byte, qtype uint16) ([]netip.Addr, error) {
	conn, err := n.DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, err
	}
	defer closeQuietly(conn)
	stop := context.AfterFunc(ctx, func() { expire(conn) })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(streamTimeout)); err != nil {
		return nil, errors.NewErr(TagDNSQueryFailed, err).SetMetadata("server", server.String())
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.NewErr(TagDNSQueryFailed, err).SetMetadata("server", server.String())
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)&0xffff))
	if _, err := conn.Write(append(framed, query...)); err != nil {
		return nil, errors.NewErr(TagDNSQueryFailed, err).SetMetadata("server", server.String())
	}
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, errors.NewErr(TagDNSQueryFailed, err).SetMetadata("server", server.String())
	}
	msg := make([]byte, binary.BigEndian.Uint16(head[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, errors.NewErr(TagDNSQueryFailed, err).SetMetadata("server", server.String())
	}
	addrs, truncated, err := parseResponse(msg, query, qtype, server)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, errors.New(TagBadDNSResponse, "the answer over a stream is truncated", "reason", "tc over tcp")
	}
	return addrs, nil
}

// expire moves the deadline of the connection of a query to the past, so that its read
// and write return: the context of the query is done. The query fails with the error
// of the context whether or not the deadline could be set.
func expire(c net.Conn) {
	_ = c.SetDeadline(time.Unix(1, 0)) //nolint:errcheck // see the comment
}

// closeQuietly closes a connection of a query that is over; a failure to close one
// that has been used says nothing about the answer.
func closeQuietly(c net.Conn) {
	_ = c.Close() //nolint:errcheck // the query is over; see the comment
}

// buildQuery makes a query for one question, with recursion desired (RFC 1035 §4.1).
func buildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	msg := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // a query, recursion desired
	binary.BigEndian.PutUint16(msg[4:], 1)      // one question
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New(TagBadHostName, "a label of the name is empty or longer than 63 bytes", "host", name)
		}
		msg = append(msg, byte(len(label)&0x3f))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, classIN)
	return msg, nil
}

// equalASCIIFold compares two names, ignoring the case of ASCII letters only (a name has
// no other kind of letter on the wire).
func equalASCIIFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// skipName returns the offset after the name that starts at off: after its zero label,
// or after a compression pointer, which ends a name (RFC 1035 §4.1.4).
func skipName(msg []byte, off int) (int, bool) {
	for off < len(msg) {
		b := msg[off]
		switch {
		case b == 0:
			return off + 1, true
		case b&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		case b&0xc0 != 0:
			return 0, false
		}
		off += 1 + int(b)
	}
	return 0, false
}

// parseResponse checks that msg answers query and returns the addresses of type qtype
// in its answer section. truncated is true when the server cut the answer (TC): the
// query is then asked again over a stream. Anything that does not answer this query
// is TagBadDNSResponse. Records of other types (CNAME) are skipped: the server is a
// recursive one, so the addresses that follow a CNAME are those of its target.
func parseResponse(msg, query []byte, qtype uint16, server netip.AddrPort) (addrs []netip.Addr, truncated bool, err error) {
	if len(msg) < 12 || !bytes.Equal(msg[:2], query[:2]) {
		return nil, false, errors.New(TagBadDNSResponse, "the id does not match", "reason", "id")
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x8000 == 0 || flags>>11&0xf != 0 {
		return nil, false, errors.New(TagBadDNSResponse, "the message is not the response to a query", "reason", "flags")
	}
	// The question must be the one that was asked; names are not case sensitive, and
	// some servers change the case. A server may leave the question out of an answer
	// that is an error (REFUSED, SERVFAIL, a query that it could not read): the id is
	// then all that ties it to the query, and it is taken as the error that it is, so
	// that the next server is asked at once and not after the wait for an answer.
	rcode := flags & 0xf
	if questions := binary.BigEndian.Uint16(msg[4:]); questions != 0 || rcode == 0 || rcode == 3 {
		if questions != 1 || len(msg) < len(query) || !equalASCIIFold(msg[12:len(query)], query[12:]) {
			return nil, false, errors.New(TagBadDNSResponse, "the question is not the one that was asked", "reason", "question")
		}
	}
	if flags&0x0200 != 0 {
		return nil, true, nil
	}
	switch rcode {
	case 0:
	case 3:
		return nil, false, errors.New(TagNoSuchHost, "the DNS server says that the name does not exist", "server", server.String())
	default:
		return nil, false, errors.New(TagDNSServerError, "the DNS server answered with an error", "server", server.String(), "rcode", int(rcode))
	}
	off := len(query)
	for i := binary.BigEndian.Uint16(msg[6:]); i > 0; i-- {
		next, ok := skipName(msg, off)
		if !ok || next+10 > len(msg) {
			return nil, false, errors.New(TagBadDNSResponse, "a record is cut off", "reason", "record")
		}
		rtype := binary.BigEndian.Uint16(msg[next:])
		class := binary.BigEndian.Uint16(msg[next+2:])
		size := int(binary.BigEndian.Uint16(msg[next+8:]))
		data := next + 10
		if data+size > len(msg) {
			return nil, false, errors.New(TagBadDNSResponse, "the data of a record is cut off", "reason", "rdata")
		}
		off = data + size
		if class != classIN || rtype != qtype {
			continue
		}
		want := 4
		if qtype == typeAAAA {
			want = 16
		}
		if addr, ok := netip.AddrFromSlice(msg[data:off]); ok && size == want {
			addrs = append(addrs, addr)
		}
	}
	return addrs, false, nil
}

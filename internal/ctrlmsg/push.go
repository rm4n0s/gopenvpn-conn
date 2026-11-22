// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/push.c, options.c (the options that a server pushes) and doc/man-sections/vpn-network-options.rst, client-options.rst (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-21.

package ctrlmsg

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rm4n0s/errors"
)

// Tags of the errors about the options that a server pushes.
const (
	// TagUnsupportedPushedOption: the server pushed an option that changes
	// what is on the wire in a way this library does not implement (compression,
	// fragmentation, a data cipher that is not AEAD). Metadata: "option".
	TagUnsupportedPushedOption = "UnsupportedPushedOption"
	// TagCipherNegotiationFailed: the server pushed a data cipher that the
	// client did not offer. Metadata: "cipher".
	TagCipherNegotiationFailed = "CipherNegotiationFailed"

	tagBadPushedOption = "BadPushedOption"

	// TagPushedOptionRejected: a pull filter of the profile with the action reject
	// matched a pushed option. Metadata: "option" (the name of the option, never its
	// arguments).
	TagPushedOptionRejected = "PushedOptionRejected"
	tagTooManyPushed        = "TooManyPushedOptions"
)

// maxPushedOptions bounds the options that a server may push over all the parts
// of its reply (SPEC §15 rule 6).
const maxPushedOptions = 4096

// Route is a route that the server pushed.
type Route struct {
	Prefix netip.Prefix
	// Gateway is the next hop when the option names one; the zero Addr means
	// the gateway of the VPN.
	Gateway netip.Addr
	// Metric is the metric, or 0 when the option has none.
	Metric int
}

// Pushed is what a server pushed: the options of every part of its PUSH_REPLY,
// understood. A Pushed is built by Add for each part and Finish after the last.
type Pushed struct {
	// Options are all the options as received, without push-continuation. The
	// value of auth-token is not kept: it is a secret.
	Options []string
	// Unknown are the names of the options that are not known.
	Unknown []string

	Topology        string // "subnet", "net30" or "p2p"
	Addrs           []netip.Prefix
	Gateway         netip.Addr
	Routes          []Route
	RedirectGateway bool
	DNSServers      []netip.Addr
	SearchDomains   []string
	MTU             int // 0 when not pushed
	PingInterval    time.Duration
	PingRestart     time.Duration
	PeerID          uint32
	HasPeerID       bool
	Cipher          string
	KeyDerivation   string
	ProtocolFlags   []string
	AuthToken       string // a secret: never logged
	AuthTokenUser   string
	RenegInterval   time.Duration
	HasReneg        bool
	ExitNotify      int // explicit-exit-notify: the number of tries, 0 when not pushed

	ifconfig []string
}

// aead is the data ciphers that are supported.
var aead = []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"}

// ignored are the options that only matter to a system tunnel or to OpenVPN's
// own program. They are kept in Options and nothing else is done.
var ignored = []string{
	"block-outside-dns", "register-dns", "persist-tun", "persist-key", "sndbuf", "rcvbuf", "socket-flags",
	"route-delay", "route-method", "ip-win32", "dhcp-renew", "dhcp-release", "tun-ipv6", "inactive",
	"ping-timer-rem", "ping-exit", "push-peer-info", "route-nopull", "redirect-private", "ifconfig-nowarn",
	"ifconfig-pool-persist", "resolv-retry", "route-up", "push-update",
}

// refused are the options that add framing that this library does not parse.
var refused = []string{"compress", "comp-lzo", "fragment"}

// Add takes the options of one part of the reply. offered are the data ciphers
// the client offered, in capitals: a pushed cipher must be one of them.
func (p *Pushed) Add(reply *PushReply, offered []string) error {
	if len(p.Options)+len(reply.Options) > maxPushedOptions {
		return errors.New(tagTooManyPushed, "the server pushed too many options", "max", maxPushedOptions)
	}
	for _, opt := range reply.Options {
		fields := strings.Fields(opt)
		if len(fields) == 0 {
			continue
		}
		name, args := fields[0], fields[1:]
		if name == "auth-token" {
			p.Options = append(p.Options, "auth-token") // the value is a secret
		} else {
			p.Options = append(p.Options, opt)
		}
		if err := p.apply(name, args, offered); err != nil {
			return err
		}
	}
	return nil
}

// outcome is what understanding one option led to.
type outcome int

const (
	okOption outcome = iota
	malformed
	unsupported
	cipherNotOffered
)

// apply understands one option, and makes the error when it is not to be taken.
func (p *Pushed) apply(name string, args, offered []string) error {
	out, detail := p.understand(name, args, offered)
	switch out {
	case malformed:
		return errors.New(tagBadPushedOption, detail, "option", name)
	case unsupported:
		return errors.New(TagUnsupportedPushedOption, "the server pushed an option that this client does not implement", "option", name, "detail", detail)
	case cipherNotOffered:
		return errors.New(TagCipherNegotiationFailed, "the server pushed a data cipher that the client did not offer", "cipher", detail)
	}
	return nil
}

// understand reads one option into p. When the option is not to be taken it says
// why: detail is then what is wrong, in words that carry no value that could be
// a secret.
func (p *Pushed) understand(name string, args, offered []string) (out outcome, detail string) {
	switch name {
	case "topology":
		if len(args) != 1 || !slices.Contains([]string{"subnet", "net30", "p2p"}, args[0]) {
			return malformed, "the topology is not subnet, net30 or p2p"
		}
		p.Topology = args[0]
	case "ifconfig":
		if len(args) != 2 {
			return malformed, "ifconfig takes two addresses"
		}
		p.ifconfig = args
	case "ifconfig-ipv6":
		if len(args) < 1 {
			return malformed, "ifconfig-ipv6 takes an address and a length"
		}
		prefix, err := netip.ParsePrefix(args[0])
		if err != nil || !prefix.Addr().Is6() {
			return malformed, "the address is not an IPv6 address with its length"
		}
		p.Addrs = append(p.Addrs, prefix)
	case "route":
		r, problem := parseRoute(args)
		if problem != "" {
			return malformed, problem
		}
		p.Routes = append(p.Routes, r)
	case "route-ipv6":
		r, problem := parseRoute6(args)
		if problem != "" {
			return malformed, problem
		}
		p.Routes = append(p.Routes, r)
	case "route-gateway":
		if len(args) != 1 {
			return malformed, "route-gateway takes one address"
		}
		if args[0] != "dhcp" {
			addr, err := netip.ParseAddr(args[0])
			if err != nil {
				return malformed, "the gateway is not an address"
			}
			p.Gateway = addr
		}
	case "redirect-gateway":
		p.RedirectGateway = true
	case "dhcp-option":
		return p.dhcpOption(args)
	case "dns":
		return p.dns(args)
	case "tun-mtu":
		n, ok := atoiRange(args, 68, 65535)
		if !ok {
			return malformed, "the MTU is not a number from 68 to 65535"
		}
		p.MTU = n
	case "ping":
		n, ok := atoiRange(args, 0, 1<<24)
		if !ok {
			return malformed, "the time is not a number of seconds"
		}
		p.PingInterval = time.Duration(n) * time.Second
	case "ping-restart":
		n, ok := atoiRange(args, 0, 1<<24)
		if !ok {
			return malformed, "the time is not a number of seconds"
		}
		p.PingRestart = time.Duration(n) * time.Second
	case "reneg-sec":
		n, ok := atoiRange(args, 0, 1<<30)
		if !ok {
			return malformed, "the time is not a number of seconds"
		}
		p.RenegInterval, p.HasReneg = time.Duration(n)*time.Second, true
	case "peer-id":
		n, ok := atoiRange(args, 0, 0xffffff)
		if !ok {
			return malformed, "the peer id is not a number from 0 to 16777215"
		}
		p.PeerID, p.HasPeerID = uint32(n&0xffffff), true
	case "cipher":
		return p.cipher(args, offered)
	case "key-derivation":
		if len(args) != 1 {
			return malformed, "key-derivation takes one word"
		}
		p.KeyDerivation = args[0]
	case "protocol-flags":
		p.ProtocolFlags = append(p.ProtocolFlags, args...)
	case "auth-token":
		if len(args) < 1 {
			return malformed, "auth-token takes a value"
		}
		p.AuthToken = args[0]
	case "auth-token-user":
		if len(args) != 1 {
			return malformed, "auth-token-user takes a value"
		}
		p.AuthTokenUser = args[0]
	case "explicit-exit-notify":
		n := 1
		if len(args) > 0 {
			var ok bool
			if n, ok = atoiRange(args, 1, 1<<16); !ok {
				return malformed, "the number of tries is not a number"
			}
		}
		p.ExitNotify = n
	default:
		switch {
		case slices.Contains(refused, name):
			return unsupported, "it adds framing to the packets"
		case slices.Contains(ignored, name):
		default:
			p.Unknown = append(p.Unknown, name)
		}
	}
	return okOption, ""
}

// cipher checks a pushed data cipher: it must be AEAD and supported, and one
// that the client offered.
func (p *Pushed) cipher(args, offered []string) (outcome, string) {
	if len(args) != 1 {
		return malformed, "cipher takes one name"
	}
	name := strings.ToUpper(args[0])
	if !slices.Contains(aead, name) {
		return unsupported, "the data cipher is not AEAD or not supported"
	}
	if !slices.Contains(offered, name) {
		return cipherNotOffered, name
	}
	p.Cipher = name
	return okOption, ""
}

// dhcpOption takes the options of "dhcp-option" that the client uses: the DNS
// servers and the domains.
func (p *Pushed) dhcpOption(args []string) (outcome, string) {
	if len(args) < 2 {
		return okOption, "" // dhcp-option takes more words for other kinds
	}
	switch args[0] {
	case "DNS", "DNS6":
		addr, err := netip.ParseAddr(args[1])
		if err != nil {
			return malformed, "the DNS server is not an address"
		}
		p.addDNS(addr)
	case "DOMAIN", "DOMAIN-SEARCH":
		p.addDomain(args[1])
	}
	return okOption, ""
}

// dns takes the "dns" option: "dns server N address A ..." and "dns
// search-domains D ...". The other forms are not used.
func (p *Pushed) dns(args []string) (outcome, string) {
	switch {
	case len(args) >= 4 && args[0] == "server" && args[2] == "address":
		for _, a := range args[3:] {
			// An address may carry a port after it; only the address is used.
			addr, err := netip.ParseAddr(a)
			if err != nil {
				ap, err2 := netip.ParseAddrPort(a)
				if err2 != nil {
					return malformed, "a DNS server is not an address"
				}
				addr = ap.Addr()
			}
			p.addDNS(addr)
		}
	case len(args) >= 2 && args[0] == "search-domains":
		for _, d := range args[1:] {
			p.addDomain(d)
		}
	}
	return okOption, ""
}

func (p *Pushed) addDNS(addr netip.Addr) {
	if !slices.Contains(p.DNSServers, addr) {
		p.DNSServers = append(p.DNSServers, addr)
	}
}

func (p *Pushed) addDomain(d string) {
	if !slices.Contains(p.SearchDomains, d) {
		p.SearchDomains = append(p.SearchDomains, d)
	}
}

// Finish ends the reply, after the last part: the addresses that depend on the
// topology are worked out. With topology subnet "ifconfig" is an address and a
// netmask; with net30 (the default) and p2p it is the local and the remote
// address.
func (p *Pushed) Finish() error {
	if p.Topology == "" {
		p.Topology = "net30"
	}
	if p.ifconfig == nil {
		return nil
	}
	local, err := netip.ParseAddr(p.ifconfig[0])
	if err != nil || !local.Is4() {
		return errors.New(tagBadPushedOption, "the local address is not an IPv4 address", "option", "ifconfig")
	}
	second, err := netip.ParseAddr(p.ifconfig[1])
	if err != nil || !second.Is4() {
		return errors.New(tagBadPushedOption, "the second address is not an IPv4 address", "option", "ifconfig")
	}
	bits := 32 // p2p
	switch p.Topology {
	case "subnet":
		var ok bool
		if bits, ok = maskBits(second); !ok {
			return errors.New(tagBadPushedOption, "the netmask is not contiguous", "option", "ifconfig")
		}
	case "net30":
		bits = 30
	}
	// IPv4 first, as the server lists them.
	p.Addrs = append([]netip.Prefix{netip.PrefixFrom(local, bits)}, p.Addrs...)
	return nil
}

// parseRoute reads "route NET [MASK [GATEWAY [METRIC]]]". It returns what is
// wrong with the option, or "" when nothing is.
func parseRoute(args []string) (Route, string) {
	if len(args) < 1 || len(args) > 4 {
		return Route{}, "route takes one to four words"
	}
	network, bits := netip.IPv4Unspecified(), 32
	if args[0] == "default" {
		bits = 0
	} else {
		var err error
		if network, err = netip.ParseAddr(args[0]); err != nil || !network.Is4() {
			return Route{}, "the network is not an IPv4 address"
		}
	}
	if len(args) >= 2 {
		mask, err := netip.ParseAddr(args[1])
		if err != nil || !mask.Is4() {
			return Route{}, "the netmask is not an IPv4 address"
		}
		var ok bool
		if bits, ok = maskBits(mask); !ok {
			return Route{}, "the netmask is not contiguous"
		}
	}
	r := Route{Prefix: netip.PrefixFrom(network, bits).Masked()}
	return r, routeTail(&r, args, 2)
}

// parseRoute6 reads "route-ipv6 NET/BITS [GATEWAY [METRIC]]".
func parseRoute6(args []string) (Route, string) {
	if len(args) < 1 || len(args) > 3 {
		return Route{}, "route-ipv6 takes one to three words"
	}
	prefix, err := netip.ParsePrefix(args[0])
	if err != nil || !prefix.Addr().Is6() {
		return Route{}, "the network is not an IPv6 prefix"
	}
	r := Route{Prefix: prefix.Masked()}
	return r, routeTail(&r, args, 1)
}

// routeTail reads the gateway and the metric that may follow a route, from
// args[at:]. A gateway that is a keyword (vpn_gateway, net_gateway,
// remote_host) leaves the gateway empty; "default" for the metric is no metric.
func routeTail(r *Route, args []string, at int) string {
	if len(args) > at {
		switch args[at] {
		case "vpn_gateway", "net_gateway", "remote_host":
		default:
			gw, err := netip.ParseAddr(args[at])
			if err != nil {
				return "the gateway is not an address"
			}
			r.Gateway = gw
		}
	}
	if len(args) > at+1 && args[at+1] != "default" {
		n, err := strconv.Atoi(args[at+1])
		if err != nil || n < 0 || n > 1<<24 {
			return "the metric is not a number"
		}
		r.Metric = n
	}
	return ""
}

// maskBits is the length of a netmask like 255.255.255.0, and false when its ones
// are not all at the start.
func maskBits(mask netip.Addr) (int, bool) {
	b := mask.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	ones := 0
	for v&0x80000000 != 0 {
		ones++
		v <<= 1
	}
	return ones, v == 0
}

// atoiRange reads one decimal number from args, between lo and hi.
func atoiRange(args []string, lo, hi int) (int, bool) {
	if len(args) != 1 {
		return 0, false
	}
	n, err := strconv.Atoi(args[0])
	return n, err == nil && n >= lo && n <= hi
}

// Verdict is what a pull filter decides about one pushed option.
type Verdict uint8

const (
	// Accept keeps the option.
	Accept Verdict = iota
	// Ignore takes the option out, as if the server had not pushed it.
	Ignore
	// Reject ends the handshake with an error.
	Reject
)

// Filter applies a pull filter to the options of a part of the reply: the options for
// which decide says Ignore are taken out, and one for which it says Reject is an error.
//
// OpenVPN: options.c apply_pull_filter.
func (r *PushReply) Filter(decide func(option string) Verdict) error {
	kept := r.Options[:0]
	for _, opt := range r.Options {
		switch decide(opt) {
		case Ignore:
			continue
		case Reject:
			name, _, _ := strings.Cut(strings.TrimSpace(opt), " ")
			return errors.New(TagPushedOptionRejected, "a pull filter rejected a pushed option", "option", name)
		}
		kept = append(kept, opt)
	}
	r.Options = kept
	return nil
}

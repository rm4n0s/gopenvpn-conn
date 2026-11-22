// SPDX-License-Identifier: GPL-2.0-only
// Based on OpenVPN 2.7.9, src/openvpn/options.c (add_option) and the option pages of doc/man-sections/ (Copyright (C) 2002-2026 OpenVPN Inc); rewritten in Go and changed for gopenvpn-conn, 2026-11-22.

package ovpn

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io/fs"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
)

// handler applies one option of the profile to the builder.
type handler func(b *builder, l line) error

// spec is an option that the library supports: how many arguments it takes (an inline
// file has none and ignores these numbers), and what it does.
type spec struct {
	min, max int
	fn       handler
}

// rawRemote is a remote line before the defaults are applied: they can come later in
// the profile.
type rawRemote struct {
	host, port, proto   string // what the line said, or ""
	connPort, connProto string // what its <connection> block said, or ""
}

// builder collects what the options of a profile say, and finish makes the Profile.
type builder struct {
	fsys          fs.FS
	dir           string
	handlers      map[string]spec
	ignoreUnknown []string
	// forwardCompatible: setenv FORWARD_COMPATIBLE 1 came, after which an option that
	// is not known is left out and not an error.
	//
	// OpenVPN: options.c msglevel_forward_compatible.
	forwardCompatible bool

	remotes        []rawRemote
	defPort        string
	defProto       string
	remoteRandom   bool
	connectTimeout time.Duration
	ignored        []string
	needsCreds     bool
	conn           *rawRemote // set while a <connection> block is read: its own proto and port

	cfg              openvpn.Config
	ca, cert, key    string
	haveCA           bool
	remoteCertServer bool
	verifyName       string
	verifyMatch      openvpn.NameMatch
	fingerprints     [][sha256.Size]byte
	minVersion       uint16
	groups           []tls.CurveID
	wrapOption       string // tls-auth, tls-crypt or tls-crypt-v2
	wrapKey          string
	wrapDirection    string // the argument of tls-auth: "", "0" or "1"
	keyDirection     string // key-direction: "", "0", "1" or "bidirectional"
	authDigest       string // auth: "" for the default, SHA1
	dataCiphers      []string
	haveDataCiphers  bool
	cipher           string
	pingRestart      time.Duration
	pingExit         time.Duration
	havePingRestart  bool
	havePingExit     bool
}

func newBuilder(fsys fs.FS, dir string) *builder {
	return &builder{fsys: fsys, dir: dir, handlers: handlers(), defPort: "1194", defProto: "udp", connectTimeout: DefaultConnectTimeout}
}

// handlers are the options that the profile parser supports.
func handlers() map[string]spec {
	return map[string]spec{
		"client": {0, 0, (*builder).hNothing}, "tls-client": {0, 0, (*builder).hNothing}, "pull": {0, 0, (*builder).hNothing},
		"push-peer-info": {0, 0, (*builder).hNothing},
		"dev":            {1, 1, (*builder).hDev}, "dev-type": {1, 1, (*builder).hDev},
		"remote": {1, 3, (*builder).hRemote}, "proto": {1, 1, (*builder).hProto},
		"port": {1, 1, (*builder).hPort}, "rport": {1, 1, (*builder).hPort},
		"remote-random": {0, 0, (*builder).hRemoteRandom}, "connect-timeout": {1, 1, (*builder).hConnectTimeout},
		"server-poll-timeout": {1, 1, (*builder).hConnectTimeout},
		"ca":                  {1, 1, (*builder).hCA}, "cert": {1, 1, (*builder).hCert}, "key": {1, 1, (*builder).hKey},
		"tls-auth": {1, 2, (*builder).hWrap}, "tls-crypt": {1, 1, (*builder).hWrap}, "tls-crypt-v2": {1, 1, (*builder).hWrap},
		"key-direction": {1, 1, (*builder).hKeyDirection}, "auth": {1, 1, (*builder).hAuth},
		"auth-user-pass": {0, 1, (*builder).hAuthUserPass}, "auth-nocache": {0, 0, (*builder).hAuthNoCache},
		"data-ciphers": {1, 1, (*builder).hDataCiphers}, "ncp-ciphers": {1, 1, (*builder).hDataCiphers}, "cipher": {1, 1, (*builder).hCipher},
		"remote-cert-tls": {1, 1, (*builder).hRemoteCertTLS}, "verify-x509-name": {1, 2, (*builder).hVerifyName},
		"peer-fingerprint": {1, 64, (*builder).hFingerprint}, "tls-version-min": {1, 2, (*builder).hTLSVersionMin},
		"tls-groups": {1, 1, (*builder).hTLSGroups},
		"reneg-sec":  {1, 2, (*builder).hRenegSec}, "hand-window": {1, 1, (*builder).hHandWindow}, "tls-timeout": {1, 1, (*builder).hTLSTimeout},
		"ping": {1, 1, (*builder).hPing}, "ping-restart": {1, 1, (*builder).hPingRestart}, "ping-exit": {1, 1, (*builder).hPingExit},
		"keepalive": {2, 2, (*builder).hKeepalive}, "tun-mtu": {1, 1, (*builder).hTunMTU},
		"explicit-exit-notify": {0, 1, (*builder).hExplicitExitNotify},
		"setenv":               {1, 64, (*builder).hSetenv}, "ignore-unknown-option": {1, 64, (*builder).hNothing},
		"pull-filter": {2, 2, (*builder).hPullFilter}, "route-nopull": {0, 0, (*builder).hRouteNoPull},
	}
}

// inlineOptions are the options that can be an inline file (<name> ... </name>).
var inlineOptions = []string{"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "auth-user-pass", "peer-fingerprint"}

// inConnection are the options that a <connection> block may have besides the ignored
// ones.
var inConnection = []string{"remote", "proto", "port", "rport"}

// ignoredOptions are accepted and have no effect: they mean nothing to a library
// (the tunnel device, the process, the log, the local routes) or only widen what
// the library does anyway. A profile lists the ones it had in Profile.Ignored.
var ignoredOptions = map[string]bool{
	"nobind": true, "persist-tun": true, "persist-key": true, "verb": true, "mute": true,
	"mute-replay-warnings": true, "resolv-retry": true, "user": true, "group": true, "daemon": true,
	"log": true, "log-append": true, "syslog": true, "script-security": true, "mssfix": true,
	"sndbuf": true, "rcvbuf": true, "socket-flags": true, "fast-io": true, "float": true,
	"connect-retry": true, "connect-retry-max": true, "key-method": true,
	"ifconfig-noexec": true, "route-noexec": true, "route-delay": true, "route-method": true,
	"ip-win32": true, "register-dns": true, "dhcp-renew": true, "dhcp-release": true, "tap-sleep": true,
	"windows-driver": true, "disable-dco": true, "allow-compression": true, "tls-cipher": true,
	"tls-ciphersuites": true, "tls-version-max": true, "reneg-bytes": true, "reneg-pkts": true,
	"replay-window": true, "auth-retry": true, "redirect-gateway": true, "route": true, "route-ipv6": true,
	"dhcp-option": true, "block-outside-dns": true, "remote-random-hostname": true, "link-mtu": true,
	"tun-mtu-extra": true, "ping-timer-rem": true, "setenv-safe": true, "echo": true, "nice": true,
	"local": true, "lport": true, "dev-node": true, "ecdh-curve": true, "dh": true, "topology": true,
	"inactive": true, "machine-readable-output": true, "mlock": true, "ifconfig": true, "txqueuelen": true,
	"show-net-up": true, "tcp-queue-limit": true, "opt-verify": true, "compat-mode": true, "tls-exit": true,
	// Options that OpenVPN 2.7 takes and that change nothing here: they are for the
	// host's routes and device (block-ipv6, redirect-private, route-metric,
	// route-gateway, tun-ipv6, mtu-disc), for the process (status), for the check of
	// the options of the peer (disable-occ), for the profile of OpenSSL's certificate
	// checks (tls-cert-profile: crypto/tls has its own rules), or for a server that
	// does not negotiate the cipher, which this library does not talk to
	// (data-ciphers-fallback: such a server fails the negotiation with its own error).
	"tun-ipv6": true, "block-ipv6": true, "disable-occ": true, "redirect-private": true,
	"route-metric": true, "route-gateway": true, "mtu-disc": true, "status": true, "status-version": true,
	"tls-cert-profile": true, "data-ciphers-fallback": true,
}

// refusedOptions are options that this version cannot honor and that would be unsafe
// or wrong to skip: the profile is refused, with the option, the line and the reason.
var refusedOptions = map[string]string{
	"secret":                     "the static key mode is not supported",
	"fragment":                   "fragmentation is not supported",
	"compress":                   "compression is not supported",
	"comp-lzo":                   "compression is not supported",
	"mode":                       "only the client mode is supported",
	"tls-server":                 "this is a client",
	"http-proxy":                 "proxies are not supported: use a Dialer with a DialContext",
	"socks-proxy":                "proxies are not supported: use a Dialer with a DialContext",
	"http-proxy-user-pass":       "proxies are not supported: use a Dialer with a DialContext",
	"http-proxy-option":          "proxies are not supported: use a Dialer with a DialContext",
	"http-proxy-retry":           "proxies are not supported: use a Dialer with a DialContext",
	"socks-proxy-retry":          "proxies are not supported: use a Dialer with a DialContext",
	"pkcs12":                     "a PKCS#12 file is not supported: give the certificate and the key",
	"cryptoapicert":              "the Windows certificate store is not supported",
	"askpass":                    "an encrypted key is not supported: decrypt it first",
	"up":                         "scripts are not run by a library",
	"down":                       "scripts are not run by a library",
	"route-up":                   "scripts are not run by a library",
	"route-pre-down":             "scripts are not run by a library",
	"up-restart":                 "scripts are not run by a library",
	"down-pre":                   "scripts are not run by a library",
	"tls-verify":                 "a verification script is not run by a library",
	"plugin":                     "plugins are not loaded by a library",
	"management":                 "there is no management interface",
	"management-query-passwords": "there is no management interface",
	"management-hold":            "there is no management interface",
	"management-client-auth":     "there is no management interface",
	"crl-verify":                 "a certificate revocation list is not checked",
	"verify-hash":                "use peer-fingerprint",
	"remote-cert-ku":             "the key usage of the server's certificate is not checked",
	"remote-cert-eku":            "the extended key usage of the server's certificate is not checked",
	"ns-cert-type":               "use remote-cert-tls server",
	"x509-username-field":        "the field that names the server is the common name",
	"ncp-disable":                "the negotiation of the cipher cannot be turned off",
	"capath":                     "a directory of authorities is not supported: give the ca",
	"extra-certs":                "extra certificates are not supported: put the chain in the cert",
	"auth-gen-token-secret":      "this is a server option",
	"tls-export-cert":            "this is a server option",
}

// apply applies one option of the profile (or of a <connection> block when inConn).
func (b *builder) apply(l line, inConn bool) error {
	if reason, ok := refusedOptions[l.name]; ok {
		return errors.New(TagUnsupportedOption, "the profile has an option that is not supported", "option", l.name, "line", l.lineNo, "reason", reason)
	}
	if ignoredOptions[l.name] {
		b.ignore(l.name)
		return nil
	}
	if inConn && !slices.Contains(inConnection, l.name) {
		return errors.New(TagUnsupportedOption, "an option that a <connection> block cannot have", "option", l.name, "line", l.lineNo, "reason", "only remote, proto and port are read in a connection block")
	}
	if l.isBlk && l.name == "connection" {
		return b.connection(l)
	}
	sp, ok := b.handlers[l.name]
	if !ok {
		if b.forwardCompatible || slices.Contains(b.ignoreUnknown, l.name) {
			b.ignore(l.name)
			return nil
		}
		return errors.New(TagUnsupportedOption, "the profile has an option that is not known", "option", l.name, "line", l.lineNo, "reason", "the option is not known")
	}
	if l.isBlk {
		if !slices.Contains(inlineOptions, l.name) {
			return errors.New(TagBadOption, "an inline block for an option that cannot be an inline file", "option", l.name, "line", l.lineNo, "reason", "the option cannot be inline")
		}
	} else if len(l.args) < sp.min || len(l.args) > sp.max {
		return errors.New(TagBadOption, "an option has the wrong number of arguments", "option", l.name, "line", l.lineNo, "reason", "it takes "+argRange(sp.min, sp.max)+" arguments")
	}
	return sp.fn(b, l)
}

func argRange(lo, hi int) string {
	if lo == hi {
		return strconv.Itoa(lo)
	}
	return strconv.Itoa(lo) + " to " + strconv.Itoa(hi)
}

// ignore notes an option that is accepted and has no effect, once.
func (b *builder) ignore(name string) {
	if !slices.Contains(b.ignored, name) {
		b.ignored = append(b.ignored, name)
	}
}

// connection reads a <connection> block: the options of one remote.
func (b *builder) connection(l line) error {
	sub, err := lex(strings.NewReader(l.inline))
	if err != nil {
		// The line numbers of the block count from its opening tag.
		return err
	}
	before := len(b.remotes)
	b.conn = &rawRemote{}
	defer func() { b.conn = nil }()
	for _, s := range sub {
		s.lineNo += l.lineNo
		if s.isBlk {
			return errors.New(TagUnsupportedOption, "an inline block inside a <connection> block", "option", s.name, "line", s.lineNo, "reason", "only remote, proto and port are read in a connection block")
		}
		if err := b.apply(s, true); err != nil {
			return err
		}
	}
	if len(b.remotes) == before {
		return errors.New(TagBadOption, "a <connection> block with no remote", "option", "connection", "line", l.lineNo, "reason", "the block has no remote")
	}
	for i := before; i < len(b.remotes); i++ {
		b.remotes[i].connPort, b.remotes[i].connProto = b.conn.connPort, b.conn.connProto
	}
	return nil
}

// text is the text of a file option: the inline text, or the file that the argument
// names.
func (b *builder) text(l line) (string, error) {
	if l.isBlk {
		return l.inline, nil
	}
	name := l.args[0]
	if b.fsys == nil {
		return "", errors.New(TagFileUnavailable, "the option names a file, and Parse has no files: use ParseFS or put the file inline", "option", l.name, "line", l.lineNo)
	}
	full := path.Join(b.dir, name)
	if path.IsAbs(name) || strings.Contains(name, `\`) || !fs.ValidPath(full) || strings.HasPrefix(path.Clean(name), "..") {
		return "", errors.New(TagFileUnavailable, "the file is not inside the directory of the profile", "option", l.name, "line", l.lineNo)
	}
	data, err := fs.ReadFile(b.fsys, full)
	if err != nil {
		return "", errors.NewErr(TagFileUnavailable, err).SetMetadata("option", l.name, "line", l.lineNo)
	}
	if len(data) > maxSize {
		return "", errors.New(TagFileUnavailable, "the file is too large", "option", l.name, "line", l.lineNo, "max", maxSize)
	}
	return string(data), nil
}

func (b *builder) hNothing(line) error { return nil }

// hDev takes dev tun and refuses dev tap; the device means nothing to a library.
func (b *builder) hDev(l line) error {
	if strings.HasPrefix(l.args[0], "tap") {
		return errors.New(TagUnsupportedOption, "the profile has an option that is not supported", "option", l.name, "line", l.lineNo, "reason", "only the tun mode is supported")
	}
	b.ignore(l.name)
	return nil
}

// seconds reads a count of seconds from 0 up to 2^31-1.
func seconds(s string) (time.Duration, bool) {
	n, err := strconv.ParseUint(s, 10, 31)
	if err != nil {
		return 0, false
	}
	return time.Duration(n&0x7fffffff) * time.Second, true // n is below 2^31
}

// networkFor is the network name of a proto, or "" when the proto is not one that a
// client can use.
func networkFor(proto string) string {
	switch proto {
	case "udp", "udp4", "udp6", "tcp4", "tcp6", "tcp":
		return proto
	case "tcp-client":
		return "tcp"
	case "tcp4-client":
		return "tcp4"
	case "tcp6-client":
		return "tcp6"
	}
	return ""
}

// validPort reports whether s is a port number.
func validPort(s string) bool {
	n, err := strconv.ParseUint(s, 10, 16)
	return err == nil && n > 0
}

func (b *builder) hRemote(l line) error {
	r := rawRemote{host: l.args[0]}
	if len(l.args) > 1 {
		r.port = l.args[1]
		if !validPort(r.port) {
			return errors.New(TagBadOption, "the port of a remote is not a number from 1 to 65535", "option", l.name, "line", l.lineNo, "reason", "bad port")
		}
	}
	if len(l.args) > 2 {
		r.proto = l.args[2]
		if networkFor(r.proto) == "" {
			return errors.New(TagBadOption, "the protocol of a remote is not one that a client uses", "option", l.name, "line", l.lineNo, "reason", "bad protocol")
		}
	}
	if r.host == "" {
		return errors.New(TagBadOption, "a remote has an empty host", "option", l.name, "line", l.lineNo, "reason", "empty host")
	}
	b.remotes = append(b.remotes, r)
	return nil
}

func (b *builder) hProto(l line) error {
	if networkFor(l.args[0]) == "" {
		return errors.New(TagBadOption, "the protocol is not one that a client uses (udp, udp4, udp6, tcp, tcp4, tcp6, tcp-client, tcp4-client, tcp6-client)", "option", l.name, "line", l.lineNo, "reason", "bad protocol")
	}
	if b.conn != nil {
		b.conn.connProto = l.args[0]
	} else {
		b.defProto = l.args[0]
	}
	return nil
}

func (b *builder) hPort(l line) error {
	if !validPort(l.args[0]) {
		return errors.New(TagBadOption, "the port is not a number from 1 to 65535", "option", l.name, "line", l.lineNo, "reason", "bad port")
	}
	if b.conn != nil {
		b.conn.connPort = l.args[0]
	} else {
		b.defPort = l.args[0]
	}
	return nil
}

func (b *builder) hRemoteRandom(line) error { b.remoteRandom = true; return nil }

func (b *builder) hConnectTimeout(l line) error {
	d, ok := seconds(l.args[0])
	if !ok || d == 0 {
		return errors.New(TagBadOption, "the timeout is not a number of seconds above 0", "option", l.name, "line", l.lineNo, "reason", "bad number")
	}
	b.connectTimeout = d
	return nil
}

func (b *builder) hCA(l line) error {
	text, err := b.text(l)
	if err != nil {
		return err
	}
	b.ca += text + "\n"
	b.haveCA = true
	return nil
}

func (b *builder) hCert(l line) error {
	text, err := b.text(l)
	if err != nil {
		return err
	}
	b.cert = text
	return nil
}

func (b *builder) hKey(l line) error {
	text, err := b.text(l)
	if err != nil {
		return err
	}
	b.key = text
	return nil
}

// hWrap takes tls-auth, tls-crypt and tls-crypt-v2: one of them.
func (b *builder) hWrap(l line) error {
	if b.wrapOption != "" {
		return errors.New(TagBadOption, "the profile protects the control channel in two ways: it can have one of tls-auth, tls-crypt and tls-crypt-v2", "option", l.name, "line", l.lineNo, "reason", "a second protection")
	}
	if l.name == "tls-auth" && !l.isBlk && len(l.args) == 2 {
		if l.args[1] != "0" && l.args[1] != "1" {
			return errors.New(TagBadOption, "the direction of tls-auth is 0 or 1", "option", l.name, "line", l.lineNo, "reason", "bad direction")
		}
		b.wrapDirection = l.args[1]
	}
	text, err := b.text(l)
	if err != nil {
		return err
	}
	b.wrapOption, b.wrapKey = l.name, text
	return nil
}

func (b *builder) hKeyDirection(l line) error {
	switch l.args[0] {
	case "0", "1", "bidirectional":
		b.keyDirection = l.args[0]
		return nil
	}
	return errors.New(TagBadOption, "the key direction is 0, 1 or bidirectional", "option", l.name, "line", l.lineNo, "reason", "bad direction")
}

func (b *builder) hAuth(l line) error {
	b.authDigest = strings.ToUpper(l.args[0])
	return nil
}

// hAuthUserPass reads the credentials file, or notes that the caller has to give them.
func (b *builder) hAuthUserPass(l line) error {
	if !l.isBlk && len(l.args) == 0 {
		b.needsCreds = true
		return nil
	}
	text, err := b.text(l)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	user := strings.TrimSuffix(lines[0], "\r")
	if len(lines) < 2 || user == "" {
		return errors.New(TagBadFile, "the credentials have the user name on the first line and the password on the second", "option", l.name, "reason", "a file with no user name or no password")
	}
	pass := strings.TrimSuffix(lines[1], "\r")
	b.cfg.Credentials = func(context.Context) (openvpn.Credentials, error) {
		return openvpn.Credentials{Username: user, Password: pass}, nil
	}
	b.needsCreds = false
	return nil
}

func (b *builder) hAuthNoCache(line) error { b.cfg.AuthNoCache = true; return nil }

// aeadCiphers are the data ciphers of the library, which are all AEAD.
var aeadCiphers = []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"}

// hDataCiphers takes the list of data-ciphers. "DEFAULT" stands for OpenVPN's default
// list, and a name that starts with "?" is one that OpenVPN leaves out when its
// library does not have it: both are in profiles that OpenVPN 2.7 reads.
//
// OpenVPN: ssl_ncp.c mutate_ncp_cipher_list.
func (b *builder) hDataCiphers(l line) error {
	b.haveDataCiphers = true
	var names []string
	for _, name := range splitList(l.args[0]) {
		name = strings.ToUpper(strings.TrimPrefix(name, "?"))
		if name == "DEFAULT" {
			names = append(names, defaultDataCiphers...)
			continue
		}
		names = append(names, name)
	}
	for _, name := range names {
		if slices.Contains(aeadCiphers, name) {
			if !slices.Contains(b.dataCiphers, name) {
				b.dataCiphers = append(b.dataCiphers, name)
			}
		} else {
			b.ignore("data-ciphers: " + name)
		}
	}
	return nil
}

func (b *builder) hCipher(l line) error {
	b.cipher = strings.ToUpper(l.args[0])
	return nil
}

func (b *builder) hRemoteCertTLS(l line) error {
	switch l.args[0] {
	case "server":
		b.remoteCertServer = true
		return nil
	case "client":
		return errors.New(TagUnsupportedOption, "the profile has an option that is not supported", "option", l.name, "line", l.lineNo, "reason", "only remote-cert-tls server is supported")
	}
	return errors.New(TagBadOption, "remote-cert-tls takes server or client", "option", l.name, "line", l.lineNo, "reason", "bad argument")
}

func (b *builder) hVerifyName(l line) error {
	b.verifyName = l.args[0]
	b.verifyMatch = openvpn.MatchSubject
	if len(l.args) == 2 {
		switch l.args[1] {
		case "subject":
		case "name":
			b.verifyMatch = openvpn.MatchCommonName
		case "name-prefix":
			b.verifyMatch = openvpn.MatchCommonNamePrefix
		default:
			return errors.New(TagBadOption, "the type of verify-x509-name is subject, name or name-prefix", "option", l.name, "line", l.lineNo, "reason", "bad type")
		}
	}
	if b.verifyName == "" {
		return errors.New(TagBadOption, "verify-x509-name has an empty name", "option", l.name, "line", l.lineNo, "reason", "empty name")
	}
	return nil
}

// hFingerprint reads SHA-256 fingerprints, from the arguments or from an inline block,
// where each line has one.
func (b *builder) hFingerprint(l line) error {
	words := l.args
	if l.isBlk {
		words = strings.Fields(l.inline)
	}
	if len(words) == 0 {
		return errors.New(TagBadOption, "no fingerprint", "option", l.name, "line", l.lineNo, "reason", "no fingerprint")
	}
	for _, w := range words {
		raw, err := hex.DecodeString(strings.ReplaceAll(w, ":", ""))
		if err != nil || len(raw) != sha256.Size || (len(w) != 2*sha256.Size && len(w) != 3*sha256.Size-1) {
			return errors.New(TagBadOption, "a fingerprint is 32 bytes in hexadecimal, with or without a colon between the bytes", "option", l.name, "line", l.lineNo, "reason", "bad fingerprint")
		}
		b.fingerprints = append(b.fingerprints, [sha256.Size]byte(raw))
	}
	return nil
}

func (b *builder) hTLSVersionMin(l line) error {
	if len(l.args) == 2 && l.args[1] != "or-highest" {
		return errors.New(TagBadOption, "the second argument of tls-version-min is or-highest", "option", l.name, "line", l.lineNo, "reason", "bad argument")
	}
	switch l.args[0] {
	case "1.2":
		b.minVersion = tls.VersionTLS12
	case "1.3":
		b.minVersion = tls.VersionTLS13
	case "1.0", "1.1":
		// A lowest version, not a required one: the library starts at TLS 1.2, which
		// is above it, as OpenVPN's build with mbed TLS does.
		b.ignore("tls-version-min " + l.args[0] + ": the lowest version is 1.2")
	default:
		return errors.New(TagBadOption, "the version is 1.2 or 1.3", "option", l.name, "line", l.lineNo, "reason", "bad version")
	}
	return nil
}

// groupIDs are the names of the key exchange groups, as OpenSSL knows them, that
// crypto/tls has.
var groupIDs = map[string]tls.CurveID{
	"secp256r1": tls.CurveP256, "prime256v1": tls.CurveP256, "P-256": tls.CurveP256,
	"secp384r1": tls.CurveP384, "P-384": tls.CurveP384,
	"secp521r1": tls.CurveP521, "P-521": tls.CurveP521,
	"X25519": tls.X25519, "X25519MLKEM768": tls.X25519MLKEM768,
	"SecP256r1MLKEM768": tls.SecP256r1MLKEM768, "SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,
}

func (b *builder) hTLSGroups(l line) error {
	var ids []tls.CurveID
	for _, name := range splitList(l.args[0]) {
		id, ok := groupIDs[name]
		if !ok {
			return errors.New(TagUnsupportedOption, "the profile has an option that is not supported", "option", l.name, "line", l.lineNo, "reason", "a group that crypto/tls does not have: "+name)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return errors.New(TagBadOption, "no group", "option", l.name, "line", l.lineNo, "reason", "no group")
	}
	b.groups = ids
	return nil
}

// hRenegSec takes reneg-sec max [min]. OpenVPN's client takes a random time between
// min and max when there is a min; this one takes max.
func (b *builder) hRenegSec(l line) error {
	d, ok := seconds(l.args[0])
	if ok && len(l.args) == 2 {
		_, ok = seconds(l.args[1])
		b.ignore("reneg-sec: the second number")
	}
	if !ok {
		return errors.New(TagBadOption, "the time is not a number of seconds", "option", l.name, "line", l.lineNo, "reason", "bad number")
	}
	if d == 0 {
		d = -1 // 0 turns it off
	}
	b.cfg.RenegotiateAfter = d
	return nil
}

func (b *builder) hHandWindow(l line) error {
	d, ok := seconds(l.args[0])
	if !ok || d == 0 {
		return errors.New(TagBadOption, "the time is not a number of seconds above 0", "option", l.name, "line", l.lineNo, "reason", "bad number")
	}
	b.cfg.HandshakeTimeout = d
	return nil
}

func (b *builder) hTLSTimeout(l line) error {
	d, ok := seconds(l.args[0])
	if !ok || d == 0 {
		return errors.New(TagBadOption, "the time is not a number of seconds above 0", "option", l.name, "line", l.lineNo, "reason", "bad number")
	}
	b.cfg.RetransmitTimeout = d
	return nil
}

func (b *builder) hPing(l line) error {
	d, ok := seconds(l.args[0])
	if !ok {
		return errors.New(TagBadOption, "the time is not a number of seconds", "option", l.name, "line", l.lineNo, "reason", "bad number")
	}
	b.cfg.PingInterval = d
	return nil
}

func (b *builder) hPingRestart(l line) error {
	d, ok := seconds(l.args[0])
	if !ok {
		return errors.New(TagBadOption, "the time is not a number of seconds", "option", l.name, "line", l.lineNo, "reason", "bad number")
	}
	b.pingRestart, b.havePingRestart = d, true
	return nil
}

// hPingExit is a ping-restart for a library: a session that hears nothing ends, and
// what comes next (dialing again, or not) is the program's.
func (b *builder) hPingExit(l line) error {
	d, ok := seconds(l.args[0])
	if !ok {
		return errors.New(TagBadOption, "the time is not a number of seconds", "option", l.name, "line", l.lineNo, "reason", "bad number")
	}
	b.pingExit, b.havePingExit = d, true
	return nil
}

func (b *builder) hKeepalive(l line) error {
	interval, ok1 := seconds(l.args[0])
	timeout, ok2 := seconds(l.args[1])
	if !ok1 || !ok2 {
		return errors.New(TagBadOption, "keepalive takes two numbers of seconds", "option", l.name, "line", l.lineNo, "reason", "bad number")
	}
	b.cfg.PingInterval = interval
	b.pingRestart, b.havePingRestart = timeout, true
	return nil
}

func (b *builder) hTunMTU(l line) error {
	n, err := strconv.ParseUint(l.args[0], 10, 17)
	if err != nil {
		return errors.New(TagBadOption, "the MTU is not a number", "option", l.name, "line", l.lineNo, "reason", "bad number")
	}
	b.cfg.MTU = int(n)
	return nil
}

// hExplicitExitNotify takes the option: the library always tells the server when it
// closes, once.
func (b *builder) hExplicitExitNotify(l line) error {
	if len(l.args) == 1 {
		n, err := strconv.ParseUint(l.args[0], 10, 16)
		if err != nil {
			return errors.New(TagBadOption, "the number of tries is not a number", "option", l.name, "line", l.lineNo, "reason", "bad number")
		}
		switch {
		case n == 0:
			b.ignore("explicit-exit-notify 0: Close tells the server all the same")
		case n > 1:
			b.ignore("explicit-exit-notify: tries beyond the first")
		}
	}
	return nil
}

// hSetenv takes setenv UV_name value (peer info), setenv opt option... (an option that
// is applied if this parser knows it and left out if not), and any other setenv, which
// is for the scripts that a library does not run.
func (b *builder) hSetenv(l line) error {
	name := l.args[0]
	switch {
	case strings.HasPrefix(name, "UV_"):
		if b.cfg.PeerInfo == nil {
			b.cfg.PeerInfo = map[string]string{}
		}
		value := ""
		if len(l.args) > 1 {
			value = l.args[1]
		}
		b.cfg.PeerInfo[name] = value
		return nil
	case name == "FORWARD_COMPATIBLE" && len(l.args) > 1 && l.args[1] == "1":
		b.forwardCompatible = true
		return nil
	case name == "opt" && len(l.args) > 1:
		inner := line{name: l.args[1], args: l.args[2:], lineNo: l.lineNo}
		if _, known := b.handlers[inner.name]; !known && refusedOptions[inner.name] == "" && !ignoredOptions[inner.name] {
			b.ignore(inner.name)
			return nil
		}
		return b.apply(inner, false)
	}
	b.ignore("setenv")
	return nil
}

func (b *builder) hPullFilter(l line) error {
	var action openvpn.PullAction
	switch l.args[0] {
	case "accept":
		action = openvpn.PullAccept
	case "ignore":
		action = openvpn.PullIgnore
	case "reject":
		action = openvpn.PullReject
	default:
		return errors.New(TagBadOption, "the action of pull-filter is accept, ignore or reject", "option", l.name, "line", l.lineNo, "reason", "bad action")
	}
	b.cfg.PullFilters = append(b.cfg.PullFilters, openvpn.PullFilter{Action: action, Prefix: l.args[1]})
	return nil
}

func (b *builder) hRouteNoPull(line) error { b.cfg.RouteNoPull = true; return nil }

// digestFor is the hash of the auth option, for tls-auth.
func digestFor(name string) (crypto.Hash, bool) {
	switch name {
	case "", "SHA1":
		return crypto.SHA1, true
	case "SHA256":
		return crypto.SHA256, true
	case "SHA384":
		return crypto.SHA384, true
	case "SHA512":
		return crypto.SHA512, true
	}
	return 0, false
}

// finish makes the Profile from what the options said.
func (b *builder) finish() (*Profile, error) {
	p := &Profile{RemoteRandom: b.remoteRandom, ConnectTimeout: b.connectTimeout, NeedsCredentials: b.needsCreds, Ignored: b.ignored}
	for _, r := range b.remotes {
		proto := firstOf(r.proto, r.connProto, b.defProto)
		port := firstOf(r.port, r.connPort, b.defPort)
		p.Remotes = append(p.Remotes, Remote{Network: networkFor(proto), Address: net.JoinHostPort(r.host, port)})
	}

	if b.havePingRestart && b.havePingExit {
		return nil, errors.New(TagBadOption, "the profile has both ping-restart and ping-exit: it can have one", "option", "ping-exit", "reason", "both ping-restart and ping-exit")
	}
	switch {
	case b.havePingExit:
		b.cfg.PingTimeout = b.pingExit
	case b.havePingRestart:
		b.cfg.PingTimeout = b.pingRestart
	}

	roots, err := b.rootPool()
	if err != nil {
		return nil, err
	}
	if roots == nil && len(b.fingerprints) == 0 {
		return nil, errors.New(TagMissingOption, "the profile has no ca and no peer-fingerprint: the server cannot be verified", "option", "ca")
	}
	var certs []tls.Certificate
	switch {
	case b.cert != "" && b.key == "":
		return nil, errors.New(TagMissingOption, "the profile has a cert and no key", "option", "key")
	case b.cert == "" && b.key != "":
		return nil, errors.New(TagMissingOption, "the profile has a key and no cert", "option", "cert")
	case b.cert != "":
		if strings.Contains(b.key, "ENCRYPTED") {
			return nil, errors.New(TagBadFile, "the key is encrypted: decrypt it first", "option", "key", "reason", "an encrypted key")
		}
		pair, err := tls.X509KeyPair([]byte(b.cert), []byte(b.key))
		if err != nil {
			return nil, errors.NewErr(TagBadFile, err).SetMetadata("option", "cert and key", "reason", "the certificate and the key do not make a pair")
		}
		certs = []tls.Certificate{pair}
	}
	b.cfg.TLS = openvpn.NewTLSConfig(openvpn.TLSOptions{
		RootCAs: roots, Certificates: certs, RemoteCertTLSServer: b.remoteCertServer, MinVersion: b.minVersion,
		VerifyName: b.verifyName, VerifyNameMatch: b.verifyMatch, PeerFingerprints: b.fingerprints, CurvePreferences: b.groups,
	})

	if err := b.makeWrap(); err != nil {
		return nil, err
	}
	if err := b.makeCiphers(); err != nil {
		return nil, err
	}
	if err := b.cfg.Validate(); err != nil {
		return nil, err
	}
	p.Config = &b.cfg
	p.Ignored = b.ignored // what the making of the Config left out is in it too
	return p, nil
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// rootPool makes the pool of the authorities from the ca options, or nil when there are none.
func (b *builder) rootPool() (*x509.CertPool, error) {
	if !b.haveCA {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b.ca)) {
		return nil, errors.New(TagBadFile, "the ca has no certificate in PEM", "option", "ca", "reason", "no certificate")
	}
	return pool, nil
}

// makeWrap makes the protection of the control channel from tls-auth, tls-crypt or
// tls-crypt-v2.
func (b *builder) makeWrap() error {
	switch b.wrapOption {
	case "":
		return nil
	case "tls-crypt":
		w, err := openvpn.NewTLSCrypt([]byte(b.wrapKey))
		if err != nil {
			return errors.NewErr(TagBadFile, err).SetMetadata("option", b.wrapOption, "reason", "the key file is not a key")
		}
		b.cfg.ControlWrap = w
	case "tls-crypt-v2":
		w, err := openvpn.NewTLSCryptV2([]byte(b.wrapKey))
		if err != nil {
			return errors.NewErr(TagBadFile, err).SetMetadata("option", b.wrapOption, "reason", "the key file is not a client key")
		}
		b.cfg.ControlWrap = w
	case "tls-auth":
		digest, ok := digestFor(b.authDigest)
		if !ok {
			return errors.New(TagUnsupportedOption, "the profile has an option that is not supported", "option", "auth", "reason", "the digest of tls-auth is SHA1, SHA256, SHA384 or SHA512")
		}
		direction := openvpn.KeyDirectionNone
		dir := firstOf(b.wrapDirection, b.keyDirection)
		switch dir {
		case "0":
			direction = openvpn.KeyDirection0
		case "1":
			direction = openvpn.KeyDirection1
		}
		w, err := openvpn.NewTLSAuth([]byte(b.wrapKey), direction, digest)
		if err != nil {
			return errors.NewErr(TagBadFile, err).SetMetadata("option", b.wrapOption, "reason", "the key file is not a key")
		}
		b.cfg.ControlWrap = w
	}
	return nil
}

// makeCiphers makes the offer of data ciphers from data-ciphers and cipher.
func (b *builder) makeCiphers() error {
	switch {
	case b.haveDataCiphers:
		if len(b.dataCiphers) == 0 {
			return errors.New(TagBadOption, "none of the data ciphers of the profile is one that the library has", "option", "data-ciphers", "reason", "no cipher that this library has")
		}
		b.cfg.DataCiphers = b.dataCiphers
		if slices.Contains(aeadCiphers, b.cipher) && !slices.Contains(b.cfg.DataCiphers, b.cipher) {
			b.cfg.DataCiphers = append(b.cfg.DataCiphers, b.cipher) // the cipher is the last offer
		}
	case b.cipher != "":
		if !slices.Contains(aeadCiphers, b.cipher) {
			// OpenVPN: options.c options_postprocess_cipher ("OpenVPN ignores --cipher
			// for cipher negotiations"): the offer is the default one. Most profiles of
			// providers still have cipher AES-256-CBC, for clients that are older than
			// the negotiation; a server that has only that cipher fails the negotiation
			// with its own error.
			b.ignore("cipher " + b.cipher + ": not AEAD; the default ciphers are offered")
			return nil
		}
		offer := slices.Clone(defaultDataCiphers)
		if !slices.Contains(offer, b.cipher) {
			offer = append(offer, b.cipher)
		}
		b.cfg.DataCiphers = offer
	}
	return nil
}

// defaultDataCiphers is the offer of data ciphers when the profile names none, and
// what "DEFAULT" in data-ciphers stands for.
var defaultDataCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}

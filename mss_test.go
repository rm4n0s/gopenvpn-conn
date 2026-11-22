// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"

	"github.com/rm4n0s/gopenvpn-conn/internal/mss"
	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// TestConnClampsTheMSS: the TCP SYNs that the Conn writes, and the ones that it
// reads, announce no MSS larger than what fits in one packet of the link, as
// OpenVPN's mssfix makes them; ConnectionState says the MSS. The usual push reply
// of the test server gives DATA_V2 with 32-bit packet ids: 24 bytes for each packet,
// and 2 more for the length of a frame on a stream. The links of the tests have no
// IP address, which counts as IPv4 (SPEC §10).
func TestConnClampsTheMSS(t *testing.T) {
	tests := []struct {
		name           string
		mssFix         int
		mode           MSSFixMode
		mtu            int
		udpMSS, tcpMSS int // 0: the clamp is off
	}{
		// 1492 - (8 or 20) - 20 - (24 or 26) - 40.
		{name: "the default", udpMSS: 1400, tcpMSS: 1386},
		{name: "mssfix with no number but fixed", mode: MSSFixFixed, udpMSS: 1452, tcpMSS: 1452},
		{name: "mssfix 1300", mssFix: 1300, udpMSS: 1236, tcpMSS: 1234},
		{name: "mssfix 1300 mtu", mssFix: 1300, mode: MSSFixMTU, udpMSS: 1208, tcpMSS: 1194},
		{name: "mssfix 1300 fixed", mssFix: 1300, mode: MSSFixFixed, udpMSS: 1260, tcpMSS: 1260},
		{name: "tun-mtu 1400", mtu: 1400, udpMSS: 1360, tcpMSS: 1360},
		{name: "mssfix 0", mssFix: -1},
	}
	src, dst := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.1")
	src6, dst6 := netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::1")
	for _, tt := range tests {
		for _, k := range kinds {
			t.Run(tt.name+"/"+k.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					want := tt.udpMSS
					if k.stream {
						want = tt.tcpMSS
					}
					pki := servertest.NewPKI(t)
					link, srv := tlsPairWith(t, k, protections()[0], serverTLS(pki, pki.ServerCert), nil)
					conn := newClient(k, link, &Config{
						TLS:    NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}}),
						MSSFix: tt.mssFix, MSSFixMode: tt.mode, MTU: tt.mtu,
					})
					closeAtEnd(t, conn)
					if err := conn.HandshakeContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					if got := conn.ConnectionState().MSS; got != want {
						t.Errorf("ConnectionState().MSS = %d, want %d", got, want)
					}

					// Out: a SYN of 1460, and one of IPv6 (20 less), to the server.
					syn := vpntest.TCPSYN(src, dst, 1460, false)
					orig := bytes.Clone(syn)
					if _, err := conn.Write(syn); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(syn, orig) {
						t.Error("Write changed the caller's packet")
					}
					if _, err := conn.Write(vpntest.TCPSYN(src6, dst6, 1440, false)); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					got := srv.DataReceived()
					if len(got) != 2 {
						t.Fatalf("the server got %d packets", len(got))
					}
					checkMSS(t, "the SYN that the server got", got[0], cmpOr(want, 1460))
					checkMSS(t, "the IPv6 SYN that the server got", got[1], cmpOr(want-20, 1440))

					// In: a SYN-ACK of 1460 from the server.
					if _, err := srv.SendData(vpntest.TCPSYN(dst, src, 1460, true)); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 1500)
					n, err := conn.Read(buf)
					if err != nil {
						t.Fatal(err)
					}
					checkMSS(t, "the SYN-ACK that Read gave", buf[:n], cmpOr(want, 1460))
				})
			})
		}
	}
}

// TestConnLeavesASmallMSS: a SYN whose MSS is small enough goes out as it is.
func TestConnLeavesASmallMSS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, srv := tlsPairWith(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert), nil)
		conn := PacketClient(link, &Config{TLS: NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}})})
		closeAtEnd(t, conn)
		syn := vpntest.TCPSYN(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.1"), 1200, false)
		if _, err := conn.Write(syn); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if got := srv.DataReceived(); len(got) != 1 || !bytes.Equal(got[0], syn) {
			t.Errorf("the server got %x, want %x", got, syn)
		}
	})
}

// checkMSS fails the test unless p is a TCP SYN with an MSS of want and a TCP
// checksum that is right.
func checkMSS(t *testing.T, what string, p []byte, want int) {
	t.Helper()
	mss, sumOK, ok := vpntest.SYNMSS(p)
	switch {
	case !ok:
		t.Errorf("%s is not a SYN: %x", what, p)
	case int(mss) != want:
		t.Errorf("%s has an MSS of %d, want %d", what, mss, want)
	case !sumOK:
		t.Errorf("%s has a TCP checksum that is wrong", what)
	}
}

// cmpOr is the first of its arguments that is above zero.
func cmpOr(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

// addrConn is a net.Conn with a remote address and nothing else.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

// TestMSSSettings: the headers of the link that the default and "mtu" count are
// those of UDP or TCP over the IP version of the server's address.
//
// OpenVPN: socket_util.h datagram_overhead.
func TestMSSSettings(t *testing.T) {
	udp4 := addrConn{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1194}}
	udp6 := addrConn{remote: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1194}}
	tcp4 := addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}}
	tcp6 := addrConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}
	mapped := addrConn{remote: &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1194}}
	tests := []struct {
		name   string
		cfg    Config
		link   net.Conn
		stream bool
		want   mss.Settings
	}{
		{"default over UDP and IPv4", Config{}, udp4, false, mss.Settings{Size: 1492, Encap: 28}},
		{"default over UDP and IPv6", Config{}, udp6, false, mss.Settings{Size: 1492, Encap: 48}},
		{"default over TCP and IPv4", Config{}, tcp4, true, mss.Settings{Size: 1492, Encap: 40}},
		{"default over TCP and IPv6", Config{}, tcp6, true, mss.Settings{Size: 1492, Encap: 60}},
		{"default to an IPv4 address in IPv6 form", Config{}, mapped, false, mss.Settings{Size: 1492, Encap: 28}},
		{"default with tun-mtu 1400", Config{MTU: 1400}, udp4, false, mss.Settings{Size: 1400, Fixed: true}},
		{"mssfix 1450", Config{MSSFix: 1450}, udp6, false, mss.Settings{Size: 1450}},
		{"mssfix 1450 mtu", Config{MSSFix: 1450, MSSFixMode: MSSFixMTU}, udp6, false, mss.Settings{Size: 1450, Encap: 48}},
		{"mssfix 1450 fixed", Config{MSSFix: 1450, MSSFixMode: MSSFixFixed}, udp6, false, mss.Settings{Size: 1450, Fixed: true}},
		{"mssfix with tun-mtu 1400", Config{MSSFix: 1450, MTU: 1400}, udp4, false, mss.Settings{Size: 1450}},
		{"mssfix 0", Config{MSSFix: -1}, udp4, false, mss.Settings{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mssSettings(&tt.cfg, tt.link, tt.stream); got != tt.want {
				t.Errorf("mssSettings = %+v, want %+v", got, tt.want)
			}
		})
	}
}

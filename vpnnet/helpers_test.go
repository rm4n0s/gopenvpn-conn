// SPDX-License-Identifier: GPL-2.0-only

package vpnnet

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"

	"github.com/rm4n0s/errors"
	openvpn "github.com/rm4n0s/gopenvpn-conn"
	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// peer is one client of the test hub: a Conn, and the in-process server at the other
// end of its link, which hands every packet that the client sends to the other peer.
type peer struct {
	conn   *openvpn.Conn
	server *vpntest.Server
	// failed holds the first error of a packet that could not be sent on.
	failed atomic.Pointer[error]
}

// pushReply is a PUSH_REPLY for the address ip (and ip6 when it is not empty).
func pushReply(ip, ip6 string, mtu string, dns []string) string {
	reply := "PUSH_REPLY,topology subnet,ifconfig " + ip + " 255.255.255.0,"
	for _, server := range dns {
		reply += "dhcp-option " + server + ","
	}
	if ip6 != "" {
		reply += "ifconfig-ipv6 " + ip6 + " fd00:8::1,"
	}
	return reply + "route-gateway 10.8.0.1,cipher AES-256-GCM,ping 10,ping-restart 60,peer-id 0,tun-mtu " + mtu + ",key-derivation tls-ekm"
}

// hub makes two peers whose servers send each packet that they get to the other, so
// that what one writes, the other reads: two clients on one network. Each Conn has
// finished its handshake. Call it inside the bubble when the test has one.
func hub(t *testing.T, ip6 bool, mtu string) (a, b *peer) {
	t.Helper()
	return hubDNS(t, ip6, mtu, nil)
}

// hubDNS is hub with dhcp-option values ("DNS 10.8.0.3", "DNS6 fd00:8::3") that the
// server pushes to both clients.
func hubDNS(t *testing.T, ip6 bool, mtu string, dns []string) (a, b *peer) {
	t.Helper()
	pki := servertest.NewPKI(t)
	a, b = &peer{}, &peer{}
	addrs := [2][2]string{{"10.8.0.2", ""}, {"10.8.0.3", ""}}
	if ip6 {
		addrs = [2][2]string{{"10.8.0.2", "fd00:8::2/64"}, {"10.8.0.3", "fd00:8::3/64"}}
	}
	peers := [2]*peer{a, b}
	for i, p := range peers {
		other := peers[1-i]
		client, link := vpntest.NewDatagramPair(vpntest.LinkOptions{})
		p.server = vpntest.NewServer(t, link, vpntest.ServerOptions{
			TLS:          &tls.Config{Certificates: []tls.Certificate{pki.ServerCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.CAPool},
			PushMessages: []string{pushReply(addrs[i][0], addrs[i][1], mtu, dns)},
			OnData: func(packet []byte) {
				// The other peer's server may not be there yet: nothing flows before both are up.
				if other.server == nil {
					return
				}
				if _, err := other.server.SendData(packet); err != nil {
					p.failed.CompareAndSwap(nil, &err)
				}
			},
		})
		p.conn = openvpn.PacketClient(client, &openvpn.Config{
			TLS: openvpn.NewTLSConfig(openvpn.TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}}),
		})
	}
	for _, p := range peers {
		if err := p.conn.HandshakeContext(context.Background()); err != nil {
			t.Fatalf("HandshakeContext: %v", err)
		}
		t.Cleanup(func() {
			// A test that closed the Conn itself gets net.ErrClosed here.
			if err := p.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Close: %v", err)
			}
		})
	}
	return a, b
}

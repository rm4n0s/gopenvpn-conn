// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// TestConnReadAndWrite: the packets of a Conn go to the server and come back,
// over both links and with each protection, with no call of HandshakeContext.
func TestConnReadAndWrite(t *testing.T) {
	for _, k := range kinds {
		for _, p := range protections() {
			t.Run(k.name+"/"+p.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					pki := servertest.NewPKI(t)
					link, srv := tlsPairWith(t, k, p, serverTLS(pki, pki.ServerCert), func(o *vpntest.ServerOptions) { o.EchoData = true })
					cfg := &Config{
						TLS:         NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}}),
						ControlWrap: p.wrap(t),
					}
					var conn *Conn
					if k.stream {
						conn = Client(link, cfg)
					} else {
						conn = PacketClient(link, cfg)
					}
					closeAtEnd(t, conn)

					src, dst := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.1")
					request := vpntest.EchoRequest(src, dst, 1, 1, []byte("ping"))
					if n, err := conn.Write(request); err != nil || n != len(request) {
						t.Fatalf("Write = %d, %v", n, err)
					}
					buf := make([]byte, conn.ConnectionState().MTU)
					n, err := conn.Read(buf)
					if err != nil || !bytes.Equal(buf[:n], request) {
						t.Fatalf("Read = %x, %v, want the packet that was written", buf[:n], err)
					}
					if got := srv.DataReceived(); len(got) != 1 || !bytes.Equal(got[0], request) {
						t.Errorf("the server got %x", got)
					}
					st := conn.ConnectionState()
					if !st.HandshakeComplete || st.Cipher != "AES-256-GCM" || st.MTU != 1500 {
						t.Errorf("state = cipher %q, MTU %d, complete %v", st.Cipher, st.MTU, st.HandshakeComplete)
					}
				})
			})
		}
	}
}

func TestConnWriteRefusesAPacketLargerThanTheMTU(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, _ := tlsPairWith(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert), nil)
		conn := PacketClient(link, &Config{TLS: NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}})})
		closeAtEnd(t, conn)
		_, err := conn.Write(make([]byte, conn.ConnectionState().MTU+1))
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagPacketTooLarge {
			t.Fatalf("Write = %v, want %s", err, TagPacketTooLarge)
		}
	})
}

func TestConnReadAndWriteAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, _ := tlsPairWith(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert), nil)
		conn := PacketClient(link, &Config{TLS: NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}})})
		if err := conn.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 10)); err != net.ErrClosed {
			t.Errorf("Read after Close = %v", err)
		}
		if _, err := conn.Write([]byte{0x45}); err != net.ErrClosed {
			t.Errorf("Write after Close = %v", err)
		}
	})
}

// A server that pushes no key-derivation asks for the old way of making the keys.
func TestConnWithAServerThatDoesNotExportKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pki := servertest.NewPKI(t)
		link, _ := tlsPairWith(t, kinds[0], protections()[0], serverTLS(pki, pki.ServerCert), func(o *vpntest.ServerOptions) {
			o.PushMessages = []string{"PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.255.255.0,cipher AES-256-GCM,peer-id 0"}
		})
		conn := PacketClient(link, &Config{TLS: NewTLSConfig(TLSOptions{RootCAs: pki.CAPool, Certificates: []tls.Certificate{pki.ClientCert}})})
		closeAtEnd(t, conn)
		err := conn.HandshakeContext(t.Context())
		if appErr, ok := errors.FromError(err); !ok || appErr.Tag != TagKeyDerivationUnsupported {
			t.Fatalf("HandshakeContext = %v, want %s", err, TagKeyDerivationUnsupported)
		}
	})
}

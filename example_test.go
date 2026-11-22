// SPDX-License-Identifier: GPL-2.0-only

package openvpn_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
)

// ExampleDial connects to a server and reads the first IP packet that it sends.
// It is compiled but not run: it needs a server and the files of a profile.
func ExampleDial() {
	ca, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		log.Fatal("ca.crt has no certificate")
	}
	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		log.Fatal(err)
	}
	key, err := os.ReadFile("tls-crypt.key") // the profile's tls-crypt file
	if err != nil {
		log.Fatal(err)
	}
	wrap, err := openvpn.NewTLSCrypt(key)
	if err != nil {
		log.Fatal(err)
	}

	config := &openvpn.Config{
		// The server's certificate must lead to the CA, as in an OpenVPN profile; the
		// name in it is not compared with the address.
		TLS: openvpn.NewTLSConfig(openvpn.TLSOptions{
			RootCAs:             roots,
			Certificates:        []tls.Certificate{cert},
			RemoteCertTLSServer: true,
		}),
		ControlWrap: wrap,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := openvpn.Dial(ctx, "udp", "vpn.example.com:1194", config)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Print(err)
		}
	}()

	// The tunnel is up. What the server pushed is in the state of the connection.
	state := conn.ConnectionState()
	fmt.Println("addresses:", state.Addrs, "cipher:", state.Cipher, "MTU:", state.MTU)

	// A Conn is a net.Conn of IP packets: one Read returns one packet.
	packet := make([]byte, state.MTU)
	n, err := conn.Read(packet)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("an IP packet of %d bytes\n", n)
}

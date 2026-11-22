// SPDX-License-Identifier: GPL-2.0-only

package vpnnet_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/rm4n0s/gopenvpn-conn/ovpn"
	"github.com/rm4n0s/gopenvpn-conn/vpnnet"
)

// ExampleNet_DialContext gets a web page through the VPN with an http.Client: the
// name is looked up through the VPN, with the DNS servers that the server pushed, and
// the connection goes through it too. Nothing else on the machine uses the VPN, and no
// root is needed. It is compiled but not run: it needs a server.
func ExampleNet_DialContext() {
	profile, err := ovpn.ParseFS(os.DirFS("/etc/openvpn/client"), "work.ovpn")
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := profile.Dial(ctx)
	if err != nil {
		log.Fatal(err)
	}
	// CloseConn: closing the Net closes the tunnel as well.
	n, err := vpnnet.New(conn, &vpnnet.Options{CloseConn: true})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := n.Close(); err != nil {
			log.Print(err)
		}
	}()

	client := &http.Client{Transport: &http.Transport{DialContext: n.DialContext}}
	resp, err := client.Get("http://intranet.example.com/")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Print(err)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp.Status, len(body), "bytes")
}

// ExampleNet_Listen listens on the tunnel address of the client: another machine of the
// VPN reaches the listener at that address.
func ExampleNet_Listen() {
	profile, err := ovpn.ParseFS(os.DirFS("/etc/openvpn/client"), "work.ovpn")
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	conn, err := profile.Dial(ctx)
	if err != nil {
		log.Fatal(err)
	}
	n, err := vpnnet.New(conn, &vpnnet.Options{CloseConn: true})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := n.Close(); err != nil {
			log.Print(err)
		}
	}()

	l, err := n.Listen("tcp", ":8080") // every address of the tunnel
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("listening at", l.Addr())
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.WriteString(w, "hello through the VPN\n"); err != nil {
			log.Print(err)
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.Serve(l))
}

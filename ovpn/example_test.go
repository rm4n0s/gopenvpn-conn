// SPDX-License-Identifier: GPL-2.0-only

package ovpn_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
	"github.com/rm4n0s/gopenvpn-conn/ovpn"
)

// ExampleParseFS reads a profile and connects with it. The files that the profile
// names (ca, cert, key, tls-crypt, auth-user-pass) are read from the directory of the
// profile, and from nowhere else. It is compiled but not run: it needs a server.
func ExampleParseFS() {
	profile, err := ovpn.ParseFS(os.DirFS("/etc/openvpn/client"), "work.ovpn")
	if err != nil {
		log.Fatal(err)
	}
	if profile.NeedsCredentials {
		// The profile has auth-user-pass with no file: the program asks for the password
		// its own way. The library never reads a terminal.
		profile.Config.Credentials = func(ctx context.Context) (openvpn.Credentials, error) {
			return openvpn.Credentials{Username: "alice", Password: os.Getenv("VPN_PASSWORD")}, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Dial tries the remotes of the profile in order (or at random with remote-random),
	// each for connect-timeout, and returns the first tunnel that comes up.
	conn, err := profile.Dial(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Print(err)
		}
	}()
	fmt.Println("addresses:", conn.ConnectionState().Addrs)
}

// SPDX-License-Identifier: GPL-2.0-only

// Command http reads an OpenVPN profile, connects to its server and gets a web page
// through the tunnel, with no root and no change to the machine. The host name of
// the URL is looked up through the tunnel too, with the DNS servers that the VPN
// server pushed. It prints the status and the size of the body.
//
//	go run ./examples/http -profile client.ovpn -url http://intranet.example.com/
//
// The files that the profile names are read from the directory of the profile.
// A profile with auth-user-pass and no file takes -user and -password-file.
// Ctrl-C stops it at any moment, and the tunnel is closed before it exits.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
	"github.com/rm4n0s/gopenvpn-conn/ovpn"
	"github.com/rm4n0s/gopenvpn-conn/vpnnet"
)

func main() {
	profile := flag.String("profile", "", "the .ovpn profile")
	url := flag.String("url", "", "the page to get")
	user := flag.String("user", "", "the user name, when the profile asks for credentials")
	passwordFile := flag.String("password-file", "", "a file with the password, when the profile asks for credentials")
	flag.Parse()
	if *profile == "" || *url == "" {
		flag.Usage()
		os.Exit(2)
	}
	// Ctrl-C (or a kill) ends the context: the dial or the request stops, and run
	// closes the tunnel on its way out, which tells the server that the client leaves.
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(interrupted, 2*time.Minute)
	err := run(ctx, *profile, *url, *user, *passwordFile)
	wasInterrupted := interrupted.Err() != nil
	cancel()
	stop()
	switch {
	case wasInterrupted:
		log.Print("interrupted")
		os.Exit(130)
	case err != nil:
		log.Fatal(err)
	}
}

func run(ctx context.Context, profilePath, url, user, passwordFile string) (err error) {
	profile, err := loadProfile(profilePath, user, passwordFile)
	if err != nil {
		return err
	}
	conn, err := profile.Dial(ctx)
	if err != nil {
		return err
	}
	n, err := vpnnet.New(conn, &vpnnet.Options{CloseConn: true})
	if err != nil {
		if cerr := conn.Close(); cerr != nil {
			log.Printf("closing the connection: %v", cerr)
		}
		return err
	}
	defer func() {
		if cerr := n.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	state := conn.ConnectionState()
	fmt.Printf("connected: address %v, DNS servers %v\n", state.Addrs, state.DNSServers)

	client := &http.Client{Transport: &http.Transport{DialContext: n.DialContext}}
	defer client.CloseIdleConnections()
	status, size, err := fetch(ctx, client, url)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s, %d bytes\n", url, status, size)
	return nil
}

// loadProfile reads the profile and its files from the directory of the profile. A
// profile that asks for credentials gets them from user and passwordFile.
func loadProfile(path, user, passwordFile string) (*ovpn.Profile, error) {
	profile, err := ovpn.ParseFS(os.DirFS(filepath.Dir(path)), filepath.Base(path))
	if err != nil {
		return nil, err
	}
	if !profile.NeedsCredentials {
		return profile, nil
	}
	if user == "" || passwordFile == "" {
		return nil, errors.New(tagNoCredentials, "the profile asks for credentials: use -user and -password-file", "profile", path)
	}
	password, err := os.ReadFile(passwordFile)
	if err != nil {
		return nil, err
	}
	profile.Config.Credentials = func(context.Context) (openvpn.Credentials, error) {
		return openvpn.Credentials{Username: user, Password: strings.TrimRight(string(password), "\r\n")}, nil
	}
	return profile, nil
}

// fetch gets url and returns the status and the size of the body.
func fetch(ctx context.Context, client *http.Client, url string) (status string, size int64, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, errors.NewErr(tagBadURL, err).SetMetadata("url", url)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	size, err = io.Copy(io.Discard, resp.Body)
	return resp.Status, size, err
}

const (
	tagNoCredentials = "NoCredentials"
	tagBadURL        = "BadURL"
)

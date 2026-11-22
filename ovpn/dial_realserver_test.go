// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package ovpn

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rm4n0s/errors"

	openvpn "github.com/rm4n0s/gopenvpn-conn"
	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

// profileDir is a directory with a profile that a test writes, the files that it
// names, and what the server needs to accept it.
type profileDir struct {
	dir        string
	serverOpts []string
}

// newProfileDir writes client.ovpn (with the remote lines that remotes holds) and
// creds.txt, with the CA, the certificate and the key of pki and a tls-crypt key
// inline, and returns the options of a server that accepts the profile.
func newProfileDir(t *testing.T, pki *servertest.PKI, remotes, extra string) profileDir {
	t.Helper()
	dir := t.TempDir()
	cryptKey := servertest.GenKey(t, "tls-crypt")
	profile := "client\nnobind\nremote-cert-tls server\n" + remotes + extra +
		"auth-user-pass creds.txt\n" +
		"<ca>\n" + readText(t, pki.CAFile) + "</ca>\n" +
		"<cert>\n" + readText(t, pki.ClientCertFile) + "</cert>\n" +
		"<key>\n" + readText(t, pki.ClientKeyFile) + "</key>\n" +
		"<tls-crypt>\n" + readText(t, cryptKey) + "</tls-crypt>\n"
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("client.ovpn", profile)
	write("creds.txt", "alice\ns3cret\n")
	script := "#!/bin/sh\n# $1 is a file: the user name on the first line, the password on the second.\n" +
		"[ \"$(sed -n 1p \"$1\")\" = alice ] && [ \"$(sed -n 2p \"$1\")\" = s3cret ]\n"
	write("auth.sh", script)
	return profileDir{dir: dir, serverOpts: []string{
		"--tls-crypt", cryptKey,
		"--script-security", "2", "--auth-user-pass-verify", "/bin/sh " + filepath.Join(dir, "auth.sh"), "via-file",
	}}
}

// echoOnce sends one ICMP echo request through conn to the server's tunnel address
// and fails the test unless the reply comes within 3 seconds.
func echoOnce(t *testing.T, conn *openvpn.Conn, srv *servertest.Server) {
	t.Helper()
	st := conn.ConnectionState()
	if len(st.Addrs) == 0 {
		t.Fatal("no tunnel address")
	}
	me, server := st.Addrs[0].Addr(), srv.TunnelIP()
	payload := bytes.Repeat([]byte{0x5a}, 56)
	if _, err := conn.Write(vpntest.EchoRequest(me, server, 0x4f50, 1, payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("no echo reply: %v\nserver log:\n%s", err, srv.Log())
		}
		e, ok := vpntest.ParseEchoReply(buf[:n])
		if !ok || e.ID != 0x4f50 || e.Seq != 1 {
			continue
		}
		if e.Src != server || e.Dst != me || !bytes.Equal(e.Payload, payload) {
			t.Fatalf("reply %+v", e)
		}
		return
	}
}

func closeConn(t *testing.T, conn *openvpn.Conn) {
	t.Helper()
	if err := conn.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// deadPort is a port on the loopback that nothing listens on, for TCP.
func deadPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func remoteLine(addr, proto string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	return "remote " + host + " " + port + " " + proto + "\n"
}

// TestProfileDialRealServer shows that a profile written by the test (inline
// certificates and tls-crypt, the credentials in a file that ParseFS reads) connects
// to a real server and carries traffic, over UDP and over TCP.
func TestProfileDialRealServer(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			pki := servertest.NewPKI(t)
			// The address is not known before the server runs: write the profile after.
			pd := newProfileDir(t, pki, "", "")
			srv := servertest.Start(t, servertest.Options{Proto: proto, PKI: pki, Extra: pd.serverOpts})
			rewriteRemotes(t, pd.dir, remoteLine(srv.Addr(), proto))

			p, err := ParseFS(os.DirFS(pd.dir), "client.ovpn")
			if err != nil {
				t.Fatalf("ParseFS: %v", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			conn, err := p.Dial(ctx)
			if err != nil {
				t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
			}
			defer closeConn(t, conn)
			echoOnce(t, conn, srv)
		})
	}
}

// TestProfileDialSecondRemote has a dead remote first: Dial goes on to the next.
func TestProfileDialSecondRemote(t *testing.T) {
	pki := servertest.NewPKI(t)
	pd := newProfileDir(t, pki, "", "connect-timeout 5\n")
	srv := servertest.Start(t, servertest.Options{PKI: pki, Extra: pd.serverOpts})
	rewriteRemotes(t, pd.dir, remoteLine(deadPort(t), "tcp")+remoteLine(srv.Addr(), "udp"))

	p, err := ParseFS(os.DirFS(pd.dir), "client.ovpn")
	if err != nil {
		t.Fatalf("ParseFS: %v", err)
	}
	if len(p.Remotes) != 2 {
		t.Fatalf("Remotes = %v", p.Remotes)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	conn, err := p.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v\nserver log:\n%s", err, srv.Log())
	}
	defer closeConn(t, conn)
	echoOnce(t, conn, srv)
}

// TestProfileDialAllRemotesFail has no server: the error is the one of the last
// remote and says how many were tried.
func TestProfileDialAllRemotesFail(t *testing.T) {
	pki := servertest.NewPKI(t)
	pd := newProfileDir(t, pki, remoteLine(deadPort(t), "tcp")+remoteLine(deadPort(t), "tcp"), "connect-timeout 5\n")
	p, err := ParseFS(os.DirFS(pd.dir), "client.ovpn")
	if err != nil {
		t.Fatalf("ParseFS: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	conn, err := p.Dial(ctx)
	if err == nil {
		closeConn(t, conn)
		t.Fatal("Dial with no server succeeded")
	}
	appErr, ok := errors.FromError(err)
	if !ok || appErr.Tag != openvpn.TagDialFailed {
		t.Fatalf("Dial = %v, want %s", err, openvpn.TagDialFailed)
	}
	if appErr.Metadata["remotes_tried"] != 2 || appErr.Metadata["remotes"] != 2 {
		t.Errorf("metadata = %v", appErr.Metadata)
	}
	if appErr.Metadata["address"] != p.Remotes[1].Address {
		t.Errorf("the error is of %v, want the last remote %s", appErr.Metadata["address"], p.Remotes[1].Address)
	}
}

// TestProfileOpenVPNClient runs the real openvpn client with the same profile, to
// show that the profile that the library reads is one that OpenVPN reads too: it
// gets through the handshake and the push, and logs "Initialization Sequence
// Completed".
func TestProfileOpenVPNClient(t *testing.T) {
	pki := servertest.NewPKI(t)
	pd := newProfileDir(t, pki, "", "")
	srv := servertest.Start(t, servertest.Options{PKI: pki, Extra: pd.serverOpts})
	rewriteRemotes(t, pd.dir, remoteLine(srv.Addr(), "udp"))

	if _, err := ParseFS(os.DirFS(pd.dir), "client.ovpn"); err != nil {
		t.Fatalf("ParseFS: %v", err)
	}
	client := servertest.StartClient(t, pd.dir, "client.ovpn")
	client.Wait(t, "Initialization Sequence Completed", 20*time.Second)
	for _, line := range bytes.Split([]byte(client.Log()), []byte("\n")) {
		if bytes.Contains(line, []byte("Initialization Sequence Completed")) {
			t.Logf("the real client: %s", line) // the evidence for the entry of IMPLEMENTED.md
		}
	}
	client.Stop(t)
}

// rewriteRemotes puts the remote lines at the start of the profile after "client".
func rewriteRemotes(t *testing.T, dir, remotes string) {
	t.Helper()
	path := filepath.Join(dir, "client.ovpn")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte("client\n"), []byte("client\n"+remotes), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

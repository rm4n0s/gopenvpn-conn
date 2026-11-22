// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/rm4n0s/errors"
)

func wantRoute(t *testing.T, err error, route string) {
	t.Helper()
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not an *errors.Error", err, err)
	}
	if !appErr.HasRoute(route) {
		t.Fatalf("route %s, want %s", appErr.Route(), route)
	}
}

func TestLoadRoots(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadRoots(empty)
	wantRoute(t, err, "loadRoots.NoCertificate")
	if _, err := loadRoots(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file gave %v", err)
	}
}

func TestPingAddresses(t *testing.T) {
	v4 := []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")}
	gateway := netip.MustParseAddr("10.8.0.1")
	me, dst, err := pingAddresses(v4, gateway, "")
	if err != nil || me != netip.MustParseAddr("10.8.0.2") || dst != gateway {
		t.Errorf("default target: %v, %v, %v", me, dst, err)
	}
	if _, dst, err = pingAddresses(v4, gateway, "10.8.0.9"); err != nil || dst != netip.MustParseAddr("10.8.0.9") {
		t.Errorf("explicit target: %v, %v", dst, err)
	}
	_, _, err = pingAddresses(nil, gateway, "")
	wantRoute(t, err, "pingAddresses.NoAddress")
	_, _, err = pingAddresses([]netip.Prefix{netip.MustParsePrefix("fd00::2/64")}, gateway, "")
	wantRoute(t, err, "pingAddresses.NoAddress")
	_, _, err = pingAddresses(v4, netip.Addr{}, "")
	wantRoute(t, err, "pingAddresses.NoTarget")
	_, _, err = pingAddresses(v4, gateway, "not an address")
	wantRoute(t, err, "pingAddresses.BadTarget")
}

func TestEchoPacketsRoundTrip(t *testing.T) {
	src, dst := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.1")
	req := echoRequest(src, dst, 7, 3, []byte("hello"))
	if checksum(req[:20]) != 0 || checksum(req[20:]) != 0 {
		t.Error("a checksum of the request does not check")
	}
	// A reply is the request with the type changed, the addresses swapped and the
	// checksums made again.
	reply := echoRequest(dst, src, 7, 3, []byte("hello"))
	reply[20] = 0
	reply[22], reply[23] = 0, 0
	sum := checksum(reply[20:])
	reply[22], reply[23] = byte(sum>>8), byte(sum&0xff)
	from, seq, payload, ok := echoReply(reply, 7)
	if !ok || from != dst || seq != 3 || string(payload) != "hello" {
		t.Errorf("echoReply = %v, %d, %q, %v", from, seq, payload, ok)
	}
	if _, _, _, ok := echoReply(reply, 8); ok {
		t.Error("a reply of another id was taken")
	}
	if _, _, _, ok := echoReply(req, 7); ok {
		t.Error("a request was taken for a reply")
	}
}

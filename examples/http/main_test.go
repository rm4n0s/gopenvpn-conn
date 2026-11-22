// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/servertest"
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

// writeProfile writes a profile whose only file is the CA, inline, and returns its path.
func writeProfile(t *testing.T, extra string) string {
	t.Helper()
	ca, err := os.ReadFile(servertest.NewPKI(t).CAFile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.ovpn")
	text := "client\nremote 127.0.0.1 1194 udp\n" + extra + "<ca>\n" + string(ca) + "</ca>\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadProfileCredentials(t *testing.T) {
	path := writeProfile(t, "auth-user-pass\n")
	_, err := loadProfile(path, "", "")
	wantRoute(t, err, "loadProfile."+tagNoCredentials)

	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := loadProfile(path, "alice", passwordFile)
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	got, err := profile.Config.Credentials(t.Context())
	if err != nil || got.Username != "alice" || got.Password != "s3cret" {
		t.Errorf("Credentials = %+v, %v", got, err)
	}
	if _, err := loadProfile(path, "alice", filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing password file gave %v", err)
	}
}

func TestLoadProfileWithoutCredentials(t *testing.T) {
	profile, err := loadProfile(writeProfile(t, ""), "", "")
	if err != nil || profile.NeedsCredentials {
		t.Fatalf("loadProfile = %v, %v", profile, err)
	}
	if _, err := loadProfile(filepath.Join(t.TempDir(), "missing.ovpn"), "", ""); err == nil {
		t.Error("a missing profile was read")
	}
}

func TestFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		if _, err := w.Write([]byte(strings.Repeat("x", 12345))); err != nil {
			t.Logf("write: %v", err)
		}
	}))
	defer server.Close()
	status, size, err := fetch(t.Context(), server.Client(), server.URL+"/page")
	if err != nil || status != "200 OK" || size != 12345 {
		t.Errorf("fetch = %q, %d, %v", status, size, err)
	}
	if status, _, err = fetch(t.Context(), server.Client(), server.URL+"/missing"); err != nil || status != "404 Not Found" {
		t.Errorf("fetch of a missing page = %q, %v", status, err)
	}
	_, _, err = fetch(t.Context(), server.Client(), "http://bad host/")
	wantRoute(t, err, "fetch."+tagBadURL)
}

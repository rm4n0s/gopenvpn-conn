// SPDX-License-Identifier: GPL-2.0-only

//go:build linux

package servertest

import (
	"net/netip"
	"slices"
	"testing"
)

func TestBuildArgs(t *testing.T) {
	pki := &PKI{CAFile: "/p/ca.crt", ServerCertFile: "/p/s.crt", ServerKeyFile: "/p/s.key"}
	base := config{
		pki:     pki,
		proto:   "udp",
		port:    1194,
		dev:     "tungo1_1",
		subnet:  netip.MustParsePrefix("10.8.0.0/24"),
		logPath: "/l/server.log",
	}
	tests := []struct {
		name string
		edit func(c *config)
		want [][]string // option sequences that must be present, in this order of words
		not  []string   // words that must not be present
	}{
		{
			name: "udp default",
			edit: func(c *config) {},
			want: [][]string{
				{"--mode", "server"}, {"--dev", "tungo1_1"}, {"--server", "10.8.0.0", "255.255.255.0"},
				{"--proto", "udp"}, {"--local", "127.0.0.1"}, {"--port", "1194"},
				{"--ca", "/p/ca.crt"}, {"--cert", "/p/s.crt"}, {"--key", "/p/s.key"},
				{"--dh", "none"}, {"--log", "/l/server.log"},
			},
			not: []string{"--verify-client-cert"},
		},
		{
			name: "tcp",
			edit: func(c *config) { c.proto = "tcp"; c.port = 5000 },
			want: [][]string{{"--proto", "tcp"}, {"--port", "5000"}},
		},
		{
			name: "no dco by default",
			edit: func(c *config) {},
			want: [][]string{{"--disable-dco"}},
		},
		{
			name: "dco on request",
			edit: func(c *config) { c.enableDCO = true },
			not:  []string{"--disable-dco"},
		},
		{
			name: "another subnet",
			edit: func(c *config) { c.subnet = netip.MustParsePrefix("10.9.4.77/28") },
			want: [][]string{{"--server", "10.9.4.64", "255.255.255.240"}},
		},
		{
			name: "extra options come last",
			edit: func(c *config) {
				c.extra = []string{"--push", "route 192.168.50.0 255.255.255.0", "--keepalive", "1", "3"}
			},
			want: [][]string{{"--keepalive", "1", "3"}, {"--push", "route 192.168.50.0 255.255.255.0"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base
			tt.edit(&c)
			args := buildArgs(c)
			for _, seq := range tt.want {
				if !containsSequence(args, seq) {
					t.Errorf("args lack %q:\n%q", seq, args)
				}
			}
			for _, w := range tt.not {
				if slices.Contains(args, w) {
					t.Errorf("args have %q:\n%q", w, args)
				}
			}
			if len(c.extra) > 0 {
				if tail := args[len(args)-len(c.extra):]; !slices.Equal(tail, c.extra) {
					t.Errorf("the extra options are not the end of the command line: %q", args)
				}
			}
		})
	}
}

// containsSequence reports whether seq appears in args as consecutive words.
func containsSequence(args, seq []string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		if slices.Equal(args[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}

// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"testing"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
)

func TestPullFilterOfAConfig(t *testing.T) {
	if (&Config{}).pullFilter() != nil {
		t.Error("a Config with no filters made a filter")
	}
	tests := []struct {
		name   string
		cfg    Config
		option string
		want   ctrlmsg.Verdict
	}{
		{"an option no filter matches", Config{PullFilters: []PullFilter{{PullIgnore, "route "}}}, "ifconfig 10.8.0.2 255.255.255.0", ctrlmsg.Accept},
		{"ignore by prefix", Config{PullFilters: []PullFilter{{PullIgnore, "route"}}}, "route-gateway 10.8.0.1", ctrlmsg.Ignore},
		{"reject", Config{PullFilters: []PullFilter{{PullReject, "compress"}}}, "compress lz4", ctrlmsg.Reject},
		{"the first match decides: accept before ignore", Config{PullFilters: []PullFilter{{PullAccept, "route 192.168.1."}, {PullIgnore, "route "}}}, "route 192.168.1.0 255.255.255.0", ctrlmsg.Accept},
		{"the first match decides: ignore the others", Config{PullFilters: []PullFilter{{PullAccept, "route 192.168.1."}, {PullIgnore, "route "}}}, "route 10.0.0.0 255.0.0.0", ctrlmsg.Ignore},
		{"a prefix is not a name", Config{PullFilters: []PullFilter{{PullIgnore, "rout "}}}, "route 1.2.3.4", ctrlmsg.Accept},
		{"route-nopull: a route", Config{RouteNoPull: true}, "route 10.0.0.0 255.0.0.0", ctrlmsg.Ignore},
		{"route-nopull: an IPv6 route", Config{RouteNoPull: true}, "route-ipv6 fd00::/64", ctrlmsg.Ignore},
		{"route-nopull: the route gateway", Config{RouteNoPull: true}, "route-gateway 10.8.0.1", ctrlmsg.Ignore},
		{"route-nopull: redirect-gateway", Config{RouteNoPull: true}, "redirect-gateway def1", ctrlmsg.Ignore},
		{"route-nopull: a DNS server", Config{RouteNoPull: true}, "dhcp-option DNS 10.8.0.1", ctrlmsg.Ignore},
		{"route-nopull: the dns option", Config{RouteNoPull: true}, "dns server 1 address 10.8.0.1", ctrlmsg.Ignore},
		{"route-nopull: the address of the tunnel stays", Config{RouteNoPull: true}, "ifconfig 10.8.0.2 255.255.255.0", ctrlmsg.Accept},
		{"route-nopull: the ping stays", Config{RouteNoPull: true}, "ping 10", ctrlmsg.Accept},
		{"a filter before route-nopull wins", Config{RouteNoPull: true, PullFilters: []PullFilter{{PullAccept, "route 10."}}}, "route 10.0.0.0 255.0.0.0", ctrlmsg.Accept},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.pullFilter()(tt.option); got != tt.want {
				t.Errorf("verdict for %q = %d, want %d", tt.option, got, tt.want)
			}
		})
	}
}

func TestPullFiltersAreCopied(t *testing.T) {
	cfg := Config{PullFilters: []PullFilter{{PullIgnore, "route"}}}
	f := cfg.pullFilter()
	cfg.PullFilters[0].Action = PullAccept // the caller changes its own slice later
	if f("route 1.2.3.4") != ctrlmsg.Ignore {
		t.Error("a change of the Config after the Conn was made changed its filters")
	}
}

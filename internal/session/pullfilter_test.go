// SPDX-License-Identifier: GPL-2.0-only

package session

import (
	"strings"
	"testing"
	"testing/synctest"

	"github.com/rm4n0s/errors"

	"github.com/rm4n0s/gopenvpn-conn/internal/ctrlmsg"
	"github.com/rm4n0s/gopenvpn-conn/internal/vpntest"
)

func filterRig(t *testing.T, filter func(string) ctrlmsg.Verdict) *tlsRig {
	t.Helper()
	push := vpntest.DefaultPushReply + ",route 10.1.0.0 255.255.0.0,route 192.168.5.0 255.255.255.0,dhcp-option DNS 10.8.0.1"
	return newTLSRig(t, tlsOptions{
		rigOptions: rigOptions{transport: transports[0], wrap: wrapKinds[0], server: vpntest.ServerOptions{PushMessages: []string{push}}},
		tweak:      func(o *Options) { o.PullFilter = filter },
	})
}

func TestPullFilterIgnoresPushedOptions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := filterRig(t, func(option string) ctrlmsg.Verdict {
			if strings.HasPrefix(option, "route ") && !strings.HasPrefix(option, "route 192.168.") {
				return ctrlmsg.Ignore
			}
			if strings.HasPrefix(option, "dhcp-option") {
				return ctrlmsg.Ignore
			}
			return ctrlmsg.Accept
		})
		if err := r.session.Handshake(t.Context()); err != nil {
			t.Fatal(err)
		}
		p := r.session.Pushed()
		if len(p.Routes) != 1 || p.Routes[0].Prefix.String() != "192.168.5.0/24" {
			t.Errorf("routes %+v: only the one that no filter ignored is left", p.Routes)
		}
		if len(p.DNSServers) != 0 {
			t.Errorf("DNS servers %v after an ignore of dhcp-option", p.DNSServers)
		}
		for _, o := range p.Options {
			if strings.HasPrefix(o, "route 10.1") || strings.HasPrefix(o, "dhcp-option") {
				t.Errorf("the option %q is in the pushed options", o)
			}
		}
		if p.MTU == 0 || p.Cipher == "" {
			t.Errorf("the options that nobody filtered are lost: %+v", p)
		}
	})
}

func TestPullFilterRejectEndsTheHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := filterRig(t, func(option string) ctrlmsg.Verdict {
			if strings.HasPrefix(option, "dhcp-option") {
				return ctrlmsg.Reject
			}
			return ctrlmsg.Accept
		})
		err := r.session.Handshake(t.Context())
		appErr, ok := errors.FromError(err)
		if !ok || appErr.Tag != ctrlmsg.TagPushedOptionRejected || !appErr.HasRoute("control->PushReply.Filter.PushedOptionRejected") {
			t.Fatalf("Handshake = %v (route %v)", err, appErr)
		}
		if r.session.Pushed() != nil {
			t.Error("Pushed() is not nil after a failure")
		}
		synctest.Wait()
	})
}

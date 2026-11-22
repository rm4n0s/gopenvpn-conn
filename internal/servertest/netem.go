// SPDX-License-Identifier: GPL-2.0-only

//go:build linux

package servertest

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Netem makes the loopback of the namespace a bad network for the rest of the test:
// `tc qdisc add dev lo root netem <params>`, for example "loss 10% delay 20ms reorder
// 25% duplicate 5%". It is taken away when the test ends. It changes the loopback
// of the private namespace of scripts/vpn-ns.sh and nothing else: the test is skipped
// anywhere else, and when tc is missing.
func Netem(t testing.TB, params string) {
	t.Helper()
	if os.Getenv("GOPENVPN_NS") != "1" {
		t.Skip("servertest: not inside the namespace of scripts/vpn-ns.sh; netem would change the machine's loopback")
	}
	if _, err := exec.LookPath("tc"); err != nil {
		t.Skip("servertest: tc is not installed")
	}
	args := append([]string{"qdisc", "add", "dev", "lo", "root", "netem"}, strings.Fields(params)...)
	if out, err := exec.Command("tc", args...).CombinedOutput(); err != nil {
		t.Skipf("servertest: tc %v: %v\n%s (the kernel may lack netem)", args, err, out)
	}
	t.Cleanup(func() { NetemOff(t) })
}

// NetemOff takes the faults away at once (the cleanup of Netem does it again, which
// is harmless).
func NetemOff(t testing.TB) {
	t.Helper()
	if os.Getenv("GOPENVPN_NS") != "1" {
		return
	}
	// tc fails when there is no qdisc to delete: that is the state that is wanted.
	if out, err := exec.Command("tc", "qdisc", "del", "dev", "lo", "root").CombinedOutput(); err != nil && !strings.Contains(string(out), "Cannot delete qdisc with handle of zero") && !strings.Contains(string(out), "No such file") {
		t.Logf("servertest: tc qdisc del: %v\n%s", err, out)
	}
}

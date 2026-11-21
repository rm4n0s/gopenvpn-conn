// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package servertest

import (
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rm4n0s/errors"
)

func TestStartStop(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{"udp", Options{Proto: "udp"}},
		{"tcp", Options{Proto: "tcp"}},
		{"udp without dco", Options{Proto: "udp", DisableDCO: true}},
		{"default options", Options{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pid := 0
			t.Run("server", func(t *testing.T) {
				s := Start(t, tt.opts)
				pid = s.PID()
				if pid <= 0 {
					t.Fatalf("PID() = %d", pid)
				}
				if !strings.Contains(s.Log(), "Initialization Sequence Completed") {
					t.Errorf("the log has no ready line:\n%s", s.Log())
				}
				wantNet := tt.opts.Proto
				if wantNet == "" {
					wantNet = "udp"
				}
				if s.Network() != wantNet {
					t.Errorf("Network() = %q, want %q", s.Network(), wantNet)
				}
				if s.TunnelIP() != netip.MustParseAddr("10.8.0.1") {
					t.Errorf("TunnelIP() = %v, want 10.8.0.1", s.TunnelIP())
				}
				if err := syscall.Kill(pid, 0); err != nil {
					t.Errorf("the server process %d is not running: %v", pid, err)
				}
				s.WaitLog(t, "link local (bound)", time.Second)
			})
			// The cleanup of the inner test has run: the server is gone and has been waited for.
			if pid <= 0 {
				t.Fatal("the server never started")
			}
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Errorf("the server process %d is still there after the test: %v", pid, err)
			}
		})
	}
}

func TestTwoServersAtOnce(t *testing.T) {
	a := Start(t, Options{Subnet: netip.MustParsePrefix("10.8.0.0/24")})
	b := Start(t, Options{Subnet: netip.MustParsePrefix("10.9.0.0/24"), Proto: "tcp"})
	if a.Addr() == b.Addr() {
		t.Errorf("two servers have the address %s", a.Addr())
	}
	if a.PID() == b.PID() {
		t.Error("two servers are one process")
	}
	if b.TunnelIP() != netip.MustParseAddr("10.9.0.1") {
		t.Errorf("TunnelIP() = %v, want 10.9.0.1", b.TunnelIP())
	}
}

func TestWaitLogTimesOutWithTheLog(t *testing.T) {
	s := Start(t, Options{})
	// A line that never comes must fail the test, with the log in the message.
	rec := &failRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.WaitLog(rec, "this line is never logged", 100*time.Millisecond)
	}()
	<-done
	if !rec.failed || !strings.Contains(rec.msg, "Initialization Sequence Completed") {
		t.Errorf("WaitLog did not fail with the log: failed=%v msg=%q", rec.failed, rec.msg)
	}
}

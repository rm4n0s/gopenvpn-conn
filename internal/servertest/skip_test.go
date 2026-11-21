// SPDX-License-Identifier: GPL-2.0-only

//go:build linux

package servertest

import (
	"runtime"
	"testing"
)

// skipRecorder is a testing.TB that records a Skip instead of skipping, so
// that a test can ask whether Start would skip.
type skipRecorder struct {
	testing.TB
	skipped bool
	reason  string
}

func (r *skipRecorder) Skip(args ...any) {
	r.skipped = true
	if len(args) > 0 {
		if s, ok := args[0].(string); ok {
			r.reason = s
		}
	}
	runtime.Goexit()
}

// startSkips runs Start in a goroutine, because a skip ends it with Goexit.
func startSkips(t *testing.T) *skipRecorder {
	t.Helper()
	r := &skipRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		Start(r, Options{})
	}()
	<-done
	return r
}

func TestStartSkips(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"openvpn is not installed", map[string]string{"PATH": t.TempDir(), "GOPENVPN_NS": "1"}, "openvpn is not installed"},
		{"not inside the namespace", map[string]string{"GOPENVPN_NS": ""}, "namespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			r := startSkips(t)
			if !r.skipped {
				t.Fatal("Start did not skip")
			}
			if got := r.reason; len(got) == 0 || !contains(got, tt.want) {
				t.Errorf("skip reason = %q, want it to mention %q", got, tt.want)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// SPDX-License-Identifier: GPL-2.0-only

//go:build linux && gopenvpn_server

package servertest

import (
	"fmt"
	"runtime"
	"testing"
)

// failRecorder is a testing.TB that records a Fatalf instead of failing.
type failRecorder struct {
	testing.TB
	failed bool
	msg    string
}

func (r *failRecorder) Fatalf(format string, args ...any) {
	r.failed = true
	r.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

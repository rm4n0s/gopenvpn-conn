// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"testing"
	"testing/synctest"
)

func TestBubbleGoroutines(t *testing.T) {
	if got := BubbleGoroutines(); got != 0 {
		t.Errorf("outside a bubble: %d, want 0", got)
	}
	synctest.Test(t, func(t *testing.T) {
		base := BubbleGoroutines()
		if base < 1 {
			t.Fatalf("in a bubble: %d, want at least 1", base)
		}
		stop := make(chan struct{})
		for i := 0; i < 3; i++ {
			go func() { <-stop }()
		}
		synctest.Wait()
		if got := BubbleGoroutines(); got != base+3 {
			t.Errorf("with 3 more goroutines: %d, want %d", got, base+3)
		}
		close(stop)
		synctest.Wait()
		if got := BubbleGoroutines(); got != base {
			t.Errorf("after they ended: %d, want %d", got, base)
		}
	})
}

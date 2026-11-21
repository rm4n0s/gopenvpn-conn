// SPDX-License-Identifier: GPL-2.0-only

package vpntest

import (
	"regexp"
	"runtime"
	"strings"
)

var bubbleMark = regexp.MustCompile(`synctest bubble (\d+)\]`)

// BubbleGoroutines is the number of goroutines in the testing/synctest bubble of
// the caller, the caller included. Unlike runtime.NumGoroutine it does not count
// what runs outside the bubble (the finalizer goroutine while it runs a
// finalizer, goroutines of other tests), so a test can compare it before and
// after without noise. It returns 0 when the caller is not in a bubble.
func BubbleGoroutines() int {
	own := make([]byte, 4096)
	own = own[:runtime.Stack(own, false)]
	m := bubbleMark.FindSubmatch(own)
	if m == nil {
		return 0
	}
	mark := "synctest bubble " + string(m[1]) + "]"
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, line := range strings.Split(string(buf), "\n") {
		if strings.HasPrefix(line, "goroutine ") && strings.HasSuffix(line, mark+":") {
			count++
		}
	}
	return count
}

// SPDX-License-Identifier: GPL-2.0-only

package clean

import "testing"

func TestDo(t *testing.T) {
	var appErr interface{ HasRoute(string) bool }
	if !appErr.HasRoute("Do.ThingFailed") || !appErr.HasRoute("Do->Other."+TagOther) {
		t.Fatal("route")
	}
}

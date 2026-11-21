// SPDX-License-Identifier: GPL-2.0-only

package sample

import "testing"

func TestRoutes(t *testing.T) {
	var appErr interface{ HasRoute(string) bool }
	_ = appErr.HasRoute("F.A")
}

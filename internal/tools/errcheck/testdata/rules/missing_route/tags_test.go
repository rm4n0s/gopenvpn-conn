// SPDX-License-Identifier: GPL-2.0-only

package sample

import "testing"

const wantRoute = "F.ByConst"

func TestRoutes(t *testing.T) {
	var appErr interface{ HasRoute(string) bool }
	_ = appErr.HasRoute("Outer->F.Tested")
	_ = appErr.HasRoute("F." + tagTestedByConst)
	_ = appErr.HasRoute("F.Part.More")
	_ = appErr.HasRoute(wantRoute)
}

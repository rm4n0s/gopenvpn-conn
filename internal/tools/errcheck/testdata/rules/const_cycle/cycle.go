// SPDX-License-Identifier: GPL-2.0-only

package sample

// These constants refer to each other: Go refuses them, but the checker only
// parses, so it must stop and not report them (they are not constant strings).
const (
	tagCycleA = tagCycleB
	tagCycleB = tagCycleA
)

// SPDX-License-Identifier: GPL-2.0-only

package sample

const tagUntested = "Untested" // want 8

const (
	TagTested         = "Tested"
	tagAlsoUntested   = "AlsoUntested" // want 8
	tagTestedByConst  = "ByConst"
	tagPartial        = "Part" // want 8
	tagInATable       = "InATable"
	tagAcrossFiles    = "AcrossFiles"
	taglineNotATagVar = "not a tag: no capital after tag"
)

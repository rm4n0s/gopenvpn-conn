// SPDX-License-Identifier: GPL-2.0-only

package sample

import "github.com/rm4n0s/errors"

const tagA = "A"

var ErrA = errors.New(tagA, "a") // want 6

var ErrD = &errors.Error{Tag: tagA}

var (
	ErrE = errors.NewErrf(tagA, "x") // want 6
)

var later = func() error { return errors.New(tagA, "in a closure") }

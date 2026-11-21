// SPDX-License-Identifier: GPL-2.0-only

package sample

import "github.com/rm4n0s/errors"

const tagA = "A"

func F() error {
	return errors.New(tagA) // want 2
}

func G() error {
	return errors.New(tagA, "msg", "key") // want 2
}

func H() error {
	return errors.New(tagA, "msg", 5, "v") // want 2
}

func I() error {
	return errors.New(tagA, "msg").SetMetadata("k", 1) // want 2
}

func J(pairs []any) error {
	return errors.New(tagA, "msg", pairs...)
}

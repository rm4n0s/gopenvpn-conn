// SPDX-License-Identifier: GPL-2.0-only

package sample

import "github.com/rm4n0s/errors"

const tagA = "A"

func F(err error) error {
	return errors.NewErr(tagA, err).SetMetadata("a", 1).SetMetadata("b", 2) // want 2
}

func G() error {
	return errors.New(tagA, "m").SetMetadata("a", 1).SetMetadata("b", 2) // want 2
}

func H(err error) error {
	return errors.NewErrf(tagA, "x %d", 1).SetMetadata("a", 1)
}

func I(err *errors.Error) error {
	return err.SetMetadata("a", 1).SetMetadata("b", 2)
}

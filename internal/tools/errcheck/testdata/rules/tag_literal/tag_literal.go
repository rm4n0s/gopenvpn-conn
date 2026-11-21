// SPDX-License-Identifier: GPL-2.0-only

package sample

import "github.com/rm4n0s/errors"

func F() error {
	return errors.New("Literal", "m") // want 5
}

func G(err error) error {
	return errors.NewErr("Literal2", err) // want 5
}

func H() error {
	return errors.NewErrf("Lit"+"eral", "m %d", 1) // want 5
}

var ErrS = &errors.Error{Tag: "Sentinel"} // want 5

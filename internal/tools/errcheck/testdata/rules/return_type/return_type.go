// SPDX-License-Identifier: GPL-2.0-only

package sample

import "github.com/rm4n0s/errors"

func F() *errors.Error { // want 7
	return nil
}

func G() (int, *errors.Error) { // want 7
	return 0, nil
}

var H = func() *errors.Error { return nil } // want 7

type I interface {
	M() *errors.Error // want 7
}

func J() error { return nil }

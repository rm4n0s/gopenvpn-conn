// SPDX-License-Identifier: GPL-2.0-only

package clean

import (
	stdErrors "errors"
	"fmt"

	"github.com/rm4n0s/errors"
)

const tagThingFailed = "ThingFailed"

// TagOther is exported because callers match on it.
const TagOther = "Other"

var ErrOther = &errors.Error{Tag: TagOther}

var makeLater = func() error {
	return errors.New(tagThingFailed, "made when called, not in init")
}

func Do(n int) error {
	if n > 3 {
		return errors.New(tagThingFailed, "too big", "n", n)
	}
	if err := stdErrors.Join(nil); err != nil {
		return errors.NewErr(tagThingFailed, err).SetMetadata("a", 1, "b", 2)
	}
	if n < 0 {
		return errors.NewErrf(TagOther, "negative: %d", n)
	}
	fmt.Println("fmt is fine when it does not make an error")
	return nil
}

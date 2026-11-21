// SPDX-License-Identifier: GPL-2.0-only

package sample

import "fmt"

func F() error {
	return fmt.Errorf("x: %w", nil) // want 1
}

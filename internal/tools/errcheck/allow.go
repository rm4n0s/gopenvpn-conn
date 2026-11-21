// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rm4n0s/errors"
)

// allowEntry silences one rule in one file, for a reason.
type allowEntry struct {
	Path   string // relative to the module root, with slashes
	Rule   int
	Reason string
	Line   int // in the allow file
}

// String formats an entry as it is written in the allow file.
func (a allowEntry) String() string {
	return fmt.Sprintf("%s:%d:%s", a.Path, a.Rule, a.Reason)
}

// loadAllow reads the allow file: one entry path:rule:reason per line, blank
// lines and lines that start with # ignored.
func loadAllow(path string) ([]allowEntry, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, errors.NewErr(tagReadAllowFailed, err).SetMetadata("file", path)
	}
	var entries []allowEntry
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return nil, errors.New(tagAllowSyntax, "an allow line is path:rule:reason", "file", path, "line", i+1)
		}
		rule, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || rule < 1 || rule > 8 {
			return nil, errors.New(tagAllowSyntax, "the rule of an allow line is a number from 1 to 8", "file", path, "line", i+1)
		}
		reason := strings.TrimSpace(parts[2])
		if reason == "" {
			return nil, errors.New(tagAllowSyntax, "an allow line needs a reason", "file", path, "line", i+1)
		}
		entries = append(entries, allowEntry{
			Path:   strings.TrimSpace(parts[0]),
			Rule:   rule,
			Reason: reason,
			Line:   i + 1,
		})
	}
	return entries, nil
}

// applyAllow removes the reports that an entry silences. It also returns the
// entries that silenced nothing: a stale entry is itself a problem.
func applyAllow(reports []Report, allow []allowEntry) (kept []Report, unused []allowEntry) {
	used := make([]bool, len(allow))
	for _, r := range reports {
		silenced := false
		for i, a := range allow {
			if a.Path == r.File && a.Rule == r.Rule {
				used[i] = true
				silenced = true
			}
		}
		if !silenced {
			kept = append(kept, r)
		}
	}
	for i, a := range allow {
		if !used[i] {
			unused = append(unused, a)
		}
	}
	return kept, unused
}

const (
	tagReadAllowFailed = "ReadAllowFailed"
	tagAllowSyntax     = "AllowSyntax"
)

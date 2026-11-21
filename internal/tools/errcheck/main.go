// SPDX-License-Identifier: GPL-2.0-only

// Command errcheck checks the error rules of SPEC §14.1 on the Go files of the
// module: the ones that a program can check. The others (a constructor is
// called in the function that fails, an error from the module is returned
// untouched) are checked by the reviewer. Rule 8, a route test for every tag, is
// met when a string of a test file ends with ".Tag".
//
// Usage:
//
//	go run ./internal/tools/errcheck -allow internal/tools/errcheck/errcheck.allow
//
// It prints one line, file:line: rule N: text, for each violation and exits
// with status 1 when there is one. The allow file accepts a violation for a
// reason; an entry that silences nothing is reported too.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/rm4n0s/errors"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main with its arguments and streams, so that tests can call it. It
// returns the exit status: 0 for no violation, 1 for violations, 2 for a
// problem that stopped the check.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("errcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	allowFile := fs.String("allow", "", "file of accepted violations, one path:rule:reason per line")
	root := fs.String("root", ".", "root directory of the module")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	var allow []allowEntry
	if *allowFile != "" {
		entries, err := loadAllow(*allowFile)
		if err != nil {
			logger.Error("cannot read the allow file", "err", err)
			return 2
		}
		allow = entries
	}
	reports, err := Check(*root)
	if err != nil {
		logger.Error("cannot check the module", "err", err)
		return 2
	}
	kept, unused := applyAllow(reports, allow)
	var out strings.Builder
	for _, r := range kept {
		out.WriteString(r.String())
		out.WriteByte('\n')
	}
	for _, a := range unused {
		fmt.Fprintf(&out, "%s:%d: unused allow entry %q: it silences nothing; remove it\n", *allowFile, a.Line, a.String())
	}
	if err := writeReport(stdout, out.String()); err != nil {
		logger.Error("cannot write the report", "err", err)
		return 2
	}
	if len(kept)+len(unused) > 0 {
		return 1
	}
	return 0
}

// writeReport writes the text of the report to w.
func writeReport(w io.Writer, text string) error {
	if _, err := io.WriteString(w, text); err != nil {
		return errors.NewErr(tagWriteFailed, err)
	}
	return nil
}

const tagWriteFailed = "WriteFailed"

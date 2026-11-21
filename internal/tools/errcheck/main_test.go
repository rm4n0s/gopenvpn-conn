// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/rm4n0s/errors"
)

// wantMarker marks, in a fixture, a line that must be reported: `// want 2` or
// `// want 1,5`.
var wantMarker = regexp.MustCompile(`// want ([0-9,]+)\s*$`)

// wantReports reads the markers of the Go files of a fixture directory and
// returns them as "file:line:rule", sorted.
func wantReports(t *testing.T, dir string) []string {
	t.Helper()
	var want []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, e.Name())))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			m := wantMarker.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			for _, rule := range strings.Split(m[1], ",") {
				want = append(want, fmt.Sprintf("%s:%d:%s", e.Name(), i+1, rule))
			}
		}
	}
	sort.Strings(want)
	return want
}

// gotReports formats reports as "file:line:rule", sorted.
func gotReports(reports []Report) []string {
	var got []string
	for _, r := range reports {
		got = append(got, fmt.Sprintf("%s:%d:%d", r.File, r.Line, r.Rule))
	}
	sort.Strings(got)
	return got
}

func TestRules(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no fixtures")
	}
	for _, e := range entries {
		dir := filepath.Join("testdata", "rules", e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			reports, err := Check(dir)
			if err != nil {
				t.Fatal(err)
			}
			got, want := gotReports(reports), wantReports(t, dir)
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("reports differ\n got: %q\nwant: %q\nfull: %v", got, want, reports)
			}
		})
	}
}

// TestEveryRuleHasAFixture fails when a rule of SPEC §14.1 that the checker
// enforces is reported by no fixture.
func TestEveryRuleHasAFixture(t *testing.T) {
	seen := map[int]bool{}
	entries, err := os.ReadDir(filepath.Join("testdata", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		reports, err := Check(filepath.Join("testdata", "rules", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range reports {
			seen[r.Rule] = true
		}
	}
	for _, rule := range []int{1, 2, 5, 6, 7, 8} {
		if !seen[rule] {
			t.Errorf("no fixture is reported for rule %d", rule)
		}
	}
}

func TestReportString(t *testing.T) {
	r := Report{File: "a/b.go", Line: 12, Rule: 2, Text: "text"}
	if got, want := r.String(), "a/b.go:12: rule 2: text"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestSkippedDirectories(t *testing.T) {
	tests := []struct {
		name string
		skip bool
	}{
		{"reference", true},
		{"testdata", true},
		{"vendor", true},
		{".git", true},
		{".wine-test", true},
		{"_old", true},
		{"internal", false},
		{"ovpn", false},
	}
	for _, tt := range tests {
		if got := skipDir(tt.name); got != tt.skip {
			t.Errorf("skipDir(%q) = %v, want %v", tt.name, got, tt.skip)
		}
	}
}

func TestLoadAllow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow")
	content := "# a comment\n\ninternal/x/y.go:2:a reason: with a colon\n  other.go : 5 : spaces are trimmed \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadAllow(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []allowEntry{
		{Path: "internal/x/y.go", Rule: 2, Reason: "a reason: with a colon", Line: 3},
		{Path: "other.go", Rule: 5, Reason: "spaces are trimmed", Line: 4},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestLoadAllowSyntax(t *testing.T) {
	tests := []struct {
		name    string
		content string
		line    int
	}{
		{"two fields", "f.go:2\n", 1},
		{"rule is not a number", "# c\nf.go:x:reason\n", 2},
		{"rule below range", "f.go:0:reason\n", 1},
		{"rule above range", "f.go:9:reason\n", 1},
		{"no reason", "f.go:2:\n", 1},
		{"blank reason", "f.go:2:   \n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "allow")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadAllow(path)
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute("loadAllow." + tagAllowSyntax) {
				t.Errorf("unexpected failure path: %s", appErr.Route())
			}
			if got := appErr.Metadata["line"]; got != tt.line {
				t.Errorf("metadata line = %v, want %d", got, tt.line)
			}
		})
	}
}

func TestLoadAllowReadFailed(t *testing.T) {
	_, err := loadAllow(filepath.Join(t.TempDir(), "missing"))
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("loadAllow.ReadAllowFailed") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cause is lost: %v", err)
	}
}

func TestCheckListDirFailed(t *testing.T) {
	_, err := Check(filepath.Join(t.TempDir(), "missing"))
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("Check->listGoFiles.ListDirFailed") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
}

func TestCheckParseFailed(t *testing.T) {
	dir := t.TempDir()
	broken := "package sample\n\nfunc broken( {\n"
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Check(dir)
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("Check." + tagParseFailed) {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if got := appErr.Metadata["file"]; got != "broken.go" {
		t.Errorf("metadata file = %v, want broken.go", got)
	}
}

func TestCheckWalksSubdirectories(t *testing.T) {
	dir := t.TempDir()
	src := "package p\n\nimport \"fmt\"\n\nfunc F() error { return fmt.Errorf(\"x\") }\n"
	for _, sub := range []string{"a/b", "testdata/x", "reference/y", ".hidden"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(sub)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(sub), "f.go"), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reports, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := gotReports(reports)
	if len(got) != 1 || got[0] != "a/b/f.go:5:1" {
		t.Errorf("reports = %q, want only a/b/f.go:5:1", got)
	}
}

func TestApplyAllow(t *testing.T) {
	reports := []Report{
		{File: "a.go", Line: 1, Rule: 1},
		{File: "a.go", Line: 9, Rule: 1},
		{File: "a.go", Line: 3, Rule: 2},
		{File: "b.go", Line: 1, Rule: 1},
	}
	allow := []allowEntry{
		{Path: "a.go", Rule: 1, Reason: "r"},
		{Path: "c.go", Rule: 1, Reason: "stale"},
	}
	kept, unused := applyAllow(reports, allow)
	if got := gotReports(kept); strings.Join(got, ",") != "a.go:3:2,b.go:1:1" {
		t.Errorf("kept = %q", got)
	}
	if len(unused) != 1 || unused[0].Path != "c.go" {
		t.Errorf("unused = %v, want the entry for c.go", unused)
	}
}

func TestRun(t *testing.T) {
	fixture := filepath.Join("testdata", "rules", "fmt_errorf")
	tmp := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(tmp, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	silenced := write("silenced", "f.go:1:fixture of the checker\n")
	stale := write("stale", "f.go:1:fixture of the checker\nf.go:7:nothing to silence\n")
	malformed := write("malformed", "not a line\n")

	tests := []struct {
		name       string
		args       []string
		wantStatus int
		wantOut    string // a regexp that stdout must match; "" for no output
		wantErr    string // a substring of stderr
	}{
		{"violation is printed", []string{"-root", fixture}, 1, `(?m)^f\.go:\d+: rule 1: fmt\.Errorf`, ""},
		{"allowed violation", []string{"-root", fixture, "-allow", silenced}, 0, "", ""},
		{"stale allow entry", []string{"-root", fixture, "-allow", stale}, 1, `unused allow entry "f\.go:7:nothing to silence"`, ""},
		{"malformed allow file", []string{"-root", fixture, "-allow", malformed}, 2, "", "cannot read the allow file"},
		{"missing allow file", []string{"-root", fixture, "-allow", filepath.Join(tmp, "nope")}, 2, "", "cannot read the allow file"},
		{"missing root", []string{"-root", filepath.Join(tmp, "nope")}, 2, "", "cannot check the module"},
		{"unknown flag", []string{"-nope"}, 2, "", "flag provided but not defined"},
		{"clean fixture", []string{"-root", filepath.Join("testdata", "rules", "clean")}, 0, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			status := run(tt.args, &stdout, &stderr)
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d\nstdout: %s\nstderr: %s", status, tt.wantStatus, &stdout, &stderr)
			}
			if tt.wantOut == "" && stdout.Len() != 0 {
				t.Errorf("unexpected stdout: %s", &stdout)
			}
			if tt.wantOut != "" && !regexp.MustCompile(tt.wantOut).Match(stdout.Bytes()) {
				t.Errorf("stdout does not match %q:\n%s", tt.wantOut, &stdout)
			}
			if tt.wantErr != "" && !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr does not contain %q:\n%s", tt.wantErr, &stderr)
			}
		})
	}
}

func TestRunLogsTheRouteOfAnError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run([]string{"-root", filepath.Join(t.TempDir(), "nope")}, &stdout, &stderr)
	if status != 2 {
		t.Fatalf("status = %d, want 2", status)
	}
	// slog writes the logged error through its LogValuer: the tag and the route.
	for _, want := range []string{"ListDirFailed", "listGoFiles"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, &stderr)
		}
	}
}

// failingWriter is a stdout that cannot be written.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestRunWriteFailed(t *testing.T) {
	var stderr bytes.Buffer
	status := run([]string{"-root", filepath.Join("testdata", "rules", "fmt_errorf")}, failingWriter{}, &stderr)
	if status != 2 {
		t.Errorf("status = %d, want 2", status)
	}
	if !strings.Contains(stderr.String(), "cannot write the report") || !strings.Contains(stderr.String(), tagWriteFailed) {
		t.Errorf("stderr does not say why:\n%s", &stderr)
	}
}

func TestWriteReportFailed(t *testing.T) {
	err := writeReport(failingWriter{}, "text")
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("writeReport." + tagWriteFailed) {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("the cause is lost: %v", err)
	}
}

func TestAllowEntryString(t *testing.T) {
	a := allowEntry{Path: "x/y.go", Rule: 3, Reason: "because"}
	if got, want := a.String(), "x/y.go:"+strconv.Itoa(3)+":because"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

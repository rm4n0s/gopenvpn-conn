// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rm4n0s/errors"
)

// errorsPath is the import path of the error package of the module.
const errorsPath = "github.com/rm4n0s/errors"

// unresolved stands for a part of a route string that is not known at parse
// time, so that it never matches the end of a tag.
const unresolved = "\x00"

// tagName matches the names of the constants that hold error tags.
var tagName = regexp.MustCompile(`^[tT]ag[A-Z]`)

// Report is one violation of the error rules of SPEC §14.1.
type Report struct {
	File string // relative to the root, with slashes
	Line int
	Rule int
	Text string
}

// String formats a report as file:line: rule N: text.
func (r Report) String() string {
	return fmt.Sprintf("%s:%d: rule %d: %s", r.File, r.Line, r.Rule, r.Text)
}

// parsedFile is a Go file and what the checker needs to know about its imports.
type parsedFile struct {
	rel     string
	file    *ast.File
	isTest  bool
	errName string // local name of github.com/rm4n0s/errors, "" when not imported
	fmtName string // local name of fmt, "" when not imported
}

// tagConst is a constant that holds an error tag.
type tagConst struct {
	pf   *parsedFile
	name string
	pos  token.Pos
}

// state is what one run of Check collects.
type state struct {
	fset    *token.FileSet
	files   []*parsedFile
	consts  map[string]ast.Expr // the value of every constant, by name, from every file
	tags    []tagConst          // tag constants of the files that are not tests
	strs    []ast.Expr          // the string literals and concatenations of the test files
	reports []Report
}

// Check parses every Go file under root and returns the violations of the
// error rules, sorted by file and line. It skips reference/, testdata/,
// vendor/ and every directory whose name starts with "." or "_".
func Check(root string) ([]Report, error) {
	paths, err := listGoFiles(root, "")
	if err != nil {
		return nil, err
	}
	s := &state{fset: token.NewFileSet(), consts: map[string]ast.Expr{}}
	for _, rel := range paths {
		full := filepath.Join(root, filepath.FromSlash(rel))
		f, err := parser.ParseFile(s.fset, full, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, errors.NewErr(tagParseFailed, err).SetMetadata("file", rel)
		}
		pf := &parsedFile{rel: rel, file: f, isTest: strings.HasSuffix(rel, "_test.go")}
		s.files = append(s.files, pf)
		s.collectImports(pf)
		s.collectConsts(pf)
	}
	for _, pf := range s.files {
		s.checkFile(pf)
	}
	s.checkTagRoutes()
	sort.Slice(s.reports, func(i, j int) bool {
		a, b := s.reports[i], s.reports[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return s.reports, nil
}

// listGoFiles returns the Go files under root/rel, as paths relative to root.
func listGoFiles(root, rel string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, errors.NewErr(tagListDirFailed, err).SetMetadata("dir", rel)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		sub := name
		if rel != "" {
			sub = rel + "/" + name
		}
		if e.IsDir() {
			if skipDir(name) {
				continue
			}
			inner, err := listGoFiles(root, sub)
			if err != nil {
				return nil, err
			}
			out = append(out, inner...)
			continue
		}
		if strings.HasSuffix(name, ".go") {
			out = append(out, sub)
		}
	}
	return out, nil
}

// skipDir reports whether a directory is not part of the module's own code.
func skipDir(name string) bool {
	switch name {
	case "reference", "testdata", "vendor", "node_modules":
		return true
	}
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// collectImports finds the local names of the packages the rules are about,
// and reports the imports of the standard errors package (rule 1).
func (s *state) collectImports(pf *parsedFile) {
	for _, imp := range pf.file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch path {
		case "errors":
			if name != "stdErrors" {
				s.report(pf, imp.Pos(), 1, "import the standard errors package as stdErrors, or use "+errorsPath)
			}
		case errorsPath:
			pf.errName = importName(name, "errors")
		case "fmt":
			pf.fmtName = importName(name, "fmt")
		}
	}
}

// importName returns the name a file uses for an import: its alias, or the
// package name. A blank or dot import has no qualified name to look for.
func importName(alias, pkg string) string {
	switch alias {
	case "":
		return pkg
	case "_", ".":
		return ""
	}
	return alias
}

// collectConsts records the string constants of a file, and the strings of a
// test file, for the tag rule (rule 8).
func (s *state) collectConsts(pf *parsedFile) {
	ast.Inspect(pf.file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GenDecl:
			if x.Tok != token.CONST {
				return true
			}
			for _, spec := range x.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						break
					}
					s.consts[name.Name] = vs.Values[i]
					if !pf.isTest && tagName.MatchString(name.Name) {
						s.tags = append(s.tags, tagConst{pf: pf, name: name.Name, pos: name.Pos()})
					}
				}
			}
		case *ast.BasicLit:
			if pf.isTest && x.Kind == token.STRING {
				s.strs = append(s.strs, x)
			}
		case *ast.BinaryExpr:
			if pf.isTest && x.Op == token.ADD {
				s.strs = append(s.strs, x)
			}
		}
		return true
	})
}

// maxConstDepth bounds how far evalString follows a constant that is defined
// by another constant, so that a cycle (which does not compile) ends.
const maxConstDepth = 16

// evalString reads a string expression made of literals, constants and +.
// A part it cannot know is replaced by unresolved.
func (s *state) evalString(e ast.Expr) string {
	return s.eval(e, 0)
}

func (s *state) eval(e ast.Expr, depth int) string {
	if depth > maxConstDepth {
		return unresolved
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			if v, err := strconv.Unquote(x.Value); err == nil {
				return v
			}
		}
	case *ast.Ident:
		if v, ok := s.consts[x.Name]; ok {
			return s.eval(v, depth+1)
		}
	case *ast.SelectorExpr:
		if v, ok := s.consts[x.Sel.Name]; ok {
			return s.eval(v, depth+1)
		}
	case *ast.ParenExpr:
		return s.eval(x.X, depth)
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return s.eval(x.X, depth) + s.eval(x.Y, depth)
		}
	}
	return unresolved
}

// report adds a violation at a position of a file.
func (s *state) report(pf *parsedFile, pos token.Pos, rule int, text string) {
	s.reports = append(s.reports, Report{
		File: pf.rel,
		Line: s.fset.Position(pos).Line,
		Rule: rule,
		Text: text,
	})
}

// checkFile applies rules 1, 2, 5, 6 and 7 to one file.
func (s *state) checkFile(pf *parsedFile) {
	handled := map[*ast.CallExpr]bool{}
	ast.Inspect(pf.file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			s.checkCall(pf, x, handled)
		case *ast.CompositeLit:
			s.checkSentinel(pf, x)
		case *ast.FuncType:
			s.checkResults(pf, x)
		}
		return true
	})
	for _, decl := range pf.file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok {
				for _, v := range vs.Values {
					s.checkPackageVar(pf, v)
				}
			}
		}
	}
}

// pkgCall returns the name of the function when a call is pkg.Name(...) for a
// file that imports a package under the local name pkg.
func pkgCall(call *ast.CallExpr, pkg string) string {
	if pkg == "" {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != pkg {
		return ""
	}
	return sel.Sel.Name
}

// constructor returns "New", "NewErr" or "NewErrf" when a call makes an error
// with the package of the module, and "" otherwise.
func constructor(pf *parsedFile, call *ast.CallExpr) string {
	switch name := pkgCall(call, pf.errName); name {
	case "New", "NewErr", "NewErrf":
		return name
	}
	return ""
}

// checkCall applies rules 1, 2 and 5 to a call.
func (s *state) checkCall(pf *parsedFile, call *ast.CallExpr, handled map[*ast.CallExpr]bool) {
	if pkgCall(call, pf.fmtName) == "Errorf" {
		s.report(pf, call.Pos(), 1, "fmt.Errorf is not used: make errors with "+errorsPath)
	}
	if kind := constructor(pf, call); kind != "" {
		s.checkConstructor(pf, call, kind)
		return
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "SetMetadata" || handled[call] {
		return
	}
	// The outermost call of a chain of SetMetadata calls: count them down to
	// the constructor they are chained on.
	count := 0
	cur := call
	for {
		count++
		handled[cur] = true
		inner := unparen(cur.Fun.(*ast.SelectorExpr).X)
		ic, ok := inner.(*ast.CallExpr)
		if !ok {
			return // chained on a variable, not on a constructor
		}
		isel, ok := ic.Fun.(*ast.SelectorExpr)
		if ok && isel.Sel.Name == "SetMetadata" {
			cur = ic
			continue
		}
		switch constructor(pf, ic) {
		case "New":
			s.report(pf, call.Pos(), 2, "give the metadata to errors.New as key/value pairs; do not chain SetMetadata")
		case "NewErr", "NewErrf":
			if count > 1 {
				s.report(pf, call.Pos(), 2, "chain one SetMetadata call with all the key/value pairs")
			}
		}
		return
	}
}

// unparen removes the parentheses around an expression.
func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// checkConstructor applies rules 2 and 5 to a call of New, NewErr or NewErrf.
func (s *state) checkConstructor(pf *parsedFile, call *ast.CallExpr, kind string) {
	if len(call.Args) > 0 {
		switch tag := call.Args[0].(type) {
		case *ast.BasicLit, *ast.BinaryExpr, *ast.CallExpr:
			s.report(pf, tag.Pos(), 5, "the tag is a constant declared next to the code, not a literal or an expression")
		}
	}
	if kind != "New" {
		return
	}
	if len(call.Args) < 2 {
		s.report(pf, call.Pos(), 2, "errors.New takes a tag and a message")
		return
	}
	if call.Ellipsis != token.NoPos {
		return
	}
	if (len(call.Args)-2)%2 == 1 {
		s.report(pf, call.Pos(), 2, "metadata comes in key/value pairs; a key has no value")
	}
	for i := 2; i < len(call.Args); i += 2 {
		if lit, ok := call.Args[i].(*ast.BasicLit); ok && lit.Kind != token.STRING {
			s.report(pf, call.Pos(), 2, "a metadata key is a string")
		}
	}
}

// checkSentinel applies rule 5 to &errors.Error{Tag: "..."}.
func (s *state) checkSentinel(pf *parsedFile, lit *ast.CompositeLit) {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok || pf.errName == "" || sel.Sel.Name != "Error" {
		return
	}
	if id, ok := sel.X.(*ast.Ident); !ok || id.Name != pf.errName {
		return
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Tag" {
			if v, ok := kv.Value.(*ast.BasicLit); ok && v.Kind == token.STRING {
				s.report(pf, v.Pos(), 5, "the tag of a sentinel is a constant, not a literal")
			}
		}
	}
}

// checkResults applies rule 7: no function returns *errors.Error.
func (s *state) checkResults(pf *parsedFile, ft *ast.FuncType) {
	if ft.Results == nil || pf.errName == "" {
		return
	}
	for _, field := range ft.Results.List {
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Error" {
			continue
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == pf.errName {
			s.report(pf, field.Pos(), 7, "return the error interface, not *errors.Error")
		}
	}
}

// checkPackageVar applies rule 6 to the value of a package-level variable. A
// function literal is skipped: what it makes runs later, not in init.
func (s *state) checkPackageVar(pf *parsedFile, value ast.Expr) {
	ast.Inspect(value, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if constructor(pf, x) != "" {
				s.report(pf, x.Pos(), 6, "a package-level error is a struct literal &errors.Error{Tag: ...}; errors.New would give it the route of init")
			}
		}
		return true
	})
}

// checkTagRoutes applies rule 8: every tag constant is the end of a route
// that a test checks. A test checks a route with HasRoute, often with the route
// in a field of a table, so the rule accepts any string of a test file that
// ends with ".Tag", written out or made of constants. It runs after every file
// is parsed, so that a constant of any file can be read.
func (s *state) checkTagRoutes() {
	strs := make([]string, 0, len(s.strs))
	for _, e := range s.strs {
		strs = append(strs, s.evalString(e))
	}
	for _, t := range s.tags {
		value := s.evalString(s.consts[t.name])
		if strings.Contains(value, unresolved) {
			continue // not a constant string: not a tag
		}
		want := "." + value
		covered := false
		for _, str := range strs {
			if strings.HasSuffix(str, want) {
				covered = true
				break
			}
		}
		if !covered {
			s.report(t.pf, t.pos, 8, fmt.Sprintf("tag %q (%s) has no route test: no string in a test ends with %q", value, t.name, want))
		}
	}
}

const (
	tagListDirFailed = "ListDirFailed"
	tagParseFailed   = "ParseFailed"
)

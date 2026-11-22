// SPDX-License-Identifier: GPL-2.0-only

package openvpn

import (
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryExportedIdentifierHasADocComment walks the packages of the module (not
// reference/, which is OpenVPN's own source) and fails for each exported type,
// function, method, constant and variable without a doc comment, and for each
// exported field of an exported struct of the packages that users import.
func TestEveryExportedIdentifierHasADocComment(t *testing.T) {
	var dirs []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		switch name := d.Name(); {
		case path != "." && (name == "reference" || name == "testdata" || name == "third_party" || strings.HasPrefix(name, ".")):
			return filepath.SkipDir
		}
		dirs = append(dirs, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, dir := range dirs {
		fset := token.NewFileSet()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		byPackage := map[string][]*ast.File{}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("%s: %v", dir, err)
			}
			byPackage[f.Name.Name] = append(byPackage[f.Name.Name], f)
		}
		for name, files := range byPackage {
			if name == "main" {
				continue
			}
			p, err := doc.NewFromFiles(fset, files, dir, doc.AllDecls)
			if err != nil {
				t.Fatal(err)
			}
			public := !strings.Contains(filepath.ToSlash(dir), "internal")
			missing := func(kind, ident string) {
				t.Errorf("%s: %s %s has no doc comment", dir, kind, ident)
			}
			values := func(vs []*doc.Value) {
				for _, v := range vs {
					exported := false
					for _, n := range v.Names {
						exported = exported || ast.IsExported(n)
					}
					if exported && strings.TrimSpace(v.Doc) == "" && !specsDocumented(v.Decl) {
						missing("value", strings.Join(v.Names, ", "))
					}
				}
			}
			funcs := func(fs []*doc.Func, recv string) {
				for _, f := range fs {
					if ast.IsExported(f.Name) && strings.TrimSpace(f.Doc) == "" {
						missing("func", recv+f.Name)
					}
				}
			}
			values(p.Consts)
			values(p.Vars)
			funcs(p.Funcs, "")
			for _, ty := range p.Types {
				if !ast.IsExported(ty.Name) {
					continue
				}
				checked++
				if strings.TrimSpace(ty.Doc) == "" {
					missing("type", ty.Name)
				}
				values(ty.Consts)
				values(ty.Vars)
				funcs(ty.Funcs, "")
				funcs(ty.Methods, ty.Name+".")
				if public {
					checkFields(t, dir, ty)
				}
			}
		}
	}
	if checked < 10 {
		t.Fatalf("only %d exported types looked at: the walk is wrong", checked)
	}
}

// specsDocumented reports whether every exported name of a const or var block has a
// comment of its own (a doc comment above it, or a line comment after it), as the
// tag constants of a block do.
func specsDocumented(d *ast.GenDecl) bool {
	for _, spec := range d.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			return false
		}
		exported := false
		for _, n := range vs.Names {
			exported = exported || n.IsExported()
		}
		if exported && vs.Doc == nil && vs.Comment == nil {
			return false
		}
	}
	return true
}

func checkFields(t *testing.T, dir string, ty *doc.Type) {
	t.Helper()
	spec, ok := ty.Decl.Specs[0].(*ast.TypeSpec)
	if !ok {
		return
	}
	st, ok := spec.Type.(*ast.StructType)
	if !ok {
		return
	}
	for _, f := range st.Fields.List {
		for _, n := range f.Names {
			if n.IsExported() && f.Doc == nil && f.Comment == nil {
				t.Errorf("%s: field %s.%s has no comment", dir, ty.Name, n.Name)
			}
		}
	}
}

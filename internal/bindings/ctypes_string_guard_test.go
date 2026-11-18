// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package bindings

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// stringBytesName is the name of the function that returns a view. It is a
// constant, so that this file does not use the identifier itself.
const stringBytesName = "stringBytes"

// stringBytesUseProblems is a source-use guard. It finds each use of the
// identifier stringBytes in files. Only 2 uses are permitted:
//
//   - the declaration of the (*WAFObject).stringBytes method;
//   - 1 direct call recv.stringBytes() in the body of the
//     (*WAFObject).StringValue method, where recv is the receiver of
//     StringValue, not inside a function literal, and where the body of
//     StringValue does not declare the name recv again.
//
// All other uses are problems: other calls, method values, method expressions,
// package-level variables, and uses in function literals.
//
// This is a source-use guard, not a lifetime proof. It limits where the view
// can come from. It does not check what StringValue does with the view: the
// copy tests check that.
func stringBytesUseProblems(fset *token.FileSet, files []*ast.File) []string {
	permitted := map[*ast.Ident]bool{}
	declarations, calls := 0, 0
	for _, file := range files {
		for _, decl := range file.Decls {
			d, c := permitStringBytesUses(decl, permitted)
			declarations += d
			calls += c
		}
	}

	problems := unpermittedStringBytesUses(fset, files, permitted)
	if declarations != 1 {
		problems = append(problems, fmt.Sprintf("found %d declarations of (*WAFObject).%s, want 1", declarations, stringBytesName))
	}
	if calls != 1 {
		problems = append(problems, fmt.Sprintf("found %d direct calls in (*WAFObject).StringValue, want 1", calls))
	}
	return problems
}

// permitStringBytesUses adds the permitted uses in decl to permitted. It
// returns the number of declarations and of direct calls that it found.
func permitStringBytesUses(decl ast.Decl, permitted map[*ast.Ident]bool) (declarations, calls int) {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || !isWAFObjectPointerMethod(fn) {
		return 0, 0
	}
	switch fn.Name.Name {
	case stringBytesName:
		permitted[fn.Name] = true
		return 1, 0
	case "StringValue":
		sels := directReceiverCalls(fn)
		for _, sel := range sels {
			permitted[sel] = true
		}
		return 0, len(sels)
	default:
		return 0, 0
	}
}

// directReceiverCalls returns the selector identifiers of the calls
// recv.stringBytes() in the body of fn, outside function literals. It returns
// nil when the body declares the name of the receiver again, because then the
// name in a call can refer to another variable.
func directReceiverCalls(fn *ast.FuncDecl) []*ast.Ident {
	recv := fn.Recv.List[0].Names
	if len(recv) != 1 || fn.Body == nil || declaresName(fn.Body, recv[0].Name) {
		return nil
	}
	var sels []*ast.Ident
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		if sel := directReceiverCall(n, recv[0].Name); sel != nil {
			sels = append(sels, sel)
		}
		return true
	})
	return sels
}

// declaresName reports whether the syntax tree under root declares name again,
// at any depth and in any form. The forms are: short variable declarations
// (this includes the binding of a type switch and of a select case), range
// variables, var, const and type declarations, the type parameters of generic
// types, and the parameters and results of function literals.
func declaresName(root ast.Node, name string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		for _, id := range declaredIdents(n) {
			found = found || id.Name == name
		}
		return !found
	})
	return found
}

// declaredIdents returns the identifiers that node n declares.
func declaredIdents(n ast.Node) []*ast.Ident {
	switch d := n.(type) {
	case *ast.AssignStmt:
		return definedIdents(d.Tok, d.Lhs...)
	case *ast.RangeStmt:
		return definedIdents(d.Tok, d.Key, d.Value)
	case *ast.ValueSpec:
		return d.Names
	case *ast.TypeSpec:
		return append([]*ast.Ident{d.Name}, fieldNames(d.TypeParams)...)
	case *ast.FuncType:
		return fieldNames(d.TypeParams, d.Params, d.Results)
	}
	return nil
}

// definedIdents returns the identifiers among exprs when tok is the := token.
// With another token, the statement assigns to existing variables.
func definedIdents(tok token.Token, exprs ...ast.Expr) []*ast.Ident {
	if tok != token.DEFINE {
		return nil
	}
	return identsOf(exprs...)
}

// identsOf returns the expressions that are plain identifiers.
func identsOf(exprs ...ast.Expr) []*ast.Ident {
	var ids []*ast.Ident
	for _, e := range exprs {
		if id, ok := e.(*ast.Ident); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// fieldNames returns the names of the fields in lists. A list can be nil.
func fieldNames(lists ...*ast.FieldList) []*ast.Ident {
	var ids []*ast.Ident
	for _, list := range lists {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			ids = append(ids, field.Names...)
		}
	}
	return ids
}

// unpermittedStringBytesUses returns a problem for each identifier
// stringBytes in files that is not in permitted.
func unpermittedStringBytesUses(fset *token.FileSet, files []*ast.File, permitted map[*ast.Ident]bool) []string {
	var problems []string
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == stringBytesName && !permitted[id] {
				problems = append(problems, fmt.Sprintf("%s: use of %s that is not permitted", fset.Position(id.Pos()), stringBytesName))
			}
			return true
		})
	}
	return problems
}

// isWAFObjectPointerMethod reports whether fn is a method with a *WAFObject receiver.
func isWAFObjectPointerMethod(fn *ast.FuncDecl) bool {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return false
	}
	star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := star.X.(*ast.Ident)
	return ok && id.Name == "WAFObject"
}

// directReceiverCall returns the selector identifier when n is the call
// recv.stringBytes() with no arguments. Otherwise it returns nil.
func directReceiverCall(n ast.Node, recv string) *ast.Ident {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != stringBytesName {
		return nil
	}
	x, ok := sel.X.(*ast.Ident)
	if !ok || x.Name != recv {
		return nil
	}
	return sel.Sel
}

// parseSources parses Go sources. The parser does not apply build
// constraints, so files with any build tag are included.
func parseSources(t *testing.T, fset *token.FileSet, sources map[string]string) []*ast.File {
	t.Helper()
	files := make([]*ast.File, 0, len(sources))
	for name, src := range sources {
		file, err := parser.ParseFile(fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
		require.NoError(t, err, name)
		files = append(files, file)
	}
	return files
}

// TestStringBytesSourceUse runs the source-use guard on all the Go files of
// this package, test files and files with build tags included.
func TestStringBytesSourceUse(t *testing.T) {
	names, err := filepath.Glob("*.go")
	require.NoError(t, err)
	sources := make(map[string]string, len(names))
	for _, name := range names {
		src, err := os.ReadFile(name)
		require.NoError(t, err)
		sources[name] = string(src)
	}

	fset := token.NewFileSet()
	require.Empty(t, stringBytesUseProblems(fset, parseSources(t, fset, sources)))
}

// linknameDirective is the prefix of the name of each linkname directive.
const linknameDirective = "//go:linkname"

// stringBytesLinknameProblems returns a problem for each real //go:linkname
// directive in files that names stringBytes. It reads the comments of the
// syntax tree, so doc text and string literals that look like a directive do
// not count. A directive can make a name in any package refer to the method,
// so this check also covers the files of this package.
func stringBytesLinknameProblems(fset *token.FileSet, files []*ast.File) []string {
	var problems []string
	for _, file := range files {
		for _, group := range file.Comments {
			for _, c := range group.List {
				if isStringBytesLinkname(c.Text) {
					problems = append(problems, fmt.Sprintf("%s: %s names %s", fset.Position(c.Pos()), strings.Fields(c.Text)[0], stringBytesName))
				}
			}
		}
	}
	return problems
}

// isStringBytesLinkname reports whether the comment text is a //go:linkname
// directive with an argument that has the name stringBytes.
func isStringBytesLinkname(text string) bool {
	return slices.ContainsFunc(linknameArgs(text), namesStringBytes)
}

// linknameArgs returns the arguments of a linkname directive: a directive
// whose name starts with "go:linkname". It returns nil when the text is not
// such a directive. This covers //go:linkname, //go:linknamestd and any
// variant that the compiler can add: the directive name is the first word of
// the comment, and the comment starts with "//" with no space.
func linknameArgs(text string) []string {
	words := strings.Fields(text)
	if len(words) == 0 || !strings.HasPrefix(words[0], linknameDirective) {
		return nil
	}
	return words[1:]
}

// namesStringBytes reports whether a //go:linkname argument is the name
// stringBytes, or ends with ".stringBytes" (the target of a method).
func namesStringBytes(arg string) bool {
	return arg == stringBytesName || strings.HasSuffix(arg, "."+stringBytesName)
}

// moduleGoFiles returns the paths of all the .go files of the main module,
// test files included, whatever their build tags. It skips hidden
// directories and the directories of other modules.
func moduleGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); path != root && statErr == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			paths = append(paths, path)
		}
		return nil
	})
	require.NoError(t, err)
	return paths
}

// TestStringBytesNoLinkname checks that no file of the module has a
// //go:linkname directive that names stringBytes. The compiler already rejects
// all other references from another package. It does not reject a linkname
// directive, and the directive also works inside this package. This check
// reads the comments of all the packages, this one and its test files
// included.
func TestStringBytesNoLinkname(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)

	fset := token.NewFileSet()
	var files []*ast.File
	for _, path := range moduleGoFiles(t, root) {
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		require.NoError(t, err, path)
		files = append(files, file)
	}
	require.NotEmpty(t, files)
	require.Empty(t, stringBytesLinknameProblems(fset, files))
}

// TestStringBytesLinknameFixtures checks that the linkname check finds a real
// directive in each form, and does not count text that only looks like one.
func TestStringBytesLinknameFixtures(t *testing.T) {
	const prefix = "package p\n\nimport _ \"unsafe\"\n\n"
	rejected := map[string]string{
		"same-package method target":  prefix + "//go:linkname x github.com/DataDog/go-libddwaf/v5/internal/bindings.(*WAFObject).stringBytes\nfunc x()\n",
		"other-package method target": prefix + "//go:linkname view github.com/DataDog/go-libddwaf/v5/internal/bindings.(*WAFObject).stringBytes\nfunc view()\n",
		"local name":                  prefix + "//go:linkname stringBytes some/pkg.name\nfunc stringBytes()\n",
		"target with a plain name":    prefix + "//go:linkname x some/pkg.stringBytes\nfunc x()\n",
		"directive with a tab":        prefix + "//go:linkname\tx some/pkg.stringBytes\nfunc x()\n",
		"linknamestd directive":       prefix + "//go:linknamestd x github.com/DataDog/go-libddwaf/v5/internal/bindings.(*WAFObject).stringBytes\nfunc x()\n",
		"linknamestd with local name": prefix + "//go:linknamestd stringBytes some/pkg.name\nfunc stringBytes()\n",
		"future linkname variant":     prefix + "//go:linknamefuture x some/pkg.stringBytes\nfunc x()\n",
		"directive inside a func":     prefix + "func f() {\n\t//go:linkname x some/pkg.stringBytes\n}\n",
	}
	for name, src := range rejected {
		t.Run("rejected/"+name, func(t *testing.T) {
			fset := token.NewFileSet()
			files := parseSources(t, fset, map[string]string{"fixture.go": src})
			require.NotEmpty(t, stringBytesLinknameProblems(fset, files))
		})
	}

	accepted := map[string]string{
		"doc text":                   "// Do not use go:linkname with stringBytes.\npackage p\n",
		"doc text with a directive":  "// Text that quotes //go:linkname x some/pkg.stringBytes in a sentence.\npackage p\n",
		"directive with a space":     prefix + "// go:linkname x some/pkg.stringBytes\nfunc x()\n",
		"block comment":              prefix + "/* //go:linkname x some/pkg.stringBytes */\nfunc x()\n",
		"string literal":             prefix + "var s = \"//go:linkname x some/pkg.stringBytes\"\n",
		"raw string literal":         prefix + "var s = `\n//go:linkname x some/pkg.stringBytes\n`\n",
		"linknamestd, other name":    prefix + "//go:linknamestd x some/pkg.other\nfunc x()\n",
		"other directive":            prefix + "//go:noinline stringBytes\nfunc x()\n",
		"directive for another name": prefix + "//go:linkname x some/pkg.other\nfunc x()\n",
		"name with a prefix":         prefix + "//go:linkname x some/pkg.myStringBytes\nfunc x()\n",
	}
	for name, src := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			fset := token.NewFileSet()
			files := parseSources(t, fset, map[string]string{"fixture.go": src})
			require.Empty(t, stringBytesLinknameProblems(fset, files))
		})
	}
}

const stringBytesFixtureDecl = `package bindings

type WAFObject struct{ data [16]byte }

func (w *WAFObject) stringBytes() ([]byte, error) { return w.data[:], nil }
`

const stringBytesFixtureStringValue = `package bindings

func (w *WAFObject) StringValue() (string, error) {
	b, err := w.stringBytes()
	return string(b), err
}
`

// TestStringBytesSourceUseFixtures checks that the guard accepts the permitted
// shape, and rejects each other kind of use.
func TestStringBytesSourceUseFixtures(t *testing.T) {
	t.Run("permitted", func(t *testing.T) {
		fset := token.NewFileSet()
		files := parseSources(t, fset, map[string]string{"decl.go": stringBytesFixtureDecl, "value.go": stringBytesFixtureStringValue})
		require.Empty(t, stringBytesUseProblems(fset, files))
	})

	rejected := []struct {
		name  string
		extra string
	}{
		{"package-level method expression", `package bindings

var view = (*WAFObject).stringBytes
var kept []byte

func keepBytes(w *WAFObject) { kept, _ = view(w) }
`},
		{"package-level method value", `package bindings

var obj WAFObject
var view = obj.stringBytes
`},
		{"method value in a function", `package bindings

func keep(w *WAFObject) func() ([]byte, error) { return w.stringBytes }
`},
		{"call in another function", `package bindings

func length(w *WAFObject) int { b, _ := w.stringBytes(); return len(b) }
`},
		{"call in a function literal", `package bindings

var f = func(w *WAFObject) []byte { b, _ := w.stringBytes(); return b }
`},
		{"StringValue on another receiver", `package bindings

type other struct{ w *WAFObject }

func (o *other) StringValue() (string, error) {
	b, err := o.w.stringBytes()
	return string(b), err
}
`},
		{"file excluded by a build tag", `//go:build ignore

package bindings

func length(w *WAFObject) int { b, _ := w.stringBytes(); return len(b) }
`},
		{"declaration on another type", `package bindings

type other struct{}

func (o *other) stringBytes() ([]byte, error) { return nil, nil }
`},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			files := parseSources(t, fset, map[string]string{"decl.go": stringBytesFixtureDecl, "value.go": stringBytesFixtureStringValue, "extra.go": tc.extra})
			require.NotEmpty(t, stringBytesUseProblems(fset, files))
		})
	}

	// Changes to StringValue itself.
	for _, tc := range []struct{ name, value string }{
		{"second call in StringValue", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	_, _ = w.stringBytes()
	b, err := w.stringBytes()
	return string(b), err
}
`},
		{"call in a function literal in StringValue", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	get := func() ([]byte, error) { return w.stringBytes() }
	b, err := get()
	return string(b), err
}
`},
		{"receiver redeclared with := in a block", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	if other != nil {
		w := other
		b, err := w.stringBytes()
		return string(b), err
	}
	return "", nil
}
`},
		{"receiver redeclared with var", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	var w *WAFObject = other
	b, err := w.stringBytes()
	return string(b), err
}
`},
		{"receiver redeclared with var in a block", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	{
		var w = other
		_ = w
	}
	b, err := w.stringBytes()
	return string(b), err
}
`},
		{"receiver redeclared as a range variable", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	for _, w := range others {
		b, err := w.stringBytes()
		return string(b), err
	}
	return "", nil
}
`},
		{"receiver redeclared as a range key", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	for w := range others {
		_ = w
	}
	b, err := w.stringBytes()
	return string(b), err
}
`},
		{"receiver redeclared in a type switch", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	switch w := any(other).(type) {
	case *WAFObject:
		b, err := w.stringBytes()
		return string(b), err
	}
	return "", nil
}
`},
		{"receiver redeclared as a parameter of a function literal", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	_ = func(w *WAFObject) {}
	b, err := w.stringBytes()
	return string(b), err
}
`},
		{"receiver redeclared as a result of a function literal", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	_ = func() (w *WAFObject) { return }
	b, err := w.stringBytes()
	return string(b), err
}
`},
		{"receiver redeclared with a select case", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	select {
	case w := <-objects:
		b, err := w.stringBytes()
		return string(b), err
	}
}
`},
		{"receiver redeclared as a type parameter", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	type local[w any] []w
	b, err := w.stringBytes()
	return string(b), err
}
`},
		{"receiver redeclared as a type parameter in a function literal", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	_ = func() {
		type local[K comparable, w any] map[K]w
	}
	b, err := w.stringBytes()
	return string(b), err
}
`},
		{"receiver redeclared as a type", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	type w struct{}
	b, err := w.stringBytes()
	return string(b), err
}
`},
		{"method value in StringValue", `package bindings

func (w *WAFObject) StringValue() (string, error) {
	get := w.stringBytes
	b, err := get()
	return string(b), err
}
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			files := parseSources(t, fset, map[string]string{"decl.go": stringBytesFixtureDecl, "value.go": tc.value})
			require.NotEmpty(t, stringBytesUseProblems(fset, files))
		})
	}
}

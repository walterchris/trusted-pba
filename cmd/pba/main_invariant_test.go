//go:build !tamago

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestVerifyAndLoadVerifiedBufferInvariant structurally enforces the #46
// verified-buffer contract on the tamago-only main.go (which a host test cannot
// import, so it is checked at the AST level): inside verifyAndLoad, a single
// path identifier — the function's sole parameter — must feed the file read and
// the firmware device path, the exact buffer returned by that read must be the
// one verified and handed to LoadImageBuffer, and no LoadImage call (which
// would re-read the file and reopen the verify-then-load window) may remain.
func TestVerifyAndLoadVerifiedBufferInvariant(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "verifyAndLoad" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("verifyAndLoad not found in main.go")
	}

	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 {
		t.Fatal("verifyAndLoad must take exactly one path parameter")
	}
	path := params[0].Names[0].Name

	var (
		readPath, readBuf string // <readBuf>, err := fs.ReadFile(root, <readPath>)
		verifyBuf         string // store.Verifier().Verify(<verifyBuf>)
		loadPath, loadBuf string // LoadImageBuffer(root, <loadPath>, <loadBuf>)
		sawLoadImage      bool
	)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Rhs) != 1 || len(node.Lhs) < 1 {
				return true
			}
			call, ok := node.Rhs[0].(*ast.CallExpr)
			if !ok || calleeName(call) != "ReadFile" || len(call.Args) != 2 {
				return true
			}
			readBuf = identName(node.Lhs[0])
			readPath = identName(call.Args[1])
		case *ast.CallExpr:
			switch calleeName(node) {
			case "Verify":
				if len(node.Args) == 1 {
					verifyBuf = identName(node.Args[0])
				}
			case "LoadImageBuffer":
				if len(node.Args) == 3 {
					loadPath = identName(node.Args[1])
					loadBuf = identName(node.Args[2])
				}
			case "LoadImage":
				sawLoadImage = true
			}
		}
		return true
	})

	if sawLoadImage {
		t.Error("verifyAndLoad calls LoadImage: it re-reads the file and breaks the verified-buffer invariant; use LoadImageBuffer")
	}
	if readBuf == "" || readPath == "" {
		t.Fatal("verifyAndLoad must read the image via fs.ReadFile(root, <path>)")
	}
	if loadBuf == "" || loadPath == "" {
		t.Fatal("verifyAndLoad must load via LoadImageBuffer(root, <path>, <buffer>)")
	}
	if readPath != path {
		t.Errorf("fs.ReadFile path is %q, want the function parameter %q", readPath, path)
	}
	if loadPath != path {
		t.Errorf("LoadImageBuffer path is %q, want the function parameter %q", loadPath, path)
	}
	if verifyBuf != readBuf {
		t.Errorf("Verify is given %q, want the read buffer %q", verifyBuf, readBuf)
	}
	if loadBuf != readBuf {
		t.Errorf("LoadImageBuffer is given buffer %q, want the verified read buffer %q", loadBuf, readBuf)
	}
}

// calleeName returns the method/function name a call expression invokes,
// e.g. "ReadFile" for fs.ReadFile(...) and "Verify" for store.Verifier().Verify(...).
func calleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name
	case *ast.Ident:
		return fun.Name
	}
	return ""
}

// identName returns the identifier name of e, or "" if e is not a plain identifier.
func identName(e ast.Expr) string {
	id, ok := e.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

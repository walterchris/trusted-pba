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
// the firmware device path; the image must be read exactly once via fs.ReadFile,
// in source order strictly before Verify, which is strictly before
// LoadImageBuffer; the exact buffer returned by that read must be the one
// verified and handed to LoadImageBuffer, never reassigned after the read; and
// no LoadImage call (which would re-read the file and reopen the
// verify-then-load window) may remain.
func TestVerifyAndLoadVerifiedBufferInvariant(t *testing.T) {
	t.Parallel()

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
		return
	}

	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 {
		t.Fatal("verifyAndLoad must take exactly one path parameter")
	}
	path := params[0].Names[0].Name

	var (
		readFileCalls     int             // every ReadFile call, assignment or not
		readAssign        *ast.AssignStmt // <readBuf>, err := fs.ReadFile(root, <readPath>)
		readPos           token.Pos
		readPath, readBuf string
		verifyPos         token.Pos
		verifyBuf         string // store.Verifier().Verify(<verifyBuf>)
		loadPos           token.Pos
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
			if !ok || !isCallTo(call, "fs", "ReadFile") || len(call.Args) != 2 {
				return true
			}
			readAssign = node
			readPos = node.Pos()
			readBuf = identName(node.Lhs[0])
			readPath = identName(call.Args[1])
		case *ast.CallExpr:
			switch {
			case isCallTo(node, "fs", "ReadFile"):
				readFileCalls++
			case calleeName(node) == "Verify":
				if len(node.Args) == 1 {
					verifyPos = node.Pos()
					verifyBuf = identName(node.Args[0])
				}
			case calleeName(node) == "LoadImageBuffer":
				if len(node.Args) == 3 {
					loadPos = node.Pos()
					loadPath = identName(node.Args[1])
					loadBuf = identName(node.Args[2])
				}
			case calleeName(node) == "LoadImage":
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
	if readFileCalls != 1 {
		t.Fatalf("verifyAndLoad contains %d ReadFile calls, want exactly 1: a re-read after Verify would execute unverified bytes", readFileCalls)
	}
	if verifyBuf == "" {
		t.Fatal("verifyAndLoad must verify the image via Verify(<buffer>)")
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

	// Source order must be read, then verify, then load: verifying after the
	// load (or loading before the verify) reopens the verify-then-load window.
	if readPos >= verifyPos || verifyPos >= loadPos {
		t.Errorf("source order must be fs.ReadFile (%v) < Verify (%v) < LoadImageBuffer (%v)",
			fset.Position(readPos), fset.Position(verifyPos), fset.Position(loadPos))
	}

	// The read buffer must never be written again after the initial read: any
	// reassignment could swap in unverified bytes between Verify and load.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign == readAssign {
			return true
		}
		for _, lhs := range assign.Lhs {
			if identName(lhs) == readBuf && assign.Pos() > readPos {
				t.Errorf("%v: %q is reassigned after the initial fs.ReadFile; the verified buffer must stay immutable until LoadImageBuffer",
					fset.Position(assign.Pos()), readBuf)
			}
		}
		return true
	})
}

// isCallTo reports whether call is `<pkg>.<method>(...)` with pkg a plain
// identifier — e.g. isCallTo(call, "fs", "ReadFile"). A host AST test cannot
// import the tamago build to resolve types, so this pins the leaf selector and
// its immediate receiver, which defeats a shadowed-name decoy (a local ReadFile);
// deeper decoys are bounded by the QEMU reject matrix as the behavioral backstop.
func isCallTo(call *ast.CallExpr, pkg, method string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return false
	}
	return identName(sel.X) == pkg
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

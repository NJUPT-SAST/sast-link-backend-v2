package session

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// Error messages must be written in Chinese to match the rest of the project's
// text. These strings do not reach clients — the handler rebuilds the response
// message from Kind and Code — but they are what operators read in logs, so a
// mixed-language log is the actual cost of letting English strings back in.
//
// This scans the package source rather than exercising every call site: there
// are ~90 constructions across the service, and enumerating them in a test would
// leave new ones unguarded.
func TestErrorMessagesAreChinese(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	fileSet := token.NewFileSet()
	checked := 0
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fileSet, source, nil, 0)
		if parseErr != nil {
			t.Fatalf("ParseFile(%q) error = %v", source, parseErr)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			index, name := messageArgument(call)
			if index < 0 || index >= len(call.Args) {
				return true
			}
			literal, ok := call.Args[index].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			message, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil || strings.TrimSpace(message) == "" {
				return true
			}
			checked++
			if !containsHan(message) {
				position := fileSet.Position(literal.Pos())
				t.Errorf("%s:%d: %s message %q is not Chinese", source, position.Line, name, message)
			}
			return true
		})
	}
	// Guard the guard: a broken matcher would silently pass.
	if checked < 50 {
		t.Fatalf("checked only %d messages, expected the scan to reach the whole service", checked)
	}
}

// messageArgument returns the index of the human-readable message argument for
// the error constructors used in this package, plus a label for diagnostics.
func messageArgument(call *ast.CallExpr) (int, string) {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		if function.Name == "newError" {
			return 1, "newError"
		}
	case *ast.SelectorExpr:
		if function.Sel.Name == "failLogin" {
			// failLogin(ctx, user, input, failureKey, sentinel, message, cause)
			return 5, "failLogin"
		}
	}
	return -1, ""
}

func containsHan(value string) bool {
	for _, symbol := range value {
		if unicode.Is(unicode.Han, symbol) {
			return true
		}
	}
	return false
}

package llm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoDirectProviderCompleteOutsideLLM pins M75: code outside this
// package calls llm.Complete, never Provider.Complete directly, so an answer
// the provider reports as cut at its token limit, filtered or unfinished can
// never be used as a draft, summary or verdict by a caller that forgot to
// check the finish reason. Any selector named Complete (call or method
// value) outside
// internal/service/llm (tests excluded) fails this test; a legitimate
// non-LLM Complete method elsewhere can be allow-listed here with a reason.
const llmImportPath = "github.com/sbomhub/sbomhub/internal/service/llm"

func TestNoDirectProviderCompleteOutsideLLM(t *testing.T) {
	root, err := filepath.Abs("../../..") // apps/api
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == self || d.Name() == "vendor" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		// The local name of the llm package in this file ("" if not
		// imported). Codex R2 Low: an identifier merely named llm is not
		// the package, and a method value (f := p.Complete) is a use too,
		// so every selector named Complete is checked, called or not.
		llmName := ""
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == llmImportPath {
				llmName = "llm"
				if imp.Name != nil {
					llmName = imp.Name.Name
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Complete" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && llmName != "" && id.Name == llmName && id.Obj == nil {
				return true // the checked package function (an unresolved, i.e. package, identifier)
			}
			offenders = append(offenders, fset.Position(sel.Pos()).String())
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("direct Provider.Complete calls outside internal/service/llm (use llm.Complete): %v", offenders)
	}
}

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// govulncheck reports GO-2026-6875 and GO-2026-6872 against every
// github.com/labstack/echo/v4 version, v4.16.3 included, with no fixed
// version and no symbol list for v4 (the Go vuln DB entry is module-wide for
// v4, so every echo call is reported as a "trace"). The upstream advisories
// (GHSA-99jh-6h7p-pp36 / GHSA-246p-cpwv-v3jq) put v4 at <= 4.16.2 and the
// v4.16.3 changelog lists both fixes. They concern exactly two features:
//
//   - GO-2026-6875: middleware.Proxy / ProxyWithConfig forwarding a
//     client-supplied X-Real-IP upstream when Echo#IPExtractor is unset.
//   - GO-2026-6872: middleware.RateLimiter's default identifier, c.RealIP(),
//     trusting a client-supplied X-Forwarded-For when Echo#IPExtractor is
//     unset.
//
// SBOMHub uses neither middleware (its rate limits are Redis-backed, keyed by
// API key / public-link token / c.RealIP() with an explicit IPExtractor), and
// always sets Echo#IPExtractor (appmw.ClientIPExtractor). This test keeps the
// first half of that true, so the "not affected" conclusion cannot rot when
// someone reaches for echo's built-in proxy or limiter.
func TestEchoAdvisoryGuard_NoEchoProxyOrRateLimiter(t *testing.T) {
	forbidden := map[string]bool{
		"Proxy":                               true,
		"ProxyWithConfig":                     true,
		"ProxyConfig":                         true,
		"RateLimiter":                         true,
		"RateLimiterWithConfig":               true,
		"RateLimiterConfig":                   true,
		"DefaultRateLimiterConfig":            true,
		"NewRateLimiterMemoryStore":           true,
		"NewRateLimiterMemoryStoreWithConfig": true,
	}
	const echoMW = "github.com/labstack/echo/v4/middleware"

	root := filepath.Join("..", "..") // apps/api
	var scanned int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "testdata" || (strings.HasPrefix(name, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		scanned++
		local := ""
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p != echoMW {
				continue
			}
			local = "middleware"
			if imp.Name != nil {
				local = imp.Name.Name
			}
		}
		if local == "" {
			return nil
		}
		if local == "." {
			t.Errorf("%s dot-imports %s; the guard cannot see its symbols", path, echoMW)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && forbidden[sel.Sel.Name] {
				t.Errorf("%s: uses echo %s.%s — see GO-2026-6875 / GO-2026-6872 and this test's comment before adding it",
					fset.Position(sel.Pos()), local, sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 50 {
		t.Fatalf("scanned only %d files; the walk root is wrong", scanned)
	}
}

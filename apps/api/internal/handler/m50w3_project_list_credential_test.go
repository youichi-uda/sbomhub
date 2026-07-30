// Package handler — M50 W3: the project-list narrowing decision, tested without
// a database so that it runs in the DEFAULT `go test ./...` suite.
//
// # Why this file exists (Codex R2, Medium)
//
// The behavioural proof that the two project-list routes narrow for a
// project-scoped key lives in m50w3_project_list_scope_integration_test.go,
// behind `//go:build integration`. Neither CI workflow runs it:
// .github/workflows/go-test.yml runs `go test -race ./...` (build tag excluded),
// and .github/workflows/rls-integration.yml runs the tagged suite for
// ./internal/repository/..., ./internal/middleware/... and ./internal/service/...
// only — not ./internal/handler/... . So `listProjectsForCredential` could have
// been changed to always call listTenant and every CI job would still have been
// green. (That gap predates this wave: the M47 W1 and M50 W2 handler-scope
// integration tests are in the same unrun package. Widening the workflow is out
// of this wave's file scope and is reported instead.)
//
// The decision itself needs no database: listProjectsForCredential takes the two
// lookups as function values, so the branch can be driven directly and the
// stubs record which one was called with what. That is the whole security
// decision — "narrow only when the credential is a project-scoped API key" — and
// it now runs on every push.
//
// What this file does NOT prove: that the narrowed lookup returns the right row
// (that is the integration file's job, and internal/service's), nor that the
// middleware admits the routes (internal/middleware's).
package handler

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
)

// m50w3Spy records which of the two lookups listProjectsForCredential chose.
type m50w3Spy struct {
	tenantCalls     int
	keyProjectCalls int
	sawTenantID     uuid.UUID
	sawKeyProjectID uuid.UUID
}

func (s *m50w3Spy) listTenant(_ context.Context, tenantID uuid.UUID) ([]model.Project, error) {
	s.tenantCalls++
	s.sawTenantID = tenantID
	return []model.Project{{ID: uuid.New(), Name: "tenant-wide-a"}, {ID: uuid.New(), Name: "tenant-wide-b"}}, nil
}

func (s *m50w3Spy) listKeyProject(_ context.Context, tenantID, keyProjectID uuid.UUID) ([]model.Project, error) {
	s.keyProjectCalls++
	s.sawTenantID = tenantID
	s.sawKeyProjectID = keyProjectID
	return []model.Project{{ID: keyProjectID, Name: "narrowed"}}, nil
}

// m50w3CtxWithKey builds the echo context each credential produces, using the
// same context key the production middlewares set.
func m50w3CtxWithKey(key *model.APIKey) echo.Context {
	e := echo.New()
	c := e.NewContext(httptest.NewRequest("GET", "/api/v1/cli/projects", nil), httptest.NewRecorder())
	if key != nil {
		c.Set(middleware.ContextKeyAPI, key)
	}
	return c
}

// TestM50W3ListProjectsForCredentialPicksTheRightLookup is the decision table.
func TestM50W3ListProjectsForCredentialPicksTheRightLookup(t *testing.T) {
	tenantID := uuid.New()
	keyProjectID := uuid.New()

	for _, tc := range []struct {
		name        string
		key         *model.APIKey
		wantNarrow  bool
		description string
	}{
		{
			name:        "no API-key credential (Clerk session / self-hosted default)",
			key:         nil,
			wantNarrow:  false,
			description: "this is the web UI's GET /api/v1/projects; narrowing it would empty the project list",
		},
		{
			name:       "tenant-level API key (project_id IS NULL)",
			key:        &model.APIKey{ID: uuid.New(), TenantID: tenantID, Permissions: "write"},
			wantNarrow: false,
			description: "the pre-M50 W2 shape of every key; it must be untouched. (How " +
				"common it is in the field is not something the code can guarantee; " +
				"the dev database held 96 of these and 0 project-scoped on 2026-07-30)",
		},
		{
			name:        "project-scoped API key",
			key:         &model.APIKey{ID: uuid.New(), TenantID: tenantID, ProjectID: &keyProjectID, Permissions: "write"},
			wantNarrow:  true,
			description: "the only case that narrows",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &m50w3Spy{}
			got, err := listProjectsForCredential(
				m50w3CtxWithKey(tc.key), tenantID, spy.listTenant, spy.listKeyProject)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantNarrow {
				if spy.keyProjectCalls != 1 || spy.tenantCalls != 0 {
					t.Fatalf("%s: chose tenantCalls=%d keyProjectCalls=%d, want the narrowed "+
						"lookup exactly once (%s)",
						tc.name, spy.tenantCalls, spy.keyProjectCalls, tc.description)
				}
				if spy.sawKeyProjectID != keyProjectID {
					t.Errorf("narrowed to project %s, want the key's %s",
						spy.sawKeyProjectID, keyProjectID)
				}
				if len(got) != 1 || got[0].ID != keyProjectID {
					t.Errorf("returned %+v, want exactly the key's project", got)
				}
			} else {
				if spy.tenantCalls != 1 || spy.keyProjectCalls != 0 {
					t.Fatalf("%s: chose tenantCalls=%d keyProjectCalls=%d, want the tenant-wide "+
						"lookup exactly once (%s)",
						tc.name, spy.tenantCalls, spy.keyProjectCalls, tc.description)
				}
				if len(got) != 2 {
					t.Errorf("returned %d projects, want the tenant-wide stub's 2", len(got))
				}
			}
			if spy.sawTenantID != tenantID {
				t.Errorf("lookup ran under tenant %s, want the request's %s. The tenant must "+
					"come from the authenticated request, never from the key's project.",
					spy.sawTenantID, tenantID)
			}
		})
	}
}

// TestM50W3ListProjectsForCredentialPropagatesErrors: a database fault on the
// narrowed path must NOT surface as "you have no projects".
func TestM50W3ListProjectsForCredentialPropagatesErrors(t *testing.T) {
	tenantID, keyProjectID := uuid.New(), uuid.New()
	boom := errors.New("connection refused")

	got, err := listProjectsForCredential(
		m50w3CtxWithKey(&model.APIKey{ID: uuid.New(), TenantID: tenantID, ProjectID: &keyProjectID}),
		tenantID,
		func(context.Context, uuid.UUID) ([]model.Project, error) { return nil, nil },
		func(context.Context, uuid.UUID, uuid.UUID) ([]model.Project, error) { return nil, boom },
	)
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the lookup's error propagated so the handler answers 500", err)
	}
	if len(got) != 0 {
		t.Errorf("returned %+v alongside the error", got)
	}
}

// TestM50W3BothProjectListHandlersRouteThroughTheSharedDecision closes the other
// half of the CI gap: the decision function above is only load-bearing if both
// handlers actually call it. Checked against the AST rather than by driving the
// handlers, because driving them needs the database this file exists to avoid.
func TestM50W3BothProjectListHandlersRouteThroughTheSharedDecision(t *testing.T) {
	for _, tc := range []struct{ file, recv, method string }{
		{"project.go", "ProjectHandler", "List"},
		{"cli.go", "CLIHandler", "ListProjects"},
	} {
		t.Run(tc.recv+"."+tc.method, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, tc.file, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", tc.file, err)
			}
			body := m50w3MethodBody(t, f, tc.recv, tc.method)

			// The result of the shared decision must be assigned to a NAMED
			// variable and that same variable must be what the handler sends.
			// "Is it called?" was too weak: `_, _ = listProjectsForCredential(...)`
			// beside a direct tenant-wide fetch satisfied it (Codex R3/R4).
			name := m50w3AssignedFrom(body, "listProjectsForCredential")
			if name == "" {
				t.Fatalf("%s.%s does not assign the result of listProjectsForCredential to a "+
					"named variable. Both project-list handlers must take their project set "+
					"FROM it, or one will serve the whole tenant to a project-scoped key while "+
					"the other narrows — the divergence M50 W2 refused both routes to avoid.",
					tc.recv, tc.method)
			}
			if !m50w3ResponseCarries(body, name) {
				t.Errorf("%s.%s assigns listProjectsForCredential's result to %q but never "+
					"sends %q as the project set of its JSON response. The narrowed set must be "+
					"what the caller receives; "+
					"computing it and answering with something else is the same disclosure as "+
					"never narrowing.", tc.recv, tc.method, name, name)
			}

			// And it must not ALSO fetch the list itself. Passing
			// `h.svc.List` as a function VALUE to listProjectsForCredential is a
			// SelectorExpr, not a CallExpr, so it does not trip this; calling
			// `h.svc.List(ctx, tenantID)` directly does.
			for _, banned := range m50w3BannedDirectListCalls {
				if m50w3CallsMethod(body, banned) {
					t.Errorf("%s.%s calls .%s(...) directly. The project set must come from "+
						"listProjectsForCredential, which is the only place the credential is "+
						"consulted; a direct list call bypasses the narrowing entirely.",
						tc.recv, tc.method, banned)
				}
			}
		})
	}
}

// m50w3AssignedFrom returns the name of the first NON-BLANK identifier assigned
// from a call to `fn`, or "" when there is none. `_, _ = fn(...)` yields "".
func m50w3AssignedFrom(body *ast.BlockStmt, fn string) string {
	var name string
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || name != "" {
			return true
		}
		for _, rhs := range assign.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != fn {
				continue
			}
			for _, lhs := range assign.Lhs {
				lid, ok := lhs.(*ast.Ident)
				if ok && lid.Name != "_" {
					name = lid.Name
					return false
				}
			}
		}
		return true
	})
	return name
}

// m50w3ResponseCarries reports whether `name` is what a `.JSON(...)` call in
// body actually sends as the project set.
//
// It accepts exactly two positions, which are the two the real handlers use:
//
//   - `name` IS an argument — ProjectHandler.List's `c.JSON(200, projects)`;
//   - `name` is the VALUE of a field called `Projects` in a composite literal
//     argument — CLIHandler.ListProjects' `c.JSON(200, ProjectsListResponse{
//     Projects: projects, Total: len(projects)})`.
//
// Not "appears anywhere in the argument", which an earlier version allowed:
// `ProjectsListResponse{Projects: somethingElse, Total: len(projects)}`
// mentions `projects` and discloses the tenant (Codex R5, Medium).
//
// It remains a syntactic check and is not data-flow analysis: it cannot see
// `name` being reassigned between the decision and the response, and it does
// not follow the value through an intermediate variable (a handler that built
// the wrapper into a local and then sent the local would fail here and would
// have to be accommodated deliberately). What the value actually contains at
// runtime is asserted against a live database in
// m50w3_project_list_scope_integration_test.go.
func m50w3ResponseCarries(body *ast.BlockStmt, name string) bool {
	carries := func(arg ast.Expr) bool {
		if id, ok := arg.(*ast.Ident); ok && id.Name == name {
			return true
		}
		lit, ok := arg.(*ast.CompositeLit)
		if !ok {
			return false
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Projects" {
				continue
			}
			if id, ok := kv.Value.(*ast.Ident); ok && id.Name == name {
				return true
			}
		}
		return false
	}

	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "JSON" {
			return true
		}
		for _, arg := range call.Args {
			if carries(arg) {
				found = true
			}
		}
		return true
	})
	return found
}

// m50w3BannedDirectListCalls are the project-listing methods a list handler must
// not invoke itself. `List` and `ListProjects` are the tenant-wide service
// entry points; `ListByTenant` is the repository one; `ListForKeyProject` is the
// narrowed one, banned too because choosing it directly would narrow
// unconditionally and empty the web UI's project list.
var m50w3BannedDirectListCalls = []string{"List", "ListProjects", "ListByTenant", "ListForKeyProject"}

// m50w3CallsMethod reports whether body contains a CALL of the form `x.name(...)`.
func m50w3CallsMethod(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			found = true
		}
		return true
	})
	return found
}

// m50w3MethodBody finds `func (x *Recv) Method(...)` and returns its body,
// failing loudly if it is absent so a rename cannot silently pass the caller.
func m50w3MethodBody(t *testing.T, f *ast.File, recv, method string) *ast.BlockStmt {
	t.Helper()
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != method || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		ident, ok := star.X.(*ast.Ident)
		if !ok || ident.Name != recv {
			continue
		}
		if fn.Body == nil {
			t.Fatalf("%s.%s has no body", recv, method)
		}
		return fn.Body
	}
	t.Fatalf("%s.%s not found — if it was renamed, update this test and check that the "+
		"replacement still routes through listProjectsForCredential", recv, method)
	return nil
}

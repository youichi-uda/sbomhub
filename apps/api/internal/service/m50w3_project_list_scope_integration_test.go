//go:build integration

// Package service — M50 W3: the narrowed project lookup a project-scoped API key
// gets instead of the tenant's list.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M50W3' ./internal/service
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// # Why this file is in internal/service and not only in internal/handler
//
// The handler-level proof of the narrowing lives in
// internal/handler/m50w3_project_list_scope_integration_test.go, and NO CI
// workflow runs it: .github/workflows/go-test.yml runs `go test -race ./...`
// (the integration tag excludes the file) and
// .github/workflows/rls-integration.yml runs the tagged suite for
// ./internal/repository/..., ./internal/middleware/... and ./internal/service/...
// only. So `ProjectService.ListForKeyProject` could have been changed to return
// `ListByTenant` and every CI job would have stayed green (Codex R2/R3, Medium).
//
// This package IS in that workflow's list, so these tests are the CI-visible
// proof that the narrowed lookup returns one project and never a sibling. Two
// qualifications, since "CI-visible" is easy to overstate (Codex R4, Low): the
// workflow runs on pushes to main and on pull requests, not on every push to
// every branch; and like every test here they t.Skip when DATABASE_URL is unset
// or unreachable, so a green run with the database missing proves nothing. The
// workflow provisions the database before this step, which is what makes the
// skip path a CI misconfiguration rather than a normal outcome.
//
// Widening the workflow to include ./internal/handler/... is the real fix and is
// out of this wave's file scope — reported, not done.
//
// What this file does NOT cover: the DECISION to narrow (that is
// handler.listProjectsForCredential, unit-tested in
// internal/handler/m50w3_project_list_credential_test.go) and the middleware's
// admission of the two routes (internal/middleware).
package service

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

func m50w3ServiceEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" {
		t.Skip("DATABASE_URL unset — this test asserts against a live database")
	}
	if migURL == "" {
		migURL = appURL
	}
	return appURL, migURL
}

func m50w3ServiceOpen(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("ping: %v — this test asserts against a live database", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type m50w3ServiceSeed struct {
	tenantID  uuid.UUID
	ownID     uuid.UUID
	ownName   string
	siblingID uuid.UUID
}

// m50w3SeedService builds one tenant with two projects. The sibling is the row
// RLS cannot separate from the key's own project — same tenant, same table — so
// it is what the narrowing has to exclude on its own.
func m50w3SeedService(t *testing.T, migDB *sql.DB, label string) m50w3ServiceSeed {
	t.Helper()
	s := m50w3ServiceSeed{
		tenantID:  uuid.New(),
		ownID:     uuid.New(),
		siblingID: uuid.New(),
	}
	s.ownName = "m50w3-svc-" + label + "-own"

	org := "m50w3-svc-" + label + "-" + s.tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		s.tenantID, org, "m50w3 svc "+label, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tenantID := s.tenantID
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup: delete tenant %s: %v", tenantID, err)
		}
	})

	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, s.tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3), ($4, $2, $5)`,
		s.ownID, s.tenantID, s.ownName,
		s.siblingID, "m50w3-svc-"+label+"-sibling"); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return s
}

// m50w3Narrowers are the two service entry points the two project-list routes
// use. Both must behave identically; they are listed together so a change to one
// that is not made to the other fails here rather than in production.
func m50w3Narrowers(db *sql.DB) []struct {
	label string
	call  func(ctx context.Context, tenantID, keyProjectID uuid.UUID) ([]model.Project, error)
} {
	projectRepo := repository.NewProjectRepository(db)
	ps := NewProjectService(projectRepo)
	cs := NewCLIService(projectRepo, repository.NewSbomRepository(db), repository.NewComponentRepository(db))
	return []struct {
		label string
		call  func(ctx context.Context, tenantID, keyProjectID uuid.UUID) ([]model.Project, error)
	}{
		{"ProjectService.ListForKeyProject (GET /api/v1/mcp/projects)", ps.ListForKeyProject},
		{"CLIService.ListForKeyProject (GET /api/v1/cli/projects)", cs.ListForKeyProject},
	}
}

// m50w3AsTenant runs fn inside a tx with the tenant GUC bound, which is what
// TenantTx does per request. `projects` is FORCE ROW LEVEL SECURITY, so an
// unbound read fails rather than returning zero rows — a zero-row assertion
// would otherwise pass for the wrong reason.
func m50w3AsTenant(t *testing.T, db *sql.DB, tenantID uuid.UUID, fn func(ctx context.Context)) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	fn(database.WithTx(context.Background(), tx))
}

// TestM50W3ListForKeyProjectReturnsOnlyTheKeysProject is the core assertion.
func TestM50W3ListForKeyProjectReturnsOnlyTheKeysProject(t *testing.T) {
	appURL, migURL := m50w3ServiceEnv(t)
	migDB := m50w3ServiceOpen(t, migURL)
	appDB := m50w3ServiceOpen(t, appURL)
	seed := m50w3SeedService(t, migDB, "own")

	for _, n := range m50w3Narrowers(appDB) {
		t.Run(n.label, func(t *testing.T) {
			m50w3AsTenant(t, appDB, seed.tenantID, func(ctx context.Context) {
				got, err := n.call(ctx, seed.tenantID, seed.ownID)
				if err != nil {
					t.Fatalf("%s: %v", n.label, err)
				}
				if len(got) != 1 {
					t.Fatalf("%s: returned %d projects, want exactly the key's own one: %+v",
						n.label, len(got), got)
				}
				if got[0].ID != seed.ownID {
					t.Errorf("%s: returned project %s (%q), want %s",
						n.label, got[0].ID, got[0].Name, seed.ownID)
				}
				if got[0].Name != seed.ownName {
					t.Errorf("%s: name = %q, want %q", n.label, got[0].Name, seed.ownName)
				}
				for _, p := range got {
					if p.ID == seed.siblingID {
						t.Errorf("%s: the sibling project is in the narrowed list", n.label)
					}
				}
			})
		})
	}
}

// TestM50W3ListForKeyProjectIsNotTheTenantList is the direct fence against the
// regression Codex named: replacing the narrowed lookup with ListByTenant. The
// tenant has two projects, so a tenant-wide answer is distinguishable by length.
func TestM50W3ListForKeyProjectIsNotTheTenantList(t *testing.T) {
	appURL, migURL := m50w3ServiceEnv(t)
	migDB := m50w3ServiceOpen(t, migURL)
	appDB := m50w3ServiceOpen(t, appURL)
	seed := m50w3SeedService(t, migDB, "nottenant")

	ps := NewProjectService(repository.NewProjectRepository(appDB))
	m50w3AsTenant(t, appDB, seed.tenantID, func(ctx context.Context) {
		wide, err := ps.List(ctx, seed.tenantID)
		if err != nil {
			t.Fatalf("tenant-wide list: %v", err)
		}
		if len(wide) != 2 {
			t.Fatalf("the fixture's tenant has %d projects, want 2 — with fewer than two "+
				"the comparison below cannot tell a narrowed list from a tenant-wide one",
				len(wide))
		}
		for _, n := range m50w3Narrowers(appDB) {
			got, err := n.call(ctx, seed.tenantID, seed.ownID)
			if err != nil {
				t.Fatalf("%s: %v", n.label, err)
			}
			if len(got) == len(wide) {
				t.Errorf("%s: returned %d projects, the same count as the tenant-wide list — "+
					"the narrowed lookup is answering with the tenant", n.label, len(got))
			}
		}
	})
}

// TestM50W3ListForKeyProjectNeverCrossesTenants: the tenant is the REQUEST's,
// never one derived from the key's project. A key whose project_id names another
// tenant's project (possible for rows minted before M47 W1 added the ownership
// check to the mint route) must get nothing, not that project.
func TestM50W3ListForKeyProjectNeverCrossesTenants(t *testing.T) {
	appURL, migURL := m50w3ServiceEnv(t)
	migDB := m50w3ServiceOpen(t, migURL)
	appDB := m50w3ServiceOpen(t, appURL)
	mine := m50w3SeedService(t, migDB, "xt-a")
	theirs := m50w3SeedService(t, migDB, "xt-b")

	for _, n := range m50w3Narrowers(appDB) {
		t.Run(n.label, func(t *testing.T) {
			m50w3AsTenant(t, appDB, mine.tenantID, func(ctx context.Context) {
				got, err := n.call(ctx, mine.tenantID, theirs.ownID)
				if err != nil {
					t.Fatalf("%s: %v", n.label, err)
				}
				if len(got) != 0 {
					t.Errorf("%s: a key whose project_id names another tenant's project got "+
						"%d rows: %+v", n.label, len(got), got)
				}
			})
		})
	}
}

// TestM50W3ListForKeyProjectEmptyResultIsANonNilSlice pins the shape the
// handlers serialise. A nil slice reaches the wire as `null`, which throws in a
// consumer that maps over the result; a zero-length slice reaches it as `[]`.
func TestM50W3ListForKeyProjectEmptyResultIsANonNilSlice(t *testing.T) {
	appURL, migURL := m50w3ServiceEnv(t)
	migDB := m50w3ServiceOpen(t, migURL)
	appDB := m50w3ServiceOpen(t, appURL)
	seed := m50w3SeedService(t, migDB, "nilslice")

	for _, n := range m50w3Narrowers(appDB) {
		t.Run(n.label, func(t *testing.T) {
			m50w3AsTenant(t, appDB, seed.tenantID, func(ctx context.Context) {
				got, err := n.call(ctx, seed.tenantID, uuid.New())
				if err != nil {
					t.Fatalf("%s: %v", n.label, err)
				}
				if got == nil {
					t.Errorf("%s: empty result is a nil slice, which serialises as JSON null; "+
						"return an empty slice so it serialises as []", n.label)
				}
				if len(got) != 0 {
					t.Errorf("%s: returned %d projects for an unallocated project id", n.label, len(got))
				}
			})
		})
	}
}

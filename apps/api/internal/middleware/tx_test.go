//go:build integration

// Package middleware - TenantTx integration test.
//
// Run with:
//
//	cd apps/api && go test -tags=integration ./internal/middleware -run TestTenantTx
//
// Prerequisites (skipped otherwise):
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema already migrated (the server's auto-migrate also handles this)
package middleware

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
)

// txEnv returns (app, migrator) URLs or skips the test.
func txEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("TenantTx integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env.example values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

func openOrSkipTx(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open failed (%v) — skipping", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("DB unreachable (%v) — skipping", err)
	}
	return db
}

func txSchemaReady(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var ok bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'sboms'
		) AND EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'projects'
		)
	`).Scan(&ok)
	if err != nil {
		t.Skipf("schema check failed: %v — skipping", err)
	}
	return ok
}

// seedTenantProject creates a tenant+project pair as migrator and registers
// cleanup so each test self-isolates.
func seedTenantProject(t *testing.T, migDB *sql.DB, label string) (tenantID, projectID uuid.UUID) {
	t.Helper()
	tenantID = uuid.New()
	projectID = uuid.New()
	slugSuffix := tenantID.String()
	if len(slugSuffix) > 8 {
		slugSuffix = slugSuffix[:8]
	}
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		tenantID, "tx-test-"+label+"-"+tenantID.String(),
		"TenantTx "+label, "tx-"+label+"-"+slugSuffix,
	); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	// projects has RLS, so even the migrator needs the GUC to insert.
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("seed project: begin: %v", err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed project: SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
		projectID, tenantID, "tx-test-project-"+label,
	); err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed project: insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("seed project: commit: %v", err)
	}
	return tenantID, projectID
}

// runTenantTxRequest fires a single request through the TenantTx middleware
// with a precomputed tenant_id in context. Returns the captured response
// status and the handler's error.
func runTenantTxRequest(t *testing.T, db *sql.DB, tenantID uuid.UUID, handler echo.HandlerFunc) (int, error) {
	t.Helper()
	e := echo.New()
	mw := TenantTx(db)
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(ContextKeyTenantID, tenantID)
	err := mw(handler)(c)
	return rec.Code, err
}

// TestTenantTx_IsolatesInsertedSboms is the core RLS invariant: tenant A
// inserts a sbom via the middleware-managed tx, tenant B must not see it.
func TestTenantTx_IsolatesInsertedSboms(t *testing.T) {
	appURL, migURL := txEnv(t)

	migDB := openOrSkipTx(t, migURL)
	defer migDB.Close()
	if !txSchemaReady(t, migDB) {
		t.Skip("schema not migrated yet — run the api server (or migrate up) first")
	}

	appDB := openOrSkipTx(t, appURL)
	defer appDB.Close()

	tenantA, projectA := seedTenantProject(t, migDB, "A")
	tenantB, _ := seedTenantProject(t, migDB, "B")

	sbomID := uuid.New()
	status, err := runTenantTxRequest(t, appDB, tenantA, func(c echo.Context) error {
		_, ierr := database.Querier(c.Request().Context(), appDB).ExecContext(
			c.Request().Context(),
			`INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data)
			 VALUES ($1, $2, $3, 'cyclonedx', '1.4', '{}'::jsonb)`,
			sbomID, tenantA, projectA,
		)
		if ierr != nil {
			return ierr
		}
		return c.NoContent(http.StatusNoContent)
	})
	if err != nil {
		t.Fatalf("tenantA insert via middleware: handler err = %v", err)
	}
	if status != http.StatusNoContent {
		t.Fatalf("tenantA insert via middleware: status = %d, want 204", status)
	}

	var count int
	status, err = runTenantTxRequest(t, appDB, tenantB, func(c echo.Context) error {
		return database.Querier(c.Request().Context(), appDB).QueryRowContext(c.Request().Context(),
			`SELECT COUNT(*) FROM sboms WHERE id = $1`, sbomID,
		).Scan(&count)
	})
	if err != nil {
		t.Fatalf("tenantB read via middleware: handler err = %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("tenantB read via middleware: status = %d, want 200", status)
	}
	if count != 0 {
		t.Fatalf("RLS leak: tenantB session saw %d rows belonging to tenantA; want 0", count)
	}
}

// TestTenantTx_PanicRollsBack asserts that a panic in the handler triggers
// rollback and re-raises. No rows must remain.
func TestTenantTx_PanicRollsBack(t *testing.T) {
	appURL, migURL := txEnv(t)
	migDB := openOrSkipTx(t, migURL)
	defer migDB.Close()
	if !txSchemaReady(t, migDB) {
		t.Skip("schema not migrated yet — run the api server first")
	}
	appDB := openOrSkipTx(t, appURL)
	defer appDB.Close()

	tenantA, projectA := seedTenantProject(t, migDB, "panic")
	sbomID := uuid.New()

	defer func() {
		if p := recover(); p == nil {
			t.Fatal("expected handler panic to propagate")
		}
		var count int
		tx, err := appDB.Begin()
		if err != nil {
			t.Fatalf("appDB.Begin: %v", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantA.String()); err != nil {
			t.Fatalf("SET LOCAL: %v", err)
		}
		if err := tx.QueryRow(`SELECT COUNT(*) FROM sboms WHERE id = $1`, sbomID).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Fatalf("panic did not roll back: found %d sbom rows; want 0", count)
		}
	}()

	_, _ = runTenantTxRequest(t, appDB, tenantA, func(c echo.Context) error {
		_, _ = database.Querier(c.Request().Context(), appDB).ExecContext(
			c.Request().Context(),
			`INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data)
			 VALUES ($1, $2, $3, 'cyclonedx', '1.4', '{}'::jsonb)`,
			sbomID, tenantA, projectA,
		)
		panic("intentional panic for rollback test")
	})
}

// TestTenantTx_RollsBackOnErrorStatus asserts that a 4xx status from the
// handler triggers rollback even if the handler returns nil error.
func TestTenantTx_RollsBackOnErrorStatus(t *testing.T) {
	appURL, migURL := txEnv(t)
	migDB := openOrSkipTx(t, migURL)
	defer migDB.Close()
	if !txSchemaReady(t, migDB) {
		t.Skip("schema not migrated yet — run the api server first")
	}
	appDB := openOrSkipTx(t, appURL)
	defer appDB.Close()

	tenantA, projectA := seedTenantProject(t, migDB, "errstatus")
	sbomID := uuid.New()

	status, err := runTenantTxRequest(t, appDB, tenantA, func(c echo.Context) error {
		_, ierr := database.Querier(c.Request().Context(), appDB).ExecContext(
			c.Request().Context(),
			`INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data)
			 VALUES ($1, $2, $3, 'cyclonedx', '1.4', '{}'::jsonb)`,
			sbomID, tenantA, projectA,
		)
		if ierr != nil {
			return ierr
		}
		// Return a 400 to trigger rollback. The DB write succeeded, but the
		// status signals "this request was rejected" — the tx must roll back.
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "intentional"})
	})
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}

	var count int
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantA.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sboms WHERE id = $1`, sbomID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("error-status path did not roll back: found %d sbom rows; want 0", count)
	}
}

// TestTenantTx_ParallelTenantsNoLeak fires N requests in parallel, each
// scoped to a unique tenant, and verifies that each tenant only sees its
// own row after every commit lands. Spec asks for 100 parallel.
func TestTenantTx_ParallelTenantsNoLeak(t *testing.T) {
	appURL, migURL := txEnv(t)
	migDB := openOrSkipTx(t, migURL)
	defer migDB.Close()
	if !txSchemaReady(t, migDB) {
		t.Skip("schema not migrated yet — run the api server first")
	}
	appDB := openOrSkipTx(t, appURL)
	defer appDB.Close()
	appDB.SetMaxOpenConns(40)

	const N = 100
	tenants := make([]uuid.UUID, N)
	projects := make([]uuid.UUID, N)
	sboms := make([]uuid.UUID, N)
	for i := 0; i < N; i++ {
		tenants[i], projects[i] = seedTenantProject(t, migDB, fmt.Sprintf("p%d", i))
		sboms[i] = uuid.New()
	}

	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := runTenantTxRequest(t, appDB, tenants[i], func(c echo.Context) error {
				_, ierr := database.Querier(c.Request().Context(), appDB).ExecContext(
					c.Request().Context(),
					`INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data)
					 VALUES ($1, $2, $3, 'cyclonedx', '1.4', '{}'::jsonb)`,
					sboms[i], tenants[i], projects[i],
				)
				if ierr != nil {
					return ierr
				}
				return c.NoContent(http.StatusNoContent)
			})
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Fatalf("parallel insert #%d failed: %v", i, e)
		}
	}

	for i := 0; i < N; i++ {
		var seen int
		_, err := runTenantTxRequest(t, appDB, tenants[i], func(c echo.Context) error {
			return database.Querier(c.Request().Context(), appDB).QueryRowContext(
				c.Request().Context(),
				`SELECT COUNT(*) FROM sboms`,
			).Scan(&seen)
		})
		if err != nil {
			t.Fatalf("readback #%d: %v", i, err)
		}
		if seen != 1 {
			t.Errorf("tenant #%d sees %d sboms, want exactly 1 (its own) — RLS leak", i, seen)
		}
	}
}

// TestTenantTx_RejectsMissingTenant asserts that the middleware refuses
// requests that arrive without a tenant context (i.e. a misconfigured route).
func TestTenantTx_RejectsMissingTenant(t *testing.T) {
	appURL, _ := txEnv(t)
	appDB := openOrSkipTx(t, appURL)
	defer appDB.Close()

	e := echo.New()
	mw := TenantTx(appDB)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// Intentionally do NOT call c.Set(ContextKeyTenantID, ...).

	handlerInvoked := false
	err := mw(func(c echo.Context) error {
		handlerInvoked = true
		return nil
	})(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handlerInvoked {
		t.Fatal("handler was invoked despite missing tenant context")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// Build-tag safety: every test in this file is gated on `integration`. The
// next line ensures the package still compiles with the production tag set
// if the build tag is removed.
var _ = sql.ErrNoRows

//go:build integration

// Package handler — M46 Codex round B-1 High-2, end-to-end: the anonymous
// download route must enforce the per-link cap even when the counter
// starts at the hostile NULL, and must not oversell it under concurrency.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M46B1' ./internal/handler
//
// This is the route-level companion to the repository test
// (repository/m46_b1_public_link_failclosed_integration_test.go). It
// drives handler.PublicDownload through a real echo context against real
// PostgreSQL, which is what actually pins the ORDER of operations: the
// cap must be consumed BEFORE the SBOM bytes are written to the response.
// Pre-fix the handler did IsDownloadLimitReached → serve →
// IncrementDownload, so (a) a NULL download_count never advanced and the
// cap never engaged at all, and (b) concurrent requests all passed the
// check before any increment committed.
package handler

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

func m46b1HandlerEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("public-download cap integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// m46b1PublicLinksSchemaLock is the SAME advisory-lock key as
// repository.publicLinksNotNullAdvisoryLock (Go test files cannot be
// imported across packages, so the constant is duplicated — keep the
// repository / service / handler copies in sync).
//
// `go test ./...` runs packages concurrently against one dev database and
// three of them need the pre-058 nullable shape; without the lock, one
// package's cleanup can restore NOT NULL while another still has NULL
// rows in flight (observed as a flaky assertion, 2026-07-26).
const m46b1PublicLinksSchemaLock = 4600581

// m46b1RelaxDownloadCountNotNull takes the cross-package advisory lock on
// a pinned session, drops the 058 NOT NULL on download_count for the
// duration of the test, and restores the exact prior state before
// releasing the lock.
func m46b1RelaxDownloadCountNotNull(t *testing.T, migDB *sql.DB) {
	t.Helper()
	ctx := context.Background()
	conn, err := migDB.Conn(ctx)
	if err != nil {
		t.Fatalf("pin conn for public_links schema lock: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, m46b1PublicLinksSchemaLock); err != nil {
		_ = conn.Close()
		t.Fatalf("acquire public_links schema lock: %v", err)
	}
	t.Cleanup(func() {
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, m46b1PublicLinksSchemaLock); err != nil {
			t.Errorf("release public_links schema lock: %v", err)
		}
		_ = conn.Close()
	})

	var wasNotNull bool
	if err := conn.QueryRowContext(ctx, `
		SELECT a.attnotnull FROM pg_attribute a
		WHERE a.attrelid = 'public.public_links'::regclass AND a.attname = 'download_count'
	`).Scan(&wasNotNull); err != nil {
		t.Fatalf("read NOT NULL state: %v", err)
	}
	if !wasNotNull {
		return
	}
	if _, err := conn.ExecContext(ctx, `ALTER TABLE public_links ALTER COLUMN download_count DROP NOT NULL`); err != nil {
		t.Fatalf("relax download_count: %v", err)
	}
	// Registered after the unlock cleanup, so it runs BEFORE it (LIFO).
	t.Cleanup(func() {
		if _, err := conn.ExecContext(ctx, `UPDATE public_links SET download_count = 0 WHERE download_count IS NULL`); err != nil {
			t.Errorf("re-backfill download_count: %v", err)
			return
		}
		if _, err := conn.ExecContext(ctx, `ALTER TABLE public_links ALTER COLUMN download_count SET NOT NULL`); err != nil {
			t.Errorf("restore NOT NULL: %v", err)
		}
	})
}

func m46b1OpenOrSkip(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open failed (%v) - skipping", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("DB unreachable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// m46b1SeedShare seeds tenant + project + sbom + a public link with the
// given cap and (possibly NULL) starting counter, and returns the token.
// The tenant DELETE cascades to everything else (C27: no residue).
func m46b1SeedShare(t *testing.T, migDB *sql.DB, label string,
	allowedDownloads any, downloadCount any) string {
	t.Helper()

	tenantID := uuid.New()
	org := "m46b1-" + label + "-" + tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		tenantID, org, "m46b1 "+label, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("C27 cleanup: delete tenant %s: %v", tenantID, err)
		}
	})

	execAsTenant := func(query string, args ...any) {
		t.Helper()
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
			t.Fatalf("SET LOCAL: %v", err)
		}
		if _, err := tx.Exec(query, args...); err != nil {
			t.Fatalf("exec as tenant: %v\nquery: %s", err, query)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	projectID := uuid.New()
	execAsTenant(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
		projectID, tenantID, "m46b1-"+label+"-project")
	sbomID := uuid.New()
	execAsTenant(`
		INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
		VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{"bomFormat":"CycloneDX"}'::jsonb, NOW())
	`, sbomID, tenantID, projectID)

	// public_links has no RLS since migration 030.
	token := uuid.New().String() + uuid.New().String()
	token = token[:64]
	if _, err := migDB.Exec(`
		INSERT INTO public_links (id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, '2099-01-01T00:00:00Z', true, $7, NULL, 0, $8, NOW(), NOW())
	`, uuid.New(), tenantID, projectID, sbomID, token, "m46b1-"+label+"-link",
		allowedDownloads, downloadCount); err != nil {
		t.Fatalf("seed public link: %v", err)
	}
	return token
}

func m46b1Handler(t *testing.T, appDB *sql.DB) *PublicLinkHandler {
	t.Helper()
	svc := service.NewPublicLinkService(appDB,
		repository.NewPublicLinkRepository(appDB),
		repository.NewProjectRepository(appDB),
		repository.NewSbomRepository(appDB),
		repository.NewComponentRepository(appDB))
	return NewPublicLinkHandler(svc)
}

// doDownload drives PublicDownload for one token and returns the HTTP
// status plus the response body.
func doDownload(t *testing.T, h *PublicLinkHandler, token string) (int, string) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/public/"+token+"/download", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("token")
	c.SetParamValues(token)
	if err := h.PublicDownload(c); err != nil {
		t.Fatalf("PublicDownload returned a transport error: %v", err)
	}
	return rec.Code, rec.Body.String()
}

// TestM46B1_PublicDownload_NullCounterCapEnforced: allowed_downloads = 1
// with download_count = NULL. Pre-fix the counter never left NULL, so
// EVERY request was admitted (unlimited anonymous downloads). Post-fix
// the first request is served and the second is refused.
func TestM46B1_PublicDownload_NullCounterCapEnforced(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	// Migration 058 made download_count NOT NULL; seed the pre-058 shape
	// to prove the application layer is fail-closed on its own.
	m46b1RelaxDownloadCountNotNull(t, migDB)

	token := m46b1SeedShare(t, migDB, "cap", 1, nil)
	h := m46b1Handler(t, appDB)

	if code, body := doDownload(t, h, token); code != http.StatusOK {
		t.Fatalf("first download: status %d body %s, want 200", code, body)
	}
	code, body := doDownload(t, h, token)
	if code != http.StatusForbidden {
		t.Errorf("second download: status %d, want 403 (the 1-download cap must be exhausted)", code)
	}
	if code == http.StatusOK {
		t.Errorf("second download served %d bytes past the cap", len(body))
	}
}

// TestM46B1_PublicDownload_ConcurrentCapNotOversold: N simultaneous
// requests against a 1-download link must yield exactly one 200. The
// consume is a single conditional UPDATE, so the check cannot be won by
// more than one racer (pre-fix check→serve→increment let all N through).
func TestM46B1_PublicDownload_ConcurrentCapNotOversold(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	token := m46b1SeedShare(t, migDB, "race", 1, 0)
	h := m46b1Handler(t, appDB)

	const attackers = 8
	codes := make([]int, attackers)
	var wg sync.WaitGroup
	for i := 0; i < attackers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/public/"+token+"/download", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("token")
			c.SetParamValues(token)
			_ = h.PublicDownload(c)
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	served := 0
	for i, code := range codes {
		switch code {
		case http.StatusOK:
			served++
		case http.StatusForbidden:
		default:
			t.Errorf("request %d: unexpected status %d", i, code)
		}
	}
	if served != 1 {
		t.Errorf("%d of %d concurrent requests were served past a 1-download cap, want exactly 1", served, attackers)
	}
}

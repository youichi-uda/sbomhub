//go:build integration

// Package service — M46 Codex round B-1 High-1: end-to-end proof that the
// anonymous share-token flow REJECTS a public link whose is_active is
// NULL.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M46B1' ./internal/service
//
// Pre-fix, PublicLinkRepository read COALESCE(is_active, true), so
// GetPublicView / GetPublicSbomRaw treated a NULL-is_active row as active
// and served the project name, SBOM and component list to any anonymous
// caller holding the token (measured red: both calls succeeded). Post-fix
// the read is fail-closed (COALESCE(is_active, false)) and both calls
// return the "link inactive" sentinel. Migration 058's NOT NULL kills the
// anomaly at the DDL layer; this test relaxes the constraint for its own
// seeds to prove the application stays fail-closed even without it.
package service

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
)

// m46b1PublicLinksSchemaLock is the SAME advisory-lock key as
// repository.publicLinksNotNullAdvisoryLock (Go test files cannot be
// imported across packages, so the constant is duplicated — keep the
// repository / service / handler copies in sync).
//
// `go test ./...` runs packages concurrently against one dev database and
// three of them need the pre-058 nullable shape; without the lock, one
// package's cleanup can restore NOT NULL while another still has NULL
// rows in flight (observed as a flaky fail-open assertion, 2026-07-26).
const m46b1PublicLinksSchemaLock = 4600581

// m46b1RelaxPublicLinksNotNull mirrors the repository-package helper: take
// the cross-package advisory lock on a pinned session, drop the 058 NOT
// NULL on is_active for the duration of the test, and restore the exact
// prior state before releasing the lock.
func m46b1RelaxPublicLinksNotNull(t *testing.T, migDB *sql.DB) {
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
		WHERE a.attrelid = 'public.public_links'::regclass AND a.attname = 'is_active'
	`).Scan(&wasNotNull); err != nil {
		t.Fatalf("read NOT NULL state of public_links.is_active: %v", err)
	}
	if !wasNotNull {
		return
	}
	if _, err := conn.ExecContext(ctx, `ALTER TABLE public_links ALTER COLUMN is_active DROP NOT NULL`); err != nil {
		t.Fatalf("relax public_links.is_active: %v", err)
	}
	// Registered after the unlock cleanup, so it runs BEFORE it (LIFO).
	t.Cleanup(func() {
		if _, err := conn.ExecContext(ctx, `UPDATE public_links SET is_active = false WHERE is_active IS NULL`); err != nil {
			t.Errorf("re-backfill public_links.is_active: %v", err)
			return
		}
		if _, err := conn.ExecContext(ctx, `ALTER TABLE public_links ALTER COLUMN is_active SET NOT NULL`); err != nil {
			t.Errorf("restore NOT NULL on public_links.is_active: %v", err)
		}
	})
}

func TestM46B1_PublicShareFlow_NullIsActive_Denied(t *testing.T) {
	appURL, migURL := wave3SvcEnv(t)
	migDB := wave3SvcOpenOrSkip(t, migURL)
	appDB := wave3SvcOpenOrSkip(t, appURL)

	m46b1RelaxPublicLinksNotNull(t, migDB)

	tenant := wave3SvcSeedTenant(t, migDB, "m46b1-plink")

	projectID := uuid.New()
	wave3SvcExecAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46b1-svc-plink-project')
	`, projectID, tenant)
	sbomID := uuid.New()
	wave3SvcExecAsTenant(t, migDB, tenant, `
		INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
		VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{"bomFormat":"CycloneDX"}'::jsonb, NOW())
	`, sbomID, tenant, projectID)

	// The hostile row: is_active NULL, otherwise fully valid (unexpired,
	// no password). public_links has no RLS (migration 030) — plain
	// migrator INSERT.
	token := "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0" + tenant.String()[:4]
	if _, err := migDB.Exec(`
		INSERT INTO public_links (id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'm46b1-svc-null-active', '2099-01-01T00:00:00Z', NULL,
			NULL, NULL, 0, 0, NOW(), NOW())
	`, uuid.New(), tenant, projectID, sbomID, token); err != nil {
		t.Fatalf("seed NULL-is_active public link: %v", err)
	}

	linkRepo := repository.NewPublicLinkRepository(appDB)
	projectRepo := repository.NewProjectRepository(appDB)
	sbomRepo := repository.NewSbomRepository(appDB)
	componentRepo := repository.NewComponentRepository(appDB)
	svc := NewPublicLinkService(appDB, linkRepo, projectRepo, sbomRepo, componentRepo)

	ctx := context.Background()

	// The anonymous view flow MUST be denied.
	view, _, err := svc.GetPublicView(ctx, token, "")
	if err == nil {
		t.Errorf("GetPublicView on a NULL-is_active link succeeded (project %q leaked to an anonymous token holder); want a denial",
			view.ProjectName)
	}

	// The anonymous download flow MUST be denied too.
	raw, _, err := svc.GetPublicSbomRaw(ctx, token, "")
	if err == nil {
		t.Errorf("GetPublicSbomRaw on a NULL-is_active link succeeded (%d bytes of SBOM leaked); want a denial", len(raw))
	}
}

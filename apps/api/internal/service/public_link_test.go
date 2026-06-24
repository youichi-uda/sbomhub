package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// codex-r7 P1 regression guard.
//
// The anonymous /api/v1/public/:token route has no tenant middleware, so when
// GetPublicView / GetPublicSbomRaw fetch the underlying project / sbom /
// components (all still under RLS) the connection's app.current_tenant_id GUC
// is unset and RLS silently returns zero rows. The codex-r7 fix wraps the
// content read in PublicLinkService.runWithTenantTx, which opens a fresh tx,
// pins the GUC to the tenant carried by the resolved link, and runs the
// reads inside that tx.
//
// These tests pin the contract of runWithTenantTx — that set_config fires
// before fn and that the tx commits on success / rolls back on error.
// End-to-end coverage of GetPublicView would require mocking every repo
// query along the read path; the helper is the load-bearing piece and is
// what the bug centred on.
func newTestPublicLinkService(t *testing.T, db *sql.DB) *PublicLinkService {
	t.Helper()
	// Repositories are not exercised by runWithTenantTx itself, so we wire
	// real repo structs against the same sqlmock-backed *sql.DB — they are
	// inert here.
	linkRepo := repository.NewPublicLinkRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	sbomRepo := repository.NewSbomRepository(db)
	componentRepo := repository.NewComponentRepository(db)
	return NewPublicLinkService(db, linkRepo, projectRepo, sbomRepo, componentRepo)
}

func TestPublicLink_RunWithTenantTx_PinsTenantAndCommitsOnSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()

	mock.ExpectBegin()
	// set_config is the load-bearing line: without it, downstream
	// projects / sboms / components reads run with no tenant_id GUC and
	// RLS rejects every row.
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT 1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	svc := newTestPublicLinkService(t, db)

	called := false
	err = svc.runWithTenantTx(context.Background(), tenantID, func(txCtx context.Context) error {
		called = true
		_, ferr := svc.db.ExecContext(txCtx, "SELECT 1")
		return ferr
	})
	if err != nil {
		t.Fatalf("runWithTenantTx: %v", err)
	}
	if !called {
		t.Fatal("fn was not invoked")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPublicLink_RunWithTenantTx_RollsBackOnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	svc := newTestPublicLinkService(t, db)

	sentinel := errors.New("downstream failure")
	gotErr := svc.runWithTenantTx(context.Background(), tenantID, func(_ context.Context) error {
		return sentinel
	})
	if !errors.Is(gotErr, sentinel) {
		t.Fatalf("runWithTenantTx err = %v, want %v", gotErr, sentinel)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPublicLink_RunWithTenantTx_NilDBReturnsErrorInsteadOfPanic(t *testing.T) {
	// Belt-and-braces: if main.go ever wires the service without a db
	// handle, we want a clear error rather than a panic from WithTxFunc.
	svc := NewPublicLinkService(nil, nil, nil, nil, nil)
	err := svc.runWithTenantTx(context.Background(), uuid.New(), func(_ context.Context) error {
		t.Fatal("fn must not be invoked when db is nil")
		return nil
	})
	if err == nil {
		t.Fatal("expected error when db is nil")
	}
}

// TestPublicLink_GetPublicView_BindsTenantBeforeContentRead is the
// end-to-end contract test for the codex-r7 P1 fix: GetByToken runs
// without a tx, then a tx opens and set_config('app.current_tenant_id',
// link.tenant_id) fires BEFORE the projects / sboms / components reads.
// If this ordering regresses (content reads escape the tenant tx), the
// share-link content flow silently returns empty.
func TestPublicLink_GetPublicView_BindsTenantBeforeContentRead(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	projectID := uuid.New()
	sbomID := uuid.New()
	linkID := uuid.New()
	token := "share-token-fixture"
	now := time.Now()

	// 1) GetByToken runs outside the tx — public_links has RLS removed
	//    in migration 030 so the anonymous lookup works without a
	//    tenant context.
	mock.ExpectQuery(`SELECT id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active`).
		WithArgs(token).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "project_id", "sbom_id", "token", "name", "expires_at", "is_active",
			"allowed_downloads", "password_hash", "view_count", "download_count", "created_at", "updated_at",
		}).AddRow(
			linkID, tenantID, projectID, nil, token, "test link", now.Add(24*time.Hour), true,
			nil, nil, 0, 0, now, now,
		))

	// 2) The tenant-scoped tx wraps every subsequent content read so
	//    RLS sees the right tenant_id.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))

	// 3) Project, sbom, components reads inside the tx.
	mock.ExpectQuery(`SELECT id, tenant_id, name, description, created_at, updated_at FROM projects WHERE id = \$1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "name", "description", "created_at", "updated_at",
		}).AddRow(projectID, tenantID, "demo project", "", now, now))

	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", []byte(`{}`), now))

	mock.ExpectQuery(`SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE sbom_id = \$1 ORDER BY name`).
		WithArgs(sbomID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at",
		}))

	mock.ExpectCommit()

	svc := newTestPublicLinkService(t, db)

	view, link, err := svc.GetPublicView(context.Background(), token, "")
	if err != nil {
		t.Fatalf("GetPublicView: %v", err)
	}
	if link == nil || link.ID != linkID {
		t.Fatalf("link mismatch: got %+v", link)
	}
	if view == nil {
		t.Fatal("view is nil")
	}
	if view.ProjectName != "demo project" {
		t.Fatalf("view.ProjectName = %q, want %q", view.ProjectName, "demo project")
	}
	if view.Sbom.ID != sbomID {
		t.Fatalf("view.Sbom.ID = %v, want %v", view.Sbom.ID, sbomID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestPublicLink_GetPublicSbomRaw_BindsTenantBeforeContentRead is the
// download-flow twin of the GetPublicView ordering test.
func TestPublicLink_GetPublicSbomRaw_BindsTenantBeforeContentRead(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	projectID := uuid.New()
	sbomID := uuid.New()
	linkID := uuid.New()
	token := "share-token-fixture-dl"
	now := time.Now()
	raw := []byte(`{"bomFormat":"CycloneDX"}`)

	mock.ExpectQuery(`SELECT id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active`).
		WithArgs(token).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "project_id", "sbom_id", "token", "name", "expires_at", "is_active",
			"allowed_downloads", "password_hash", "view_count", "download_count", "created_at", "updated_at",
		}).AddRow(
			linkID, tenantID, projectID, sbomID, token, "test link", now.Add(24*time.Hour), true,
			nil, nil, 0, 0, now, now,
		))

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE id = \$1`).
		WithArgs(sbomID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", raw, now))
	mock.ExpectCommit()

	svc := newTestPublicLinkService(t, db)

	gotRaw, link, err := svc.GetPublicSbomRaw(context.Background(), token, "")
	if err != nil {
		t.Fatalf("GetPublicSbomRaw: %v", err)
	}
	if link == nil || link.ID != linkID {
		t.Fatalf("link mismatch: got %+v", link)
	}
	if string(gotRaw) != string(raw) {
		t.Fatalf("raw mismatch: got %q want %q", gotRaw, raw)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

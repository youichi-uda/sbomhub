package repository

// M46 Codex round B-1 — Medium-1: the four projects.tenant_id resolvers
// that were still scanning into a bare uuid.UUID after wave 2 fixed only
// vex.go. uuid.UUID.Scan(nil) succeeds and SILENTLY leaves uuid.Nil, so a
// NULL-tenant project row (projects.tenant_id is DDL-nullable — 007 added
// the column without NOT NULL) made these return (uuid.Nil, nil):
//
//   - LicensePolicyRepository.LookupProjectTenantID → uuid.Nil written
//     into license_policies.tenant_id
//   - SbomRepository.LookupProjectTenantID → uuid.Nil into sboms.tenant_id
//   - ProjectRepository.GetTenantID → uuid.Nil flows into notification /
//     CLI tenant scoping
//
// Post-fix all four delegate to the shared lookupProjectTenantID resolver
// (project_tenant.go) that scans through uuid.NullUUID and fails loudly.
// The vex.go equivalent is pinned in m46_w2_rows_err_test.go.

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func expectNullTenantLookup(mock sqlmock.Sqlmock, projectID uuid.UUID) {
	mock.ExpectQuery(`SELECT tenant_id FROM projects WHERE id`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(nil))
}

func requireNullTenantError(t *testing.T, method string, got uuid.UUID, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s on a NULL tenant_id returned (%v, nil); want an explicit error, not a silent uuid.Nil", method, got)
	}
	if got != uuid.Nil {
		t.Errorf("%s error path returned %v, want uuid.Nil", method, got)
	}
}

func TestLicensePolicyRepository_LookupProjectTenantID_NullTenant(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewLicensePolicyRepository(db)
	projectID := uuid.New()

	expectNullTenantLookup(mock, projectID)
	got, err := repo.LookupProjectTenantID(context.Background(), projectID)
	requireNullTenantError(t, "LicensePolicyRepository.LookupProjectTenantID", got, err)
}

func TestSbomRepository_LookupProjectTenantID_NullTenant(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewSbomRepository(db)
	projectID := uuid.New()

	expectNullTenantLookup(mock, projectID)
	got, err := repo.LookupProjectTenantID(context.Background(), projectID)
	requireNullTenantError(t, "SbomRepository.LookupProjectTenantID", got, err)
}

func TestProjectRepository_GetTenantID_NullTenant(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewProjectRepository(db)
	projectID := uuid.New()

	expectNullTenantLookup(mock, projectID)
	got, err := repo.GetTenantID(context.Background(), projectID)
	requireNullTenantError(t, "ProjectRepository.GetTenantID", got, err)
}

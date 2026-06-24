package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestLicensePolicyRepository_Create_PassesTenantID asserts that the
// tenant_id column is bound at position 2 of the INSERT statement. This
// guards against an accidental reordering that would silently drop
// tenant_id into another column and pass schema/RLS only by coincidence.
//
// Pairs with the FORCE RLS WITH CHECK clause on license_policies
// (migration 023): a missing tenant_id is rejected at INSERT time.
func TestLicensePolicyRepository_Create_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewLicensePolicyRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	policyID := uuid.New()
	now := time.Now()

	mock.ExpectExec("INSERT INTO license_policies").
		WithArgs(
			policyID,
			tenantID,
			projectID,
			"MIT",
			"MIT License",
			model.LicensePolicyAllowed,
			"approved",
			now,
			now,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.Create(context.Background(), &model.LicensePolicy{
		ID:          policyID,
		TenantID:    tenantID,
		ProjectID:   projectID,
		LicenseID:   "MIT",
		LicenseName: "MIT License",
		PolicyType:  model.LicensePolicyAllowed,
		Reason:      "approved",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestLicensePolicyRepository_LookupProjectTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewLicensePolicyRepository(db)
	projectID := uuid.New()
	tenantID := uuid.New()

	t.Run("found", func(t *testing.T) {
		mock.ExpectQuery("SELECT tenant_id FROM projects WHERE id").
			WithArgs(projectID).
			WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))

		got, err := repo.LookupProjectTenantID(context.Background(), projectID)
		if err != nil {
			t.Fatalf("LookupProjectTenantID returned error: %v", err)
		}
		if got != tenantID {
			t.Errorf("tenant_id mismatch: got %v, want %v", got, tenantID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		missingID := uuid.New()
		mock.ExpectQuery("SELECT tenant_id FROM projects WHERE id").
			WithArgs(missingID).
			WillReturnError(sql.ErrNoRows)

		if _, err := repo.LookupProjectTenantID(context.Background(), missingID); err == nil {
			t.Error("expected error for missing project, got nil")
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

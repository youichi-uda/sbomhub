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

// TestVEXRepository_Create_PassesTenantID asserts that the tenant_id column
// is bound at position 2 of the INSERT statement. This guards against an
// accidental reordering that would silently drop tenant_id into another
// column (e.g. project_id) and pass schema/RLS only by coincidence.
//
// Pairs with the FORCE RLS WITH CHECK clause on vex_statements (migration
// 023): a missing tenant_id is rejected at INSERT time regardless of any
// column-level constraint.
func TestVEXRepository_Create_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewVEXRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()
	statementID := uuid.New()
	now := time.Now()

	mock.ExpectExec("INSERT INTO vex_statements").
		WithArgs(
			statementID,
			tenantID,
			projectID,
			vulnID,
			sqlmock.AnyArg(), // component_id (nil)
			model.VEXStatusNotAffected,
			model.VEXJustificationComponentNotPresent,
			"action",
			"impact",
			"alice@example.com",
			now,
			now,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.Create(context.Background(), &model.VEXStatement{
		ID:              statementID,
		TenantID:        tenantID,
		ProjectID:       projectID,
		VulnerabilityID: vulnID,
		ComponentID:     nil,
		Status:          model.VEXStatusNotAffected,
		Justification:   model.VEXJustificationComponentNotPresent,
		ActionStatement: "action",
		ImpactStatement: "impact",
		CreatedBy:       "alice@example.com",
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestVEXRepository_LookupProjectTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewVEXRepository(db)
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

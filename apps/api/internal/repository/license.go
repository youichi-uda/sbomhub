package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

type LicensePolicyRepository struct {
	db *sql.DB
}

func NewLicensePolicyRepository(db *sql.DB) *LicensePolicyRepository {
	return &LicensePolicyRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
func (r *LicensePolicyRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Create inserts a new license_policies row.
//
// tenant_id is required because license_policies is FORCE ROW LEVEL
// SECURITY (migration 023) with `WITH CHECK (tenant_id = current_setting(
// 'app.current_tenant_id')::UUID)`. The application runtime role
// (sbomhub_app) is NOBYPASSRLS, so a missing or wrong tenant_id is rejected
// at INSERT time. Callers must populate p.TenantID before calling Create;
// LicensePolicyService resolves it from the parent project via
// LookupProjectTenantID below.
func (r *LicensePolicyRepository) Create(ctx context.Context, p *model.LicensePolicy) error {
	query := `
		INSERT INTO license_policies (id, tenant_id, project_id, license_id, license_name, policy_type, reason, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
		p.ID, p.TenantID, p.ProjectID, p.LicenseID, p.LicenseName, p.PolicyType, p.Reason, p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// LookupProjectTenantID returns the tenant_id of the project that owns
// projectID. It mirrors SbomRepository.LookupProjectTenantID and exists so
// LicensePolicyService can populate LicensePolicy.TenantID before insert
// without growing its constructor surface (which would force a
// cmd/server/main.go change owned by a different wave).
func (r *LicensePolicyRepository) LookupProjectTenantID(ctx context.Context, projectID uuid.UUID) (uuid.UUID, error) {
	var tenantID uuid.UUID
	err := r.q(ctx).QueryRowContext(ctx, `SELECT tenant_id FROM projects WHERE id = $1`, projectID).Scan(&tenantID)
	return tenantID, err
}

func (r *LicensePolicyRepository) Update(ctx context.Context, p *model.LicensePolicy) error {
	query := `
		UPDATE license_policies
		SET policy_type = $1, reason = $2, updated_at = $3
		WHERE id = $4
	`
	result, err := r.q(ctx).ExecContext(ctx, query, p.PolicyType, p.Reason, p.UpdatedAt, p.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("license policy not found")
	}
	return nil
}

func (r *LicensePolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.LicensePolicy, error) {
	query := `
		SELECT id, project_id, license_id, license_name, policy_type, reason, created_at, updated_at
		FROM license_policies
		WHERE id = $1
	`
	var p model.LicensePolicy
	err := r.q(ctx).QueryRowContext(ctx, query, id).Scan(
		&p.ID, &p.ProjectID, &p.LicenseID, &p.LicenseName, &p.PolicyType, &p.Reason, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *LicensePolicyRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.LicensePolicy, error) {
	query := `
		SELECT id, project_id, license_id, license_name, policy_type, reason, created_at, updated_at
		FROM license_policies
		WHERE project_id = $1
		ORDER BY license_name
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []model.LicensePolicy
	for rows.Next() {
		var p model.LicensePolicy
		if err := rows.Scan(
			&p.ID, &p.ProjectID, &p.LicenseID, &p.LicenseName, &p.PolicyType, &p.Reason, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func (r *LicensePolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM license_policies WHERE id = $1`
	result, err := r.q(ctx).ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("license policy not found")
	}
	return nil
}

func (r *LicensePolicyRepository) GetByLicenseID(ctx context.Context, projectID uuid.UUID, licenseID string) (*model.LicensePolicy, error) {
	query := `
		SELECT id, project_id, license_id, license_name, policy_type, reason, created_at, updated_at
		FROM license_policies
		WHERE project_id = $1 AND license_id = $2
	`
	var p model.LicensePolicy
	err := r.q(ctx).QueryRowContext(ctx, query, projectID, licenseID).Scan(
		&p.ID, &p.ProjectID, &p.LicenseID, &p.LicenseName, &p.PolicyType, &p.Reason, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetPoliciesForLicenses returns policies that match the given license IDs
func (r *LicensePolicyRepository) GetPoliciesForLicenses(ctx context.Context, projectID uuid.UUID, licenseIDs []string) (map[string]*model.LicensePolicy, error) {
	if len(licenseIDs) == 0 {
		return make(map[string]*model.LicensePolicy), nil
	}

	query := `
		SELECT id, project_id, license_id, license_name, policy_type, reason, created_at, updated_at
		FROM license_policies
		WHERE project_id = $1 AND license_id = ANY($2)
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, projectID, pq.Array(licenseIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]*model.LicensePolicy)
	for rows.Next() {
		var p model.LicensePolicy
		if err := rows.Scan(
			&p.ID, &p.ProjectID, &p.LicenseID, &p.LicenseName, &p.PolicyType, &p.Reason, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result[p.LicenseID] = &p
	}
	return result, nil
}

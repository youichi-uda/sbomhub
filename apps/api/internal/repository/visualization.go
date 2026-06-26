package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// VisualizationRepository persists per-project METI visualization
// framework settings (the (a)-(f) classification: who made the SBOM,
// dependency scope, generation method, data format, utilization scope
// and actor).
//
// M4 Codex review round 13 / F73: every method takes tenantID as the
// first scoping argument and includes `AND tenant_id = $N` in the
// WHERE / DO UPDATE WHERE clause. Mirrors the ChecklistRepository
// hardening -- the SQL-layer (migration 040) and app-layer guards are
// independent and either alone is sufficient; we ship both so a
// regression in one is caught by the other.
//
// M4 Codex review round 14 / F74: every query routes through r.q(ctx)
// rather than r.db directly, so the request-scoped *sql.Tx attached by
// middleware.TenantTx is reused. Without this, RLS would not see the
// SET LOCAL app.current_tenant_id GUC and every read/write would return
// 0 rows / be rejected by WITH CHECK (production blocker).
type VisualizationRepository struct {
	db *sql.DB
}

func NewVisualizationRepository(db *sql.DB) *VisualizationRepository {
	return &VisualizationRepository{db: db}
}

// q routes the statement through the request-scoped *sql.Tx attached to
// ctx by middleware.TenantTx when one is present; otherwise it falls
// back to r.db. See the ChecklistRepository.q docstring for the full
// rationale -- this is the F74 production-blocker fix that makes the
// SET LOCAL app.current_tenant_id GUC visible to migration 040's RLS.
func (r *VisualizationRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// GetByProject returns visualization settings for a project, scoped to
// the caller's tenant. tenantID MUST come from the authenticated
// session (NOT from request path / body) -- F73 regression class.
func (r *VisualizationRepository) GetByProject(ctx context.Context, tenantID, projectID uuid.UUID) (*model.VisualizationSettings, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("VisualizationRepository.GetByProject: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("VisualizationRepository.GetByProject: project_id is required")
	}
	query := `
		SELECT id, tenant_id, project_id, sbom_author_scope, dependency_scope,
		       generation_method, data_format, utilization_scope, utilization_actor,
		       created_at, updated_at
		FROM sbom_visualization_settings
		WHERE tenant_id = $1 AND project_id = $2
	`
	var settings model.VisualizationSettings
	var utilizationScopeJSON []byte
	err := r.q(ctx).QueryRowContext(ctx, query, tenantID, projectID).Scan(
		&settings.ID, &settings.TenantID, &settings.ProjectID,
		&settings.SBOMAuthorScope, &settings.DependencyScope,
		&settings.GenerationMethod, &settings.DataFormat,
		&utilizationScopeJSON, &settings.UtilizationActor,
		&settings.CreatedAt, &settings.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Parse JSONB utilization_scope
	if len(utilizationScopeJSON) > 0 {
		if err := json.Unmarshal(utilizationScopeJSON, &settings.UtilizationScope); err != nil {
			return nil, err
		}
	}
	return &settings, nil
}

// Upsert creates or updates visualization settings.
//
// settings.TenantID is the WRITE intent; the ON CONFLICT DO UPDATE arm
// carries an explicit `WHERE sbom_visualization_settings.tenant_id =
// EXCLUDED.tenant_id` guard so a tenant-A session that happens to land
// on a tenant-B project_id row cannot overwrite it. Defense-in-depth
// pair with migration 040 RLS WITH CHECK. F73 regression class.
func (r *VisualizationRepository) Upsert(ctx context.Context, settings *model.VisualizationSettings) error {
	if settings == nil {
		return fmt.Errorf("VisualizationRepository.Upsert: settings is required")
	}
	if settings.TenantID == uuid.Nil {
		return fmt.Errorf("VisualizationRepository.Upsert: tenant_id is required")
	}
	if settings.ProjectID == uuid.Nil {
		return fmt.Errorf("VisualizationRepository.Upsert: project_id is required")
	}

	now := time.Now()
	settings.UpdatedAt = now

	// Serialize utilization_scope to JSONB
	utilizationScopeJSON, err := json.Marshal(settings.UtilizationScope)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO sbom_visualization_settings (
			id, tenant_id, project_id, sbom_author_scope, dependency_scope,
			generation_method, data_format, utilization_scope, utilization_actor,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (project_id)
		DO UPDATE SET
			sbom_author_scope = EXCLUDED.sbom_author_scope,
			dependency_scope  = EXCLUDED.dependency_scope,
			generation_method = EXCLUDED.generation_method,
			data_format       = EXCLUDED.data_format,
			utilization_scope = EXCLUDED.utilization_scope,
			utilization_actor = EXCLUDED.utilization_actor,
			updated_at        = EXCLUDED.updated_at
		WHERE sbom_visualization_settings.tenant_id = EXCLUDED.tenant_id
	`
	if settings.ID == uuid.Nil {
		settings.ID = uuid.New()
		settings.CreatedAt = now
	}
	_, err = r.q(ctx).ExecContext(ctx, query,
		settings.ID, settings.TenantID, settings.ProjectID,
		settings.SBOMAuthorScope, settings.DependencyScope,
		settings.GenerationMethod, settings.DataFormat,
		utilizationScopeJSON, settings.UtilizationActor,
		settings.CreatedAt, settings.UpdatedAt,
	)
	return err
}

// Delete removes visualization settings for a project, scoped to the
// caller's tenant. F73 regression class: a tenant-A session must not
// be able to delete a tenant-B row by guessing the project_id.
func (r *VisualizationRepository) Delete(ctx context.Context, tenantID, projectID uuid.UUID) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("VisualizationRepository.Delete: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return fmt.Errorf("VisualizationRepository.Delete: project_id is required")
	}
	query := `DELETE FROM sbom_visualization_settings WHERE tenant_id = $1 AND project_id = $2`
	_, err := r.q(ctx).ExecContext(ctx, query, tenantID, projectID)
	return err
}

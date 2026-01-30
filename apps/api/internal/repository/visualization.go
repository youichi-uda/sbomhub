package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type VisualizationRepository struct {
	db *sql.DB
}

func NewVisualizationRepository(db *sql.DB) *VisualizationRepository {
	return &VisualizationRepository{db: db}
}

// GetByProject returns visualization settings for a project
func (r *VisualizationRepository) GetByProject(ctx context.Context, projectID uuid.UUID) (*model.VisualizationSettings, error) {
	query := `
		SELECT id, tenant_id, project_id, sbom_author_scope, dependency_scope,
		       generation_method, data_format, utilization_scope, utilization_actor,
		       created_at, updated_at
		FROM sbom_visualization_settings
		WHERE project_id = $1
	`
	var settings model.VisualizationSettings
	var utilizationScopeJSON []byte
	err := r.db.QueryRowContext(ctx, query, projectID).Scan(
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

// Upsert creates or updates visualization settings
func (r *VisualizationRepository) Upsert(ctx context.Context, settings *model.VisualizationSettings) error {
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
			sbom_author_scope = $4, dependency_scope = $5,
			generation_method = $6, data_format = $7,
			utilization_scope = $8, utilization_actor = $9,
			updated_at = $11
	`
	if settings.ID == uuid.Nil {
		settings.ID = uuid.New()
		settings.CreatedAt = now
	}
	_, err = r.db.ExecContext(ctx, query,
		settings.ID, settings.TenantID, settings.ProjectID,
		settings.SBOMAuthorScope, settings.DependencyScope,
		settings.GenerationMethod, settings.DataFormat,
		utilizationScopeJSON, settings.UtilizationActor,
		settings.CreatedAt, settings.UpdatedAt,
	)
	return err
}

// Delete removes visualization settings for a project
func (r *VisualizationRepository) Delete(ctx context.Context, projectID uuid.UUID) error {
	query := `DELETE FROM sbom_visualization_settings WHERE project_id = $1`
	_, err := r.db.ExecContext(ctx, query, projectID)
	return err
}

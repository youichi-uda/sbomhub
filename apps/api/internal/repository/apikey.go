package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type APIKeyRepository struct {
	db *sql.DB
}

func NewAPIKeyRepository(db *sql.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

func (r *APIKeyRepository) Create(ctx context.Context, k *model.APIKey) error {
	query := `
		INSERT INTO api_keys (id, project_id, name, key_hash, key_prefix, permissions, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.db.ExecContext(ctx, query,
		k.ID, k.ProjectID, k.Name, k.KeyHash, k.KeyPrefix, k.Permissions, k.ExpiresAt, k.CreatedAt,
	)
	return err
}

func (r *APIKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.APIKey, error) {
	query := `
		SELECT id, project_id, name, key_hash, key_prefix, permissions, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE id = $1
	`
	var k model.APIKey
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&k.ID, &k.ProjectID, &k.Name, &k.KeyHash, &k.KeyPrefix, &k.Permissions, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (r *APIKeyRepository) GetByKeyHash(ctx context.Context, keyHash string) (*model.APIKey, error) {
	query := `
		SELECT id, project_id, name, key_hash, key_prefix, permissions, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE key_hash = $1
	`
	var k model.APIKey
	err := r.db.QueryRowContext(ctx, query, keyHash).Scan(
		&k.ID, &k.ProjectID, &k.Name, &k.KeyHash, &k.KeyPrefix, &k.Permissions, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (r *APIKeyRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.APIKey, error) {
	query := `
		SELECT id, project_id, name, key_hash, key_prefix, permissions, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE project_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []model.APIKey
	for rows.Next() {
		var k model.APIKey
		if err := rows.Scan(
			&k.ID, &k.ProjectID, &k.Name, &k.KeyHash, &k.KeyPrefix, &k.Permissions, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
		); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (r *APIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM api_keys WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET last_used_at = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), id)
	return err
}

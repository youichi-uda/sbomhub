package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

type AuditRepository struct {
	db *sql.DB
}

func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Create(ctx context.Context, a *model.AuditLog) error {
	detailsJSON, err := json.Marshal(a.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	query := `
		INSERT INTO audit_logs (
			id, tenant_id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err = r.db.ExecContext(ctx, query,
		a.ID, a.TenantID, a.UserID, a.Action, a.ResourceType, a.ResourceID,
		detailsJSON, a.IPAddress.String(), a.UserAgent, a.CreatedAt)
	return err
}

func (r *AuditRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]model.AuditLog, error) {
	query := `
		SELECT id, tenant_id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		FROM audit_logs
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []model.AuditLog
	for rows.Next() {
		var a model.AuditLog
		var detailsJSON []byte
		var ipStr sql.NullString
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.UserID, &a.Action, &a.ResourceType, &a.ResourceID,
			&detailsJSON, &ipStr, &a.UserAgent, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		if len(detailsJSON) > 0 {
			json.Unmarshal(detailsJSON, &a.Details)
		}
		if ipStr.Valid {
			a.IPAddress = net.ParseIP(ipStr.String)
		}
		logs = append(logs, a)
	}
	return logs, nil
}

func (r *AuditRepository) ListByUser(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]model.AuditLog, error) {
	query := `
		SELECT id, tenant_id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		FROM audit_logs
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []model.AuditLog
	for rows.Next() {
		var a model.AuditLog
		var detailsJSON []byte
		var ipStr sql.NullString
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.UserID, &a.Action, &a.ResourceType, &a.ResourceID,
			&detailsJSON, &ipStr, &a.UserAgent, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		if len(detailsJSON) > 0 {
			json.Unmarshal(detailsJSON, &a.Details)
		}
		if ipStr.Valid {
			a.IPAddress = net.ParseIP(ipStr.String)
		}
		logs = append(logs, a)
	}
	return logs, nil
}

func (r *AuditRepository) ListByResource(ctx context.Context, tenantID uuid.UUID, resourceType string, resourceID uuid.UUID, limit, offset int) ([]model.AuditLog, error) {
	query := `
		SELECT id, tenant_id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		FROM audit_logs
		WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
		ORDER BY created_at DESC
		LIMIT $4 OFFSET $5
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID, resourceType, resourceID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []model.AuditLog
	for rows.Next() {
		var a model.AuditLog
		var detailsJSON []byte
		var ipStr sql.NullString
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.UserID, &a.Action, &a.ResourceType, &a.ResourceID,
			&detailsJSON, &ipStr, &a.UserAgent, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		if len(detailsJSON) > 0 {
			json.Unmarshal(detailsJSON, &a.Details)
		}
		if ipStr.Valid {
			a.IPAddress = net.ParseIP(ipStr.String)
		}
		logs = append(logs, a)
	}
	return logs, nil
}

func (r *AuditRepository) Count(ctx context.Context, tenantID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&count)
	return count, err
}

// DeleteOlderThan deletes audit logs older than the specified duration
func (r *AuditRepository) DeleteOlderThan(ctx context.Context, tenantID uuid.UUID, before time.Time) (int64, error) {
	query := `DELETE FROM audit_logs WHERE tenant_id = $1 AND created_at < $2`
	result, err := r.db.ExecContext(ctx, query, tenantID, before)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Log is a convenience method to create an audit log
func (r *AuditRepository) Log(ctx context.Context, input *model.CreateAuditLogInput) error {
	var ip net.IP
	if input.IPAddress != "" {
		ip = net.ParseIP(input.IPAddress)
	}

	log := &model.AuditLog{
		ID:           uuid.New(),
		TenantID:     input.TenantID,
		UserID:       input.UserID,
		Action:       input.Action,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		Details:      input.Details,
		IPAddress:    ip,
		UserAgent:    input.UserAgent,
		CreatedAt:    time.Now(),
	}
	return r.Create(ctx, log)
}

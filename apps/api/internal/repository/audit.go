package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

// AuditFilter defines filter options for audit log queries
type AuditFilter struct {
	Action       string
	ResourceType string
	UserID       *uuid.UUID
	StartDate    *time.Time
	EndDate      *time.Time
	Limit        int
	Offset       int
}

// ListWithFilter returns audit logs with filtering support
func (r *AuditRepository) ListWithFilter(ctx context.Context, tenantID uuid.UUID, filter AuditFilter) ([]model.AuditLog, int, error) {
	// Build query with filters
	baseQuery := `
		FROM audit_logs
		WHERE tenant_id = $1
	`
	args := []interface{}{tenantID}
	argIndex := 2

	if filter.Action != "" {
		baseQuery += fmt.Sprintf(" AND action = $%d", argIndex)
		args = append(args, filter.Action)
		argIndex++
	}

	if filter.ResourceType != "" {
		baseQuery += fmt.Sprintf(" AND resource_type = $%d", argIndex)
		args = append(args, filter.ResourceType)
		argIndex++
	}

	if filter.UserID != nil {
		baseQuery += fmt.Sprintf(" AND user_id = $%d", argIndex)
		args = append(args, *filter.UserID)
		argIndex++
	}

	if filter.StartDate != nil {
		baseQuery += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, *filter.StartDate)
		argIndex++
	}

	if filter.EndDate != nil {
		baseQuery += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, *filter.EndDate)
		argIndex++
	}

	// Get total count
	countQuery := `SELECT COUNT(*) ` + baseQuery
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Get paginated results
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	selectQuery := fmt.Sprintf(`
		SELECT id, tenant_id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
	%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, baseQuery, argIndex, argIndex+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
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
			return nil, 0, err
		}
		if len(detailsJSON) > 0 {
			json.Unmarshal(detailsJSON, &a.Details)
		}
		if ipStr.Valid {
			a.IPAddress = net.ParseIP(ipStr.String)
		}
		logs = append(logs, a)
	}

	return logs, total, nil
}

// ActionCount represents the count of a specific action
type ActionCount struct {
	Action string `json:"action"`
	Count  int    `json:"count"`
}

// GetActionCounts returns action statistics for a given period
func (r *AuditRepository) GetActionCounts(ctx context.Context, tenantID uuid.UUID, start, end time.Time) ([]ActionCount, error) {
	query := `
		SELECT action, COUNT(*) as count
		FROM audit_logs
		WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
		GROUP BY action
		ORDER BY count DESC
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var counts []ActionCount
	for rows.Next() {
		var ac ActionCount
		if err := rows.Scan(&ac.Action, &ac.Count); err != nil {
			return nil, err
		}
		counts = append(counts, ac)
	}
	return counts, nil
}

// GetDailyActionCounts returns daily action counts for charting
func (r *AuditRepository) GetDailyActionCounts(ctx context.Context, tenantID uuid.UUID, days int) ([]map[string]interface{}, error) {
	query := `
		SELECT DATE(created_at) as date, action, COUNT(*) as count
		FROM audit_logs
		WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '1 day' * $2
		GROUP BY DATE(created_at), action
		ORDER BY date DESC, count DESC
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var date time.Time
		var action string
		var count int
		if err := rows.Scan(&date, &action, &count); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"date":   date.Format("2006-01-02"),
			"action": action,
			"count":  count,
		})
	}
	return results, nil
}

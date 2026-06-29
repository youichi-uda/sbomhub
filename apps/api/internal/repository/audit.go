package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

type AuditRepository struct {
	db *sql.DB
}

func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
//
// RLS history note: migration 023 originally put audit_logs under FORCE ROW
// LEVEL SECURITY with a tenant-scoped policy. That broke webhook-driven
// audit INSERTs (Clerk / Lemon Squeezy handlers run with no tenant GUC, so
// the policy evaluated to NULL and silently rejected the row). Migration
// 029 dropped the policy; tenant scope on every audit_logs read is now
// enforced by explicit `WHERE tenant_id = $N` clauses in this file. The
// `q(ctx)` indirection still matters: when the caller is inside a TenantTx
// transaction the INSERT should join that tx so it commits/rolls back
// atomically with the rest of the request. Webhook callers have no tx and
// fall through to r.db, which is fine now that RLS is off.
func (r *AuditRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Create inserts an audit log row. After migration 029 there is no RLS on
// audit_logs, so this INSERT succeeds even when the caller has no tenant
// GUC set (webhook handlers, background jobs, etc.). a.TenantID MAY be nil
// for system-level events; such rows are invisible to tenant-scoped reads
// by construction (every List/Get below filters with `tenant_id = $1`).
//
// M9 F158: the audit_logs.ip_address column is inet NULL. net.IP(nil).String()
// returns the literal "<nil>", which PG inet rejects. Pass NULL when the
// IP is unset; webhook handlers (webhook_clerk.go, webhook_lemonsqueezy.go)
// construct AuditLog values with IPAddress=nil and would otherwise fail
// the INSERT.
func (r *AuditRepository) Create(ctx context.Context, a *model.AuditLog) error {
	detailsJSON, err := json.Marshal(a.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	var ipArg interface{}
	if len(a.IPAddress) > 0 && !a.IPAddress.IsUnspecified() {
		ipArg = a.IPAddress.String()
	}

	query := `
		INSERT INTO audit_logs (
			id, tenant_id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err = r.q(ctx).ExecContext(ctx, query,
		a.ID, a.TenantID, a.UserID, a.Action, a.ResourceType, a.ResourceID,
		detailsJSON, ipArg, a.UserAgent, a.CreatedAt)
	return err
}

// List returns paginated audit log rows for a single tenant.
//
// The `WHERE tenant_id = $1` filter is load-bearing: migration 029 removed
// the RLS policy on audit_logs, so this clause is what isolates tenants.
// Callers MUST pass the tenant id from the authenticated session — never a
// tenant_id read from a user-supplied request body — otherwise this becomes
// a cross-tenant information-disclosure primitive. The filter also excludes
// rows with `tenant_id IS NULL` (system-level events written by webhook
// handlers), which is the intended behavior for a tenant audit view.
func (r *AuditRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]model.AuditLog, error) {
	query := `
		SELECT id, tenant_id, user_id, action, resource_type, resource_id,
			details, ip_address, user_agent, created_at
		FROM audit_logs
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, limit, offset)
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
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, userID, limit, offset)
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
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, resourceType, resourceID, limit, offset)
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
	err := r.q(ctx).QueryRowContext(ctx, query, tenantID).Scan(&count)
	return count, err
}

// DeleteOlderThan deletes audit logs older than the specified duration
func (r *AuditRepository) DeleteOlderThan(ctx context.Context, tenantID uuid.UUID, before time.Time) (int64, error) {
	query := `DELETE FROM audit_logs WHERE tenant_id = $1 AND created_at < $2`
	result, err := r.q(ctx).ExecContext(ctx, query, tenantID, before)
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
	if err := r.q(ctx).QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
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

	rows, err := r.q(ctx).QueryContext(ctx, selectQuery, args...)
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
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, start, end)
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
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, days)
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

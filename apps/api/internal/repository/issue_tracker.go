package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// IssueTrackerRepository handles issue tracker data access
type IssueTrackerRepository struct {
	db *sql.DB
}

// NewIssueTrackerRepository creates a new IssueTrackerRepository
func NewIssueTrackerRepository(db *sql.DB) *IssueTrackerRepository {
	return &IssueTrackerRepository{db: db}
}

// CreateConnection creates a new issue tracker connection
func (r *IssueTrackerRepository) CreateConnection(ctx context.Context, conn *model.IssueTrackerConnection) error {
	query := `
		INSERT INTO issue_tracker_connections (
			id, tenant_id, tracker_type, name, base_url, auth_type, auth_email,
			auth_token_encrypted, default_project_key, default_issue_type, is_active,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
	`
	_, err := r.db.ExecContext(ctx, query,
		conn.ID, conn.TenantID, conn.TrackerType, conn.Name, conn.BaseURL,
		conn.AuthType, conn.AuthEmail, conn.AuthTokenEncrypted,
		conn.DefaultProjectKey, conn.DefaultIssueType, conn.IsActive,
	)
	return err
}

// GetConnection gets a connection by ID
func (r *IssueTrackerRepository) GetConnection(ctx context.Context, id uuid.UUID) (*model.IssueTrackerConnection, error) {
	query := `
		SELECT id, tenant_id, tracker_type, name, base_url, auth_type, auth_email,
			auth_token_encrypted, default_project_key, default_issue_type, is_active,
			last_sync_at, created_at, updated_at
		FROM issue_tracker_connections
		WHERE id = $1
	`

	var conn model.IssueTrackerConnection
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&conn.ID, &conn.TenantID, &conn.TrackerType, &conn.Name, &conn.BaseURL,
		&conn.AuthType, &conn.AuthEmail, &conn.AuthTokenEncrypted,
		&conn.DefaultProjectKey, &conn.DefaultIssueType, &conn.IsActive,
		&conn.LastSyncAt, &conn.CreatedAt, &conn.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &conn, nil
}

// ListConnections lists connections for a tenant
func (r *IssueTrackerRepository) ListConnections(ctx context.Context, tenantID uuid.UUID) ([]model.IssueTrackerConnection, error) {
	query := `
		SELECT id, tenant_id, tracker_type, name, base_url, auth_type, auth_email,
			auth_token_encrypted, default_project_key, default_issue_type, is_active,
			last_sync_at, created_at, updated_at
		FROM issue_tracker_connections
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []model.IssueTrackerConnection
	for rows.Next() {
		var conn model.IssueTrackerConnection
		if err := rows.Scan(
			&conn.ID, &conn.TenantID, &conn.TrackerType, &conn.Name, &conn.BaseURL,
			&conn.AuthType, &conn.AuthEmail, &conn.AuthTokenEncrypted,
			&conn.DefaultProjectKey, &conn.DefaultIssueType, &conn.IsActive,
			&conn.LastSyncAt, &conn.CreatedAt, &conn.UpdatedAt,
		); err != nil {
			return nil, err
		}
		connections = append(connections, conn)
	}

	return connections, nil
}

// ListConnectionsByType lists connections of a specific type for a tenant
func (r *IssueTrackerRepository) ListConnectionsByType(ctx context.Context, tenantID uuid.UUID, trackerType model.TrackerType) ([]model.IssueTrackerConnection, error) {
	query := `
		SELECT id, tenant_id, tracker_type, name, base_url, auth_type, auth_email,
			auth_token_encrypted, default_project_key, default_issue_type, is_active,
			last_sync_at, created_at, updated_at
		FROM issue_tracker_connections
		WHERE tenant_id = $1 AND tracker_type = $2
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, trackerType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []model.IssueTrackerConnection
	for rows.Next() {
		var conn model.IssueTrackerConnection
		if err := rows.Scan(
			&conn.ID, &conn.TenantID, &conn.TrackerType, &conn.Name, &conn.BaseURL,
			&conn.AuthType, &conn.AuthEmail, &conn.AuthTokenEncrypted,
			&conn.DefaultProjectKey, &conn.DefaultIssueType, &conn.IsActive,
			&conn.LastSyncAt, &conn.CreatedAt, &conn.UpdatedAt,
		); err != nil {
			return nil, err
		}
		connections = append(connections, conn)
	}

	return connections, nil
}

// UpdateConnection updates a connection
func (r *IssueTrackerRepository) UpdateConnection(ctx context.Context, conn *model.IssueTrackerConnection) error {
	query := `
		UPDATE issue_tracker_connections SET
			name = $2, base_url = $3, auth_type = $4, auth_email = $5,
			auth_token_encrypted = $6, default_project_key = $7, default_issue_type = $8,
			is_active = $9, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query,
		conn.ID, conn.Name, conn.BaseURL, conn.AuthType, conn.AuthEmail,
		conn.AuthTokenEncrypted, conn.DefaultProjectKey, conn.DefaultIssueType,
		conn.IsActive,
	)
	return err
}

// DeleteConnection deletes a connection
func (r *IssueTrackerRepository) DeleteConnection(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM issue_tracker_connections WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// UpdateConnectionSyncTime updates the last sync time for a connection
func (r *IssueTrackerRepository) UpdateConnectionSyncTime(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE issue_tracker_connections SET last_sync_at = NOW(), updated_at = NOW() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// CreateTicket creates a new vulnerability ticket
func (r *IssueTrackerRepository) CreateTicket(ctx context.Context, ticket *model.VulnerabilityTicket) error {
	query := `
		INSERT INTO vulnerability_tickets (
			id, tenant_id, vulnerability_id, project_id, connection_id,
			external_ticket_id, external_ticket_key, external_ticket_url,
			local_status, external_status, priority, assignee, summary,
			last_synced_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), NOW())
	`
	_, err := r.db.ExecContext(ctx, query,
		ticket.ID, ticket.TenantID, ticket.VulnerabilityID, ticket.ProjectID,
		ticket.ConnectionID, ticket.ExternalTicketID, ticket.ExternalTicketKey,
		ticket.ExternalTicketURL, ticket.LocalStatus, ticket.ExternalStatus,
		ticket.Priority, ticket.Assignee, ticket.Summary, ticket.LastSyncedAt,
	)
	return err
}

// GetTicket gets a ticket by ID
func (r *IssueTrackerRepository) GetTicket(ctx context.Context, id uuid.UUID) (*model.VulnerabilityTicket, error) {
	query := `
		SELECT id, tenant_id, vulnerability_id, project_id, connection_id,
			external_ticket_id, external_ticket_key, external_ticket_url,
			local_status, external_status, priority, assignee, summary,
			last_synced_at, created_at, updated_at
		FROM vulnerability_tickets
		WHERE id = $1
	`

	var ticket model.VulnerabilityTicket
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&ticket.ID, &ticket.TenantID, &ticket.VulnerabilityID, &ticket.ProjectID,
		&ticket.ConnectionID, &ticket.ExternalTicketID, &ticket.ExternalTicketKey,
		&ticket.ExternalTicketURL, &ticket.LocalStatus, &ticket.ExternalStatus,
		&ticket.Priority, &ticket.Assignee, &ticket.Summary,
		&ticket.LastSyncedAt, &ticket.CreatedAt, &ticket.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &ticket, nil
}

// GetTicketByVulnerability gets a ticket by vulnerability ID and connection ID
func (r *IssueTrackerRepository) GetTicketByVulnerability(ctx context.Context, vulnID, connectionID uuid.UUID) (*model.VulnerabilityTicket, error) {
	query := `
		SELECT id, tenant_id, vulnerability_id, project_id, connection_id,
			external_ticket_id, external_ticket_key, external_ticket_url,
			local_status, external_status, priority, assignee, summary,
			last_synced_at, created_at, updated_at
		FROM vulnerability_tickets
		WHERE vulnerability_id = $1 AND connection_id = $2
	`

	var ticket model.VulnerabilityTicket
	err := r.db.QueryRowContext(ctx, query, vulnID, connectionID).Scan(
		&ticket.ID, &ticket.TenantID, &ticket.VulnerabilityID, &ticket.ProjectID,
		&ticket.ConnectionID, &ticket.ExternalTicketID, &ticket.ExternalTicketKey,
		&ticket.ExternalTicketURL, &ticket.LocalStatus, &ticket.ExternalStatus,
		&ticket.Priority, &ticket.Assignee, &ticket.Summary,
		&ticket.LastSyncedAt, &ticket.CreatedAt, &ticket.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &ticket, nil
}

// ListTicketsByVulnerability lists all tickets for a vulnerability
func (r *IssueTrackerRepository) ListTicketsByVulnerability(ctx context.Context, vulnID uuid.UUID) ([]model.VulnerabilityTicketWithDetails, error) {
	query := `
		SELECT t.id, t.tenant_id, t.vulnerability_id, t.project_id, t.connection_id,
			t.external_ticket_id, t.external_ticket_key, t.external_ticket_url,
			t.local_status, t.external_status, t.priority, t.assignee, t.summary,
			t.last_synced_at, t.created_at, t.updated_at,
			v.cve_id, v.severity, c.tracker_type, c.name, p.name
		FROM vulnerability_tickets t
		JOIN vulnerabilities v ON t.vulnerability_id = v.id
		JOIN issue_tracker_connections c ON t.connection_id = c.id
		JOIN projects p ON t.project_id = p.id
		WHERE t.vulnerability_id = $1
		ORDER BY t.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, vulnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tickets []model.VulnerabilityTicketWithDetails
	for rows.Next() {
		var t model.VulnerabilityTicketWithDetails
		if err := rows.Scan(
			&t.ID, &t.TenantID, &t.VulnerabilityID, &t.ProjectID, &t.ConnectionID,
			&t.ExternalTicketID, &t.ExternalTicketKey, &t.ExternalTicketURL,
			&t.LocalStatus, &t.ExternalStatus, &t.Priority, &t.Assignee, &t.Summary,
			&t.LastSyncedAt, &t.CreatedAt, &t.UpdatedAt,
			&t.CVEID, &t.Severity, &t.TrackerType, &t.TrackerName, &t.ProjectName,
		); err != nil {
			return nil, err
		}
		tickets = append(tickets, t)
	}

	return tickets, nil
}

// ListTickets lists tickets for a tenant with optional filters
func (r *IssueTrackerRepository) ListTickets(ctx context.Context, tenantID uuid.UUID, status string, limit, offset int) ([]model.VulnerabilityTicketWithDetails, int, error) {
	// Count query
	countQuery := `SELECT COUNT(*) FROM vulnerability_tickets WHERE tenant_id = $1`
	countArgs := []interface{}{tenantID}
	argIndex := 2

	if status != "" {
		countQuery += fmt.Sprintf(` AND local_status = $%d`, argIndex)
		countArgs = append(countArgs, status)
		argIndex++
	}

	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// List query
	query := `
		SELECT t.id, t.tenant_id, t.vulnerability_id, t.project_id, t.connection_id,
			t.external_ticket_id, t.external_ticket_key, t.external_ticket_url,
			t.local_status, t.external_status, t.priority, t.assignee, t.summary,
			t.last_synced_at, t.created_at, t.updated_at,
			v.cve_id, v.severity, c.tracker_type, c.name, p.name
		FROM vulnerability_tickets t
		JOIN vulnerabilities v ON t.vulnerability_id = v.id
		JOIN issue_tracker_connections c ON t.connection_id = c.id
		JOIN projects p ON t.project_id = p.id
		WHERE t.tenant_id = $1
	`
	args := []interface{}{tenantID}
	argIndex = 2

	if status != "" {
		query += fmt.Sprintf(` AND t.local_status = $%d`, argIndex)
		args = append(args, status)
		argIndex++
	}

	query += fmt.Sprintf(` ORDER BY t.created_at DESC LIMIT $%d OFFSET $%d`, argIndex, argIndex+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var tickets []model.VulnerabilityTicketWithDetails
	for rows.Next() {
		var t model.VulnerabilityTicketWithDetails
		if err := rows.Scan(
			&t.ID, &t.TenantID, &t.VulnerabilityID, &t.ProjectID, &t.ConnectionID,
			&t.ExternalTicketID, &t.ExternalTicketKey, &t.ExternalTicketURL,
			&t.LocalStatus, &t.ExternalStatus, &t.Priority, &t.Assignee, &t.Summary,
			&t.LastSyncedAt, &t.CreatedAt, &t.UpdatedAt,
			&t.CVEID, &t.Severity, &t.TrackerType, &t.TrackerName, &t.ProjectName,
		); err != nil {
			return nil, 0, err
		}
		tickets = append(tickets, t)
	}

	return tickets, total, nil
}

// UpdateTicket updates a ticket
func (r *IssueTrackerRepository) UpdateTicket(ctx context.Context, ticket *model.VulnerabilityTicket) error {
	query := `
		UPDATE vulnerability_tickets SET
			local_status = $2, external_status = $3, priority = $4,
			assignee = $5, summary = $6, last_synced_at = $7, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query,
		ticket.ID, ticket.LocalStatus, ticket.ExternalStatus,
		ticket.Priority, ticket.Assignee, ticket.Summary, ticket.LastSyncedAt,
	)
	return err
}

// GetTicketsToSync gets tickets that need to be synced
func (r *IssueTrackerRepository) GetTicketsToSync(ctx context.Context, olderThan time.Duration) ([]model.VulnerabilityTicket, error) {
	cutoff := time.Now().Add(-olderThan)
	query := `
		SELECT t.id, t.tenant_id, t.vulnerability_id, t.project_id, t.connection_id,
			t.external_ticket_id, t.external_ticket_key, t.external_ticket_url,
			t.local_status, t.external_status, t.priority, t.assignee, t.summary,
			t.last_synced_at, t.created_at, t.updated_at
		FROM vulnerability_tickets t
		JOIN issue_tracker_connections c ON t.connection_id = c.id
		WHERE c.is_active = true
			AND t.local_status NOT IN ('resolved', 'closed')
			AND (t.last_synced_at IS NULL OR t.last_synced_at < $1)
		LIMIT 100
	`

	rows, err := r.db.QueryContext(ctx, query, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tickets []model.VulnerabilityTicket
	for rows.Next() {
		var t model.VulnerabilityTicket
		if err := rows.Scan(
			&t.ID, &t.TenantID, &t.VulnerabilityID, &t.ProjectID, &t.ConnectionID,
			&t.ExternalTicketID, &t.ExternalTicketKey, &t.ExternalTicketURL,
			&t.LocalStatus, &t.ExternalStatus, &t.Priority, &t.Assignee, &t.Summary,
			&t.LastSyncedAt, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, err
		}
		tickets = append(tickets, t)
	}

	return tickets, nil
}

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// M47 W2 — sentinels for the 0-row mutation contract on this repository.
//
// `issue_tracker_connections` and `vulnerability_tickets` are both ENABLE +
// FORCE ROW LEVEL SECURITY (migration 042, verified against pg_class), so
// RLS is the braces that stops a cross-tenant write. What was missing was
// the belt AND the ability to notice: every mutation below ran
// `WHERE id = $1` with no tenant predicate and discarded its result, so a
// blocked cross-tenant statement matched 0 rows and returned nil.
// `DELETE /api/v1/integrations/:id` therefore answered 204 for a connection
// that still exists (carried over from M47 W1).
//
// Both sentinels wrap sql.ErrNoRows — see ErrTenantUserNotFound
// (repository/user.go) for the rationale.
var (
	// ErrIssueTrackerConnectionNotFound is returned by UpdateConnection /
	// DeleteConnection / UpdateConnectionSyncTime when the statement matched
	// no `issue_tracker_connections` row for the calling tenant.
	ErrIssueTrackerConnectionNotFound = fmt.Errorf("issue_tracker_connections: no row matched for this tenant: %w", sql.ErrNoRows)

	// ErrVulnerabilityTicketNotFound is returned by UpdateTicket when the
	// statement matched no `vulnerability_tickets` row for the calling
	// tenant.
	ErrVulnerabilityTicketNotFound = fmt.Errorf("vulnerability_tickets: no row matched for this tenant: %w", sql.ErrNoRows)
)

// IssueTrackerRepository handles issue tracker data access
type IssueTrackerRepository struct {
	db *sql.DB
}

// NewIssueTrackerRepository creates a new IssueTrackerRepository
func NewIssueTrackerRepository(db *sql.DB) *IssueTrackerRepository {
	return &IssueTrackerRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one is
// attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db otherwise.
func (r *IssueTrackerRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
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
	_, err := r.q(ctx).ExecContext(ctx, query,
		conn.ID, conn.TenantID, conn.TrackerType, conn.Name, conn.BaseURL,
		conn.AuthType, conn.AuthEmail, conn.AuthTokenEncrypted,
		conn.DefaultProjectKey, conn.DefaultIssueType, conn.IsActive,
	)
	return err
}

// GetConnection gets a connection by ID.
//
// auth_email, default_project_key, and default_issue_type are the three
// nullable string columns of the 015 schema (a GitHub PAT connection has
// no auth_email at all) and the model fields are plain strings, so the
// SELECTs here and in ListConnections / ListConnectionsByType COALESCE
// them to ” — same pattern as GetTicket's external_project_key (F366).
// The application itself always writes ” for absent values
// (CreateConnection / UpdateConnection bind the plain string fields
// directly), but rows seeded by operators / support tooling / direct SQL
// carry NULL, which used to abort the scan with "converting NULL to
// string is unsupported" and take down ticket_sync for the whole tenant.
// last_sync_at stays a bare column: it scans into *time.Time, where NULL
// is representable and meaningful.
func (r *IssueTrackerRepository) GetConnection(ctx context.Context, id uuid.UUID) (*model.IssueTrackerConnection, error) {
	query := `
		SELECT id, tenant_id, tracker_type, name, base_url, auth_type,
			COALESCE(auth_email, ''),
			auth_token_encrypted,
			COALESCE(default_project_key, ''), COALESCE(default_issue_type, ''),
			is_active, last_sync_at, created_at, updated_at
		FROM issue_tracker_connections
		WHERE id = $1
	`

	var conn model.IssueTrackerConnection
	err := r.q(ctx).QueryRowContext(ctx, query, id).Scan(
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
		SELECT id, tenant_id, tracker_type, name, base_url, auth_type,
			COALESCE(auth_email, ''),
			auth_token_encrypted,
			COALESCE(default_project_key, ''), COALESCE(default_issue_type, ''),
			is_active, last_sync_at, created_at, updated_at
		FROM issue_tracker_connections
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID)
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
	// M46 B-1: a truncated connection list would silently hide a
	// configured tracker (and the UI would offer to re-create it).
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return connections, nil
}

// ListConnectionsByType lists connections of a specific type for a tenant
func (r *IssueTrackerRepository) ListConnectionsByType(ctx context.Context, tenantID uuid.UUID, trackerType model.TrackerType) ([]model.IssueTrackerConnection, error) {
	query := `
		SELECT id, tenant_id, tracker_type, name, base_url, auth_type,
			COALESCE(auth_email, ''),
			auth_token_encrypted,
			COALESCE(default_project_key, ''), COALESCE(default_issue_type, ''),
			is_active, last_sync_at, created_at, updated_at
		FROM issue_tracker_connections
		WHERE tenant_id = $1 AND tracker_type = $2
		ORDER BY created_at DESC
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, trackerType)
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
	// M46 B-1: same fail-closed contract as ListConnections.
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return connections, nil
}

// UpdateConnection updates a connection, restricted to the tenant that owns
// the supplied struct.
//
// M47 W2: `AND tenant_id = $10` is the explicit belt to migration 042's
// FORCE RLS braces (the M47 W1 pattern), and 0 rows returns
// ErrIssueTrackerConnectionNotFound so a refused write cannot be reported
// as a completed one. conn.TenantID must come from a trusted lookup
// (GetConnection / ListConnections), never from a request body.
func (r *IssueTrackerRepository) UpdateConnection(ctx context.Context, conn *model.IssueTrackerConnection) error {
	query := `
		UPDATE issue_tracker_connections SET
			name = $2, base_url = $3, auth_type = $4, auth_email = $5,
			auth_token_encrypted = $6, default_project_key = $7, default_issue_type = $8,
			is_active = $9, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $10
	`
	res, err := r.q(ctx).ExecContext(ctx, query,
		conn.ID, conn.Name, conn.BaseURL, conn.AuthType, conn.AuthEmail,
		conn.AuthTokenEncrypted, conn.DefaultProjectKey, conn.DefaultIssueType,
		conn.IsActive, conn.TenantID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update issue_tracker_connections (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update connection %s for tenant %s: %w", conn.ID, conn.TenantID, ErrIssueTrackerConnectionNotFound)
	}
	return nil
}

// DeleteConnection deletes a connection, restricted to the calling tenant.
//
// M47 W2 (the M47 W1 carry-over): the pre-fix statement was a bare
// `DELETE FROM issue_tracker_connections WHERE id = $1` whose result was
// discarded. RLS blocked the cross-tenant row, the statement matched 0
// rows, and `DELETE /api/v1/integrations/:id` returned 204 for a
// connection that still existed — the caller could not tell "deleted" from
// "someone else's id". tenantID MUST come from the authenticated session.
func (r *IssueTrackerRepository) DeleteConnection(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `DELETE FROM issue_tracker_connections WHERE id = $1 AND tenant_id = $2`
	res, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete issue_tracker_connections (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("delete connection %s for tenant %s: %w", id, tenantID, ErrIssueTrackerConnectionNotFound)
	}
	return nil
}

// UpdateConnectionSyncTime updates the last sync time for a connection,
// restricted to the calling tenant (same belt + audible-0-rows contract as
// its siblings — the asymmetry between the three connection mutations was
// itself the M47 W2 finding).
func (r *IssueTrackerRepository) UpdateConnectionSyncTime(ctx context.Context, tenantID, id uuid.UUID) error {
	query := `UPDATE issue_tracker_connections SET last_sync_at = NOW(), updated_at = NOW() WHERE id = $1 AND tenant_id = $2`
	res, err := r.q(ctx).ExecContext(ctx, query, id, tenantID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update issue_tracker_connections sync time (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update sync time of connection %s for tenant %s: %w", id, tenantID, ErrIssueTrackerConnectionNotFound)
	}
	return nil
}

// CreateTicket creates a new vulnerability ticket
func (r *IssueTrackerRepository) CreateTicket(ctx context.Context, ticket *model.VulnerabilityTicket) error {
	query := `
		INSERT INTO vulnerability_tickets (
			id, tenant_id, vulnerability_id, project_id, connection_id,
			external_ticket_id, external_ticket_key, external_ticket_url,
			external_project_key,
			local_status, external_status, priority, assignee, summary,
			last_synced_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW(), NOW())
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
		ticket.ID, ticket.TenantID, ticket.VulnerabilityID, ticket.ProjectID,
		ticket.ConnectionID, ticket.ExternalTicketID, ticket.ExternalTicketKey,
		ticket.ExternalTicketURL, ticket.ExternalProjectKey, ticket.LocalStatus,
		ticket.ExternalStatus, ticket.Priority, ticket.Assignee, ticket.Summary,
		ticket.LastSyncedAt,
	)
	return err
}

// GetTicket gets a ticket by ID.
//
// external_project_key is COALESCEd to ” because pre-051 rows carry NULL
// (deliberately not backfilled — see the 051 migration header) and the model
// field is a plain string whose empty value is the service-side "legacy row,
// fall back to the URL-derived repository" sentinel (F366). GetTicket is the
// only read that needs the column: SyncTicket re-fetches by ID through it,
// and no API response exposes per-ticket rows any other way.
//
// external_ticket_key, external_status, priority, assignee, and summary are
// the other five nullable columns of the 015 schema, all scanned into plain
// string model fields, so every read of vulnerability_tickets (here,
// GetTicketByVulnerability, ListTicketsByVulnerability, ListTickets,
// GetTicketsToSync) COALESCEs them to ” as well. The application always
// writes ” for absent values (CreateTicket / UpdateTicket bind the plain
// string fields directly), but a row seeded by an operator / import SQL with
// e.g. assignee = NULL would otherwise abort the scan with "converting NULL
// to string is unsupported" — taking down GetTicketsToSync (the whole
// tenant's ticket_sync) and the ListTickets API for that tenant, the exact
// failure class fixed on issue_tracker_connections' GetConnection.
func (r *IssueTrackerRepository) GetTicket(ctx context.Context, id uuid.UUID) (*model.VulnerabilityTicket, error) {
	query := `
		SELECT id, tenant_id, vulnerability_id, project_id, connection_id,
			external_ticket_id, COALESCE(external_ticket_key, ''), external_ticket_url,
			COALESCE(external_project_key, ''),
			local_status, COALESCE(external_status, ''), COALESCE(priority, ''),
			COALESCE(assignee, ''), COALESCE(summary, ''),
			last_synced_at, created_at, updated_at
		FROM vulnerability_tickets
		WHERE id = $1
	`

	var ticket model.VulnerabilityTicket
	err := r.q(ctx).QueryRowContext(ctx, query, id).Scan(
		&ticket.ID, &ticket.TenantID, &ticket.VulnerabilityID, &ticket.ProjectID,
		&ticket.ConnectionID, &ticket.ExternalTicketID, &ticket.ExternalTicketKey,
		&ticket.ExternalTicketURL, &ticket.ExternalProjectKey, &ticket.LocalStatus,
		&ticket.ExternalStatus, &ticket.Priority, &ticket.Assignee, &ticket.Summary,
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
			external_ticket_id, COALESCE(external_ticket_key, ''), external_ticket_url,
			local_status, COALESCE(external_status, ''), COALESCE(priority, ''),
			COALESCE(assignee, ''), COALESCE(summary, ''),
			last_synced_at, created_at, updated_at
		FROM vulnerability_tickets
		WHERE vulnerability_id = $1 AND connection_id = $2
	`

	var ticket model.VulnerabilityTicket
	err := r.q(ctx).QueryRowContext(ctx, query, vulnID, connectionID).Scan(
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

// ListTicketsByVulnerability lists all tickets for a vulnerability.
//
// v.severity is COALESCEd to ” for the same reason as the ticket's own
// nullable columns (see GetTicket): vulnerabilities.severity is a
// nullable VARCHAR(20) (001_init) scanned into the plain string
// VulnerabilityTicketWithDetails.Severity, so a ticket joined to a
// severity-less vulnerability would otherwise abort the whole list with
// "converting NULL to string is unsupported" (a 500 on the tickets API).
// The other JOIN-source columns scanned here and in ListTickets
// (v.cve_id, c.tracker_type, c.name, p.name) are all NOT NULL in their
// DDLs, so they stay bare.
func (r *IssueTrackerRepository) ListTicketsByVulnerability(ctx context.Context, vulnID uuid.UUID) ([]model.VulnerabilityTicketWithDetails, error) {
	query := `
		SELECT t.id, t.tenant_id, t.vulnerability_id, t.project_id, t.connection_id,
			t.external_ticket_id, COALESCE(t.external_ticket_key, ''), t.external_ticket_url,
			t.local_status, COALESCE(t.external_status, ''), COALESCE(t.priority, ''),
			COALESCE(t.assignee, ''), COALESCE(t.summary, ''),
			t.last_synced_at, t.created_at, t.updated_at,
			v.cve_id, COALESCE(v.severity, ''), c.tracker_type, c.name, p.name
		FROM vulnerability_tickets t
		JOIN vulnerabilities v ON t.vulnerability_id = v.id
		JOIN issue_tracker_connections c ON t.connection_id = c.id
		JOIN projects p ON t.project_id = p.id
		WHERE t.vulnerability_id = $1
		ORDER BY t.created_at DESC
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, vulnID)
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
	// M46 B-1: a partial ticket list reads as "this CVE has no ticket
	// yet" and invites a duplicate ticket — fail closed.
	if err := rows.Err(); err != nil {
		return nil, err
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
		// argIndex deliberately not incremented here: the list query below
		// resets it to 2 (re-add the increment if a count filter is added).
	}

	var total int
	if err := r.q(ctx).QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// List query
	query := `
		SELECT t.id, t.tenant_id, t.vulnerability_id, t.project_id, t.connection_id,
			t.external_ticket_id, COALESCE(t.external_ticket_key, ''), t.external_ticket_url,
			t.local_status, COALESCE(t.external_status, ''), COALESCE(t.priority, ''),
			COALESCE(t.assignee, ''), COALESCE(t.summary, ''),
			t.last_synced_at, t.created_at, t.updated_at,
			v.cve_id, COALESCE(v.severity, ''), c.tracker_type, c.name, p.name
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

	rows, err := r.q(ctx).QueryContext(ctx, query, args...)
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
	// M46 B-1: without this the page could be short while `total` (a
	// separate COUNT) stayed right, silently hiding tickets behind a
	// consistent-looking pagination footer.
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return tickets, total, nil
}

// UpdateTicket updates a ticket, restricted to the tenant that owns the
// supplied struct.
//
// M47 W2: `AND tenant_id = $8` is the explicit belt to migration 042's
// FORCE RLS braces, and 0 rows returns ErrVulnerabilityTicketNotFound.
// Pre-fix this was the ticket-sync write path's blind spot: SyncTicket
// pulls the external tracker's state and then persists it here, so a
// silently-0-row UPDATE meant the local mirror stayed stale forever while
// every sync reported success. ticket.TenantID comes from GetTicket (the
// re-fetch SyncTicket performs), never from a request body.
func (r *IssueTrackerRepository) UpdateTicket(ctx context.Context, ticket *model.VulnerabilityTicket) error {
	query := `
		UPDATE vulnerability_tickets SET
			local_status = $2, external_status = $3, priority = $4,
			assignee = $5, summary = $6, last_synced_at = $7, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $8
	`
	res, err := r.q(ctx).ExecContext(ctx, query,
		ticket.ID, ticket.LocalStatus, ticket.ExternalStatus,
		ticket.Priority, ticket.Assignee, ticket.Summary, ticket.LastSyncedAt,
		ticket.TenantID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update vulnerability_tickets (RowsAffected): %w", err)
	}
	if n == 0 {
		return fmt.Errorf("update ticket %s for tenant %s: %w", ticket.ID, ticket.TenantID, ErrVulnerabilityTicketNotFound)
	}
	return nil
}

// GetTicketsToSync gets tickets that need to be synced
func (r *IssueTrackerRepository) GetTicketsToSync(ctx context.Context, olderThan time.Duration) ([]model.VulnerabilityTicket, error) {
	cutoff := time.Now().Add(-olderThan)
	query := `
		SELECT t.id, t.tenant_id, t.vulnerability_id, t.project_id, t.connection_id,
			t.external_ticket_id, COALESCE(t.external_ticket_key, ''), t.external_ticket_url,
			t.local_status, COALESCE(t.external_status, ''), COALESCE(t.priority, ''),
			COALESCE(t.assignee, ''), COALESCE(t.summary, ''),
			t.last_synced_at, t.created_at, t.updated_at
		FROM vulnerability_tickets t
		JOIN issue_tracker_connections c ON t.connection_id = c.id
		WHERE c.is_active = true
			AND t.local_status NOT IN ('resolved', 'closed')
			AND (t.last_synced_at IS NULL OR t.last_synced_at < $1)
		LIMIT 100
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, cutoff)
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
	// M46 B-1: the sync scheduler must not treat a truncated batch as
	// "everything is synced" — surface the failure and retry next tick.
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tickets, nil
}

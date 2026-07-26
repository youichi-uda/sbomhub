package repository

// M46 Codex round B-1 — Medium-2: rows.Err() regression tests for the 17
// production loops (16 functions) that were still missing the check after
// the wave-2 sweep: component.go / issue_tracker.go / kev.go / search.go /
// vulnerability.go.
//
// Same contract as m46_w2_rows_err_test.go: rows.Next() returns false both
// at normal EOF and when the connection dies mid-iteration; only
// rows.Err() distinguishes the two. Without the check, every one of these
// listings silently returns a truncated result set with a nil error —
// vulnerability lists, KEV panels and ticket lists can render "fewer
// findings" on a transient DB error instead of failing loudly.
//
// Each test delivers one good row and then fails mid-iteration
// (RowError(1, ...)). Pre-fix the method returned the 1-row partial slice
// with err == nil (measured red); post-fix the iteration error surfaces.
// ExpectQuery patterns match stable FROM/WHERE fragments so they are
// insensitive to SELECT-list rewrites.

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// --- component.go -----------------------------------------------------------

func TestComponentRepository_ListBySbom_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewComponentRepository(db)
	sbomID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at",
	}).
		AddRow(uuid.New(), sbomID, "left-pad", "1.0.0", "library", "pkg:npm/left-pad@1.0.0", "MIT", now).
		AddRow(uuid.New(), sbomID, "lodash", "4.17.21", "library", "pkg:npm/lodash@4.17.21", "MIT", now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`FROM components WHERE sbom_id`).
		WithArgs(sbomID).
		WillReturnRows(rows)

	_, err := repo.ListBySbom(context.Background(), sbomID)
	requireIterationError(t, "ComponentRepository.ListBySbom", err)
}

// componentVulnRows builds the 14-column result shape shared by
// GetVulnerabilities / GetVulnerabilitiesPaginated.
func componentVulnRows() *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows([]string{
		"id", "cve_id", "description", "severity", "cvss_score",
		"epss_score", "epss_percentile", "source",
		"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
		"published_at", "updated_at",
	}).
		AddRow(uuid.New(), "CVE-2024-0001", "d1", "HIGH", 7.5,
			0.5, 0.9, "NVD", false, nil, nil, nil, now, now).
		AddRow(uuid.New(), "CVE-2024-0002", "d2", "LOW", 1.0,
			0.0, 0.0, "NVD", false, nil, nil, nil, now, now).
		RowError(1, errMidIteration)
}

func TestComponentRepository_GetVulnerabilities_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewComponentRepository(db)
	sbomID := uuid.New()

	mock.ExpectQuery(`JOIN component_vulnerabilities cv ON cv\.vulnerability_id = v\.id`).
		WithArgs(sbomID).
		WillReturnRows(componentVulnRows())

	_, err := repo.GetVulnerabilities(context.Background(), sbomID, "")
	requireIterationError(t, "ComponentRepository.GetVulnerabilities", err)
}

func TestComponentRepository_GetVulnerabilitiesPaginated_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewComponentRepository(db)
	sbomID := uuid.New()

	mock.ExpectQuery(`WHERE EXISTS`).
		WithArgs(sbomID, 10, 0).
		WillReturnRows(componentVulnRows())

	_, err := repo.GetVulnerabilitiesPaginated(context.Background(), sbomID, 10, 0, "")
	requireIterationError(t, "ComponentRepository.GetVulnerabilitiesPaginated", err)
}

func TestComponentRepository_ListComponentVulnerabilitiesBySbom_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewComponentRepository(db)
	sbomID := uuid.New()

	rows := sqlmock.NewRows([]string{
		"id", "name", "version", "purl", "license", "cve_id", "severity",
	}).
		AddRow(uuid.New(), "left-pad", "1.0.0", "pkg:npm/left-pad@1.0.0", "MIT", "CVE-2024-0001", "HIGH").
		AddRow(uuid.New(), "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "MIT", "CVE-2024-0002", "LOW").
		RowError(1, errMidIteration)
	mock.ExpectQuery(`JOIN component_vulnerabilities cv ON cv\.component_id = c\.id`).
		WithArgs(sbomID).
		WillReturnRows(rows)

	_, err := repo.ListComponentVulnerabilitiesBySbom(context.Background(), sbomID)
	requireIterationError(t, "ComponentRepository.ListComponentVulnerabilitiesBySbom", err)
}

// --- issue_tracker.go --------------------------------------------------------

// issueTrackerConnRows builds the 14-column connections result shape.
func issueTrackerConnRows(tenantID uuid.UUID) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows([]string{
		"id", "tenant_id", "tracker_type", "name", "base_url", "auth_type",
		"auth_email", "auth_token_encrypted", "default_project_key",
		"default_issue_type", "is_active", "last_sync_at", "created_at", "updated_at",
	}).
		AddRow(uuid.New(), tenantID, "jira", "conn-1", "https://x.atlassian.net", "api_token",
			"a@example.test", "enc-1", "PROJ", "Bug", true, nil, now, now).
		AddRow(uuid.New(), tenantID, "backlog", "conn-2", "https://x.backlog.jp", "api_key",
			"", "enc-2", "", "", true, nil, now, now).
		RowError(1, errMidIteration)
}

func TestIssueTrackerRepository_ListConnections_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewIssueTrackerRepository(db)
	tenantID := uuid.New()

	mock.ExpectQuery(`FROM issue_tracker_connections\s+WHERE tenant_id = \$1\s+ORDER BY`).
		WithArgs(tenantID).
		WillReturnRows(issueTrackerConnRows(tenantID))

	_, err := repo.ListConnections(context.Background(), tenantID)
	requireIterationError(t, "IssueTrackerRepository.ListConnections", err)
}

func TestIssueTrackerRepository_ListConnectionsByType_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewIssueTrackerRepository(db)
	tenantID := uuid.New()

	mock.ExpectQuery(`FROM issue_tracker_connections\s+WHERE tenant_id = \$1 AND tracker_type`).
		WithArgs(tenantID, "jira").
		WillReturnRows(issueTrackerConnRows(tenantID))

	_, err := repo.ListConnectionsByType(context.Background(), tenantID, "jira")
	requireIterationError(t, "IssueTrackerRepository.ListConnectionsByType", err)
}

// ticketWithDetailsRows builds the 21-column tickets+details result shape
// shared by ListTicketsByVulnerability / ListTickets.
func ticketWithDetailsRows() *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows([]string{
		"id", "tenant_id", "vulnerability_id", "project_id", "connection_id",
		"external_ticket_id", "external_ticket_key", "external_ticket_url",
		"local_status", "external_status", "priority", "assignee", "summary",
		"last_synced_at", "created_at", "updated_at",
		"cve_id", "severity", "tracker_type", "name", "project_name",
	}).
		AddRow(uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(),
			"10001", "PROJ-1", "https://x.atlassian.net/browse/PROJ-1",
			"open", "To Do", "High", "alice", "s1",
			nil, now, now, "CVE-2024-0001", "HIGH", "jira", "conn-1", "proj-1").
		AddRow(uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(),
			"10002", "PROJ-2", "https://x.atlassian.net/browse/PROJ-2",
			"open", "Doing", "Low", "bob", "s2",
			nil, now, now, "CVE-2024-0002", "LOW", "jira", "conn-1", "proj-1").
		RowError(1, errMidIteration)
}

func TestIssueTrackerRepository_ListTicketsByVulnerability_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewIssueTrackerRepository(db)
	vulnID := uuid.New()

	mock.ExpectQuery(`WHERE t\.vulnerability_id = \$1`).
		WithArgs(vulnID).
		WillReturnRows(ticketWithDetailsRows())

	_, err := repo.ListTicketsByVulnerability(context.Background(), vulnID)
	requireIterationError(t, "IssueTrackerRepository.ListTicketsByVulnerability", err)
}

func TestIssueTrackerRepository_ListTickets_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewIssueTrackerRepository(db)
	tenantID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM vulnerability_tickets`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery(`WHERE t\.tenant_id = \$1`).
		WithArgs(tenantID, 10, 0).
		WillReturnRows(ticketWithDetailsRows())

	_, _, err := repo.ListTickets(context.Background(), tenantID, "", 10, 0)
	requireIterationError(t, "IssueTrackerRepository.ListTickets", err)
}

func TestIssueTrackerRepository_GetTicketsToSync_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewIssueTrackerRepository(db)
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "tenant_id", "vulnerability_id", "project_id", "connection_id",
		"external_ticket_id", "external_ticket_key", "external_ticket_url",
		"local_status", "external_status", "priority", "assignee", "summary",
		"last_synced_at", "created_at", "updated_at",
	}).
		AddRow(uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(),
			"10001", "PROJ-1", "https://x/1", "open", "To Do", "High", "alice", "s1", nil, now, now).
		AddRow(uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(),
			"10002", "PROJ-2", "https://x/2", "open", "Doing", "Low", "bob", "s2", nil, now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`WHERE c\.is_active = true`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(rows)

	_, err := repo.GetTicketsToSync(context.Background(), time.Hour)
	requireIterationError(t, "IssueTrackerRepository.GetTicketsToSync", err)
}

// --- kev.go ------------------------------------------------------------------

// kevEntryRows builds the 13-column kev_catalog result shape.
func kevEntryRows() *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows([]string{
		"id", "cve_id", "vendor_project", "product", "vulnerability_name",
		"short_description", "required_action", "date_added", "due_date",
		"known_ransomware_use", "notes", "created_at", "updated_at",
	}).
		AddRow(uuid.New(), "CVE-2024-0001", "acme", "widget", "vn1",
			"sd1", "ra1", now, now, false, "", now, now).
		AddRow(uuid.New(), "CVE-2024-0002", "acme", "gadget", "vn2",
			"sd2", "ra2", now, now, true, "", now, now).
		RowError(1, errMidIteration)
}

func TestKEVRepository_List_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewKEVRepository(db)

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM kev_catalog`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery(`FROM kev_catalog\s+ORDER BY date_added DESC\s+LIMIT`).
		WithArgs(10, 0).
		WillReturnRows(kevEntryRows())

	_, _, err := repo.List(context.Background(), 10, 0)
	requireIterationError(t, "KEVRepository.List", err)
}

func TestKEVRepository_GetRecentEntries_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewKEVRepository(db)

	mock.ExpectQuery(`FROM kev_catalog\s+WHERE date_added >`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(kevEntryRows())

	_, err := repo.GetRecentEntries(context.Background(), time.Now().Add(-time.Hour))
	requireIterationError(t, "KEVRepository.GetRecentEntries", err)
}

func TestKEVRepository_GetAllCVEIDs_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewKEVRepository(db)

	rows := sqlmock.NewRows([]string{"cve_id"}).
		AddRow("CVE-2024-0001").
		AddRow("CVE-2024-0002").
		RowError(1, errMidIteration)
	mock.ExpectQuery(`SELECT cve_id FROM kev_catalog`).
		WillReturnRows(rows)

	_, err := repo.GetAllCVEIDs(context.Background())
	requireIterationError(t, "KEVRepository.GetAllCVEIDs", err)
}

func TestKEVRepository_GetKEVVulnerabilities_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewKEVRepository(db)
	projectID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "cve_id", "description", "severity", "cvss_score",
		"epss_score", "epss_percentile", "epss_updated_at",
		"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
		"source", "published_at", "updated_at",
	}).
		AddRow(uuid.New(), "CVE-2024-0001", "d1", "HIGH", 7.5,
			nil, nil, nil, true, now, now, false, "NVD", now, now).
		AddRow(uuid.New(), "CVE-2024-0002", "d2", "LOW", 1.0,
			nil, nil, nil, true, now, now, false, "NVD", now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`WHERE s\.project_id = \$1 AND v\.in_kev = true`).
		WithArgs(projectID).
		WillReturnRows(rows)

	_, err := repo.GetKEVVulnerabilities(context.Background(), projectID)
	requireIterationError(t, "KEVRepository.GetKEVVulnerabilities", err)
}

// --- search.go ---------------------------------------------------------------

// searchByCVEVulnRow satisfies the vulnerability head-row lookup that
// precedes SearchByCVE's two affected/unaffected project loops.
func expectSearchByCVEHeadRow(mock sqlmock.Sqlmock, cveID string, vulnID uuid.UUID) {
	mock.ExpectQuery(`FROM vulnerabilities\s+WHERE cve_id = \$1`).
		WithArgs(cveID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "epss_score", "severity",
		}).AddRow(vulnID, cveID, "d1", 7.5, 0.5, "HIGH"))
}

func TestSearchRepository_SearchByCVE_AffectedRowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewSearchRepository(db)
	vulnID := uuid.New()

	expectSearchByCVEHeadRow(mock, "CVE-2024-0001", vulnID)
	affected := sqlmock.NewRows([]string{
		"project_id", "project_name", "component_id", "component_name", "component_version",
	}).
		AddRow(uuid.New(), "proj-1", uuid.New(), "left-pad", "1.0.0").
		AddRow(uuid.New(), "proj-2", uuid.New(), "lodash", "4.17.21").
		RowError(1, errMidIteration)
	mock.ExpectQuery(`INNER JOIN component_vulnerabilities cv ON c\.id = cv\.component_id\s+WHERE cv\.vulnerability_id`).
		WithArgs(vulnID).
		WillReturnRows(affected)

	_, err := repo.SearchByCVE(context.Background(), "CVE-2024-0001")
	requireIterationError(t, "SearchRepository.SearchByCVE (affected loop)", err)
}

func TestSearchRepository_SearchByCVE_UnaffectedRowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewSearchRepository(db)
	vulnID := uuid.New()

	expectSearchByCVEHeadRow(mock, "CVE-2024-0001", vulnID)
	mock.ExpectQuery(`INNER JOIN component_vulnerabilities cv ON c\.id = cv\.component_id\s+WHERE cv\.vulnerability_id`).
		WithArgs(vulnID).
		WillReturnRows(sqlmock.NewRows([]string{
			"project_id", "project_name", "component_id", "component_name", "component_version",
		}).AddRow(uuid.New(), "proj-1", uuid.New(), "left-pad", "1.0.0"))
	unaffected := sqlmock.NewRows([]string{"id", "name"}).
		AddRow(uuid.New(), "proj-2").
		AddRow(uuid.New(), "proj-3").
		RowError(1, errMidIteration)
	mock.ExpectQuery(`WHERE p\.id NOT IN`).
		WithArgs(vulnID).
		WillReturnRows(unaffected)

	_, err := repo.SearchByCVE(context.Background(), "CVE-2024-0001")
	requireIterationError(t, "SearchRepository.SearchByCVE (unaffected loop)", err)
}

// --- vulnerability.go ---------------------------------------------------------

func TestVulnerabilityRepository_ListByProject_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewVulnerabilityRepository(db)
	projectID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "cve_id", "description", "severity", "cvss_score", "source", "published_at", "updated_at",
	}).
		AddRow(uuid.New(), "CVE-2024-0001", "d1", "HIGH", 7.5, "NVD", now, now).
		AddRow(uuid.New(), "CVE-2024-0002", "d2", "LOW", 1.0, "NVD", now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`WHERE s\.project_id = \$1\s+ORDER BY v\.cvss_score DESC`).
		WithArgs(projectID).
		WillReturnRows(rows)

	_, err := repo.ListByProject(context.Background(), projectID)
	requireIterationError(t, "VulnerabilityRepository.ListByProject", err)
}

func TestVulnerabilityRepository_CountBySeverity_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewVulnerabilityRepository(db)
	projectID := uuid.New()

	rows := sqlmock.NewRows([]string{"severity", "count"}).
		AddRow("HIGH", 3).
		AddRow("LOW", 1).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`GROUP BY COALESCE\(v\.severity, ''\)`).
		WithArgs(projectID).
		WillReturnRows(rows)

	_, err := repo.CountBySeverity(context.Background(), projectID)
	requireIterationError(t, "VulnerabilityRepository.CountBySeverity", err)
}

package repository

// M46 Track A wave 2 — rows.Err() regression tests for eol.go / ipa.go /
// public_link.go / vex.go / ssvc.go.
//
// database/sql contract: rows.Next() returns false BOTH at normal EOF and
// when the connection dies / the server aborts the cursor mid-iteration.
// Only rows.Err() distinguishes the two. A list loop without the check
// silently returns the rows fetched so far as if they were the complete
// result — for vulnerability / EOL / VEX / SSVC listings that means a
// security dashboard can render "no findings" (or a truncated subset) on a
// transient DB error instead of failing loudly.
//
// Each test drives the repository method through sqlmock with a result set
// that delivers one good row and then fails mid-iteration (RowError on the
// second row). Pre-fix (no rows.Err() check) the method returned the
// 1-row partial slice with a nil error, so the `err == nil` branch below
// failed — that is the measured red. Post-fix every method surfaces the
// iteration error.
//
// The ExpectQuery patterns deliberately match on stable FROM/WHERE
// fragments (not the SELECT list) so they match the query both before and
// after the M46 W2 COALESCE rewrite — otherwise the pre-fix red would be a
// spurious "query mismatch" error instead of the real partial-result bug.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// errMidIteration is the injected mid-iteration failure. Distinctive text so
// the assertions can verify the surfaced error is OUR error, not an
// unrelated sqlmock artifact.
var errMidIteration = errors.New("m46w2: connection reset mid-iteration")

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

// requireIterationError asserts the method surfaced errMidIteration.
func requireIterationError(t *testing.T, method string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: returned nil error on a mid-iteration failure — partial rows were silently returned as the full result", method)
	}
	if !strings.Contains(err.Error(), errMidIteration.Error()) {
		t.Fatalf("%s: error = %v, want the injected mid-iteration error", method, err)
	}
}

func TestEOLRepository_ListProducts_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewEOLRepository(db)
	now := time.Now()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM eol_products`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	rows := sqlmock.NewRows([]string{"id", "name", "title", "category", "link", "total_cycles", "created_at", "updated_at"}).
		AddRow(uuid.New(), "python", "Python", "language", "https://python.org", 10, now, now).
		AddRow(uuid.New(), "nodejs", "Node.js", "runtime", "https://nodejs.org", 20, now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`FROM eol_products ORDER BY name`).
		WithArgs(10, 0).
		WillReturnRows(rows)

	_, _, err := repo.ListProducts(context.Background(), 10, 0)
	requireIterationError(t, "EOLRepository.ListProducts", err)
}

func TestEOLRepository_GetCyclesByProduct_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewEOLRepository(db)
	productID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "product_id", "cycle", "release_date", "eol_date", "eos_date",
		"latest_version", "is_lts", "is_eol", "discontinued", "link", "support_end_date",
		"created_at", "updated_at",
	}).
		AddRow(uuid.New(), productID, "3.12", &now, nil, nil, "3.12.1", false, false, false, "", nil, now, now).
		AddRow(uuid.New(), productID, "3.11", &now, nil, nil, "3.11.7", true, true, true, "", nil, now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`FROM eol_product_cycles\s+WHERE product_id`).
		WithArgs(productID).
		WillReturnRows(rows)

	_, err := repo.GetCyclesByProduct(context.Background(), productID)
	requireIterationError(t, "EOLRepository.GetCyclesByProduct", err)
}

func TestEOLRepository_GetMappings_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewEOLRepository(db)
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "product_id", "component_pattern", "component_type", "purl_type", "priority", "is_active", "created_at",
	}).
		AddRow(uuid.New(), uuid.New(), "python", "library", "pypi", 100, true, now).
		AddRow(uuid.New(), uuid.New(), "node", "runtime", "npm", 90, true, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`FROM eol_component_mappings`).
		WillReturnRows(rows)

	_, err := repo.GetMappings(context.Background())
	requireIterationError(t, "EOLRepository.GetMappings", err)
}

func TestEOLRepository_GetComponentsForEOLCheck_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewEOLRepository(db)
	projectID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at",
	}).
		AddRow(uuid.New(), uuid.New(), "left-pad", "1.0.0", "library", "pkg:npm/left-pad@1.0.0", "MIT", now).
		AddRow(uuid.New(), uuid.New(), "lodash", "4.17.21", "library", "pkg:npm/lodash@4.17.21", "MIT", now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`eol_checked_at IS NULL`).
		WithArgs(projectID, 50).
		WillReturnRows(rows)

	_, err := repo.GetComponentsForEOLCheck(context.Background(), projectID, 50)
	requireIterationError(t, "EOLRepository.GetComponentsForEOLCheck", err)
}

func TestEOLRepository_GetComponentsWithEOL_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewEOLRepository(db)
	projectID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(`SELECT COUNT\(\*\)\s+FROM components c`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	rows := sqlmock.NewRows([]string{
		"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at",
		"eol_status", "eol_product_id", "eol_cycle_id", "eol_date", "eos_date",
	}).
		AddRow(uuid.New(), uuid.New(), "left-pad", "1.0.0", "library", "pkg:npm/left-pad@1.0.0", "MIT", now,
			"eol", nil, nil, nil, nil).
		AddRow(uuid.New(), uuid.New(), "lodash", "4.17.21", "library", "pkg:npm/lodash@4.17.21", "MIT", now,
			"active", nil, nil, nil, nil).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`CASE c\.eol_status`).
		WithArgs(projectID, 10, 0).
		WillReturnRows(rows)

	_, _, err := repo.GetComponentsWithEOL(context.Background(), projectID, "", 10, 0)
	requireIterationError(t, "EOLRepository.GetComponentsWithEOL", err)
}

func TestEOLRepository_GetAllProductNames_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewEOLRepository(db)

	rows := sqlmock.NewRows([]string{"name"}).
		AddRow("python").
		AddRow("nodejs").
		RowError(1, errMidIteration)
	mock.ExpectQuery(`SELECT name FROM eol_products`).
		WillReturnRows(rows)

	_, err := repo.GetAllProductNames(context.Background())
	requireIterationError(t, "EOLRepository.GetAllProductNames", err)
}

func ipaAnnouncementColumns() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "ipa_id", "title", "title_ja", "description", "category", "severity",
		"source_url", "related_cves", "published_at", "created_at", "updated_at",
	})
}

func TestIPARepository_ListAnnouncements_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewIPARepository(db)
	now := time.Now()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM ipa_announcements`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	rows := ipaAnnouncementColumns().
		AddRow(uuid.New(), "ipa-1", "t1", "tj1", "d1", "security_alert", "HIGH",
			"https://example.test/1", []byte("{CVE-2024-0001}"), now, now, now).
		AddRow(uuid.New(), "ipa-2", "t2", "tj2", "d2", "security_alert", "LOW",
			"https://example.test/2", []byte("{}"), now, now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`FROM ipa_announcements`).
		WithArgs(10, 0).
		WillReturnRows(rows)

	_, _, err := repo.ListAnnouncements(context.Background(), "", 10, 0)
	requireIterationError(t, "IPARepository.ListAnnouncements", err)
}

func TestIPARepository_GetAnnouncementsByCVE_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewIPARepository(db)
	now := time.Now()

	rows := ipaAnnouncementColumns().
		AddRow(uuid.New(), "ipa-1", "t1", "tj1", "d1", "security_alert", "HIGH",
			"https://example.test/1", []byte("{CVE-2024-0001}"), now, now, now).
		AddRow(uuid.New(), "ipa-2", "t2", "tj2", "d2", "security_alert", "LOW",
			"https://example.test/2", []byte("{CVE-2024-0001}"), now, now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`ANY\(related_cves\)`).
		WithArgs("CVE-2024-0001").
		WillReturnRows(rows)

	_, err := repo.GetAnnouncementsByCVE(context.Background(), "CVE-2024-0001")
	requireIterationError(t, "IPARepository.GetAnnouncementsByCVE", err)
}

func TestIPARepository_GetRecentAnnouncements_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewIPARepository(db)
	now := time.Now()

	rows := ipaAnnouncementColumns().
		AddRow(uuid.New(), "ipa-1", "t1", "tj1", "d1", "security_alert", "HIGH",
			"https://example.test/1", []byte("{}"), now, now, now).
		AddRow(uuid.New(), "ipa-2", "t2", "tj2", "d2", "security_alert", "LOW",
			"https://example.test/2", []byte("{}"), now, now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`WHERE published_at >`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(rows)

	_, err := repo.GetRecentAnnouncements(context.Background(), now.Add(-time.Hour))
	requireIterationError(t, "IPARepository.GetRecentAnnouncements", err)
}

func TestPublicLinkRepository_ListByProject_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewPublicLinkRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "tenant_id", "project_id", "sbom_id", "token", "name", "expires_at", "is_active",
		"allowed_downloads", "password_hash", "view_count", "download_count", "created_at", "updated_at",
	}).
		AddRow(uuid.New(), tenantID, projectID, nil, "tok-1", "link-1", now, true,
			nil, nil, 0, 0, now, now).
		AddRow(uuid.New(), tenantID, projectID, nil, "tok-2", "link-2", now, true,
			nil, nil, 0, 0, now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`FROM public_links\s+WHERE project_id`).
		WithArgs(projectID, tenantID).
		WillReturnRows(rows)

	_, err := repo.ListByProject(context.Background(), tenantID, projectID)
	requireIterationError(t, "PublicLinkRepository.ListByProject", err)
}

func TestVEXRepository_ListByProject_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewVEXRepository(db)
	projectID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "project_id", "vulnerability_id", "component_id",
		"status", "justification", "action_statement", "impact_statement",
		"created_by", "created_at", "updated_at",
		"cve_id", "severity", "name", "version",
	}).
		AddRow(uuid.New(), projectID, uuid.New(), nil,
			"not_affected", "component_not_present", "a1", "i1",
			"alice", now, now, "CVE-2024-0001", "HIGH", nil, nil).
		AddRow(uuid.New(), projectID, uuid.New(), nil,
			"affected", "", "a2", "i2",
			"bob", now, now, "CVE-2024-0002", "LOW", nil, nil).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`FROM vex_statements vs`).
		WithArgs(projectID).
		WillReturnRows(rows)

	_, err := repo.ListByProject(context.Background(), projectID)
	requireIterationError(t, "VEXRepository.ListByProject", err)
}

func TestVEXRepository_ListByVulnerability_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewVEXRepository(db)
	vulnID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "project_id", "vulnerability_id", "component_id",
		"status", "justification", "action_statement", "impact_statement",
		"created_by", "created_at", "updated_at",
	}).
		AddRow(uuid.New(), uuid.New(), vulnID, nil,
			"not_affected", "component_not_present", "a1", "i1", "alice", now, now).
		AddRow(uuid.New(), uuid.New(), vulnID, nil,
			"affected", "", "a2", "i2", "bob", now, now).
		RowError(1, errMidIteration)
	mock.ExpectQuery(`FROM vex_statements\s+WHERE vulnerability_id`).
		WithArgs(vulnID).
		WillReturnRows(rows)

	_, err := repo.ListByVulnerability(context.Background(), vulnID)
	requireIterationError(t, "VEXRepository.ListByVulnerability", err)
}

// TestVEXRepository_LookupProjectTenantID_NullTenant pins the M46 W2
// contract for the one nullable-uuid violation: projects.tenant_id is
// DDL-nullable (007 added it without NOT NULL) and uuid.UUID.Scan(nil)
// SILENTLY returns uuid.Nil — pre-fix a NULL-tenant project row made
// LookupProjectTenantID return (uuid.Nil, nil), which VEXService would
// then write into vex_statements.tenant_id. The fix scans through
// uuid.NullUUID and returns an explicit error instead (COALESCE to a
// zero uuid would be the same silent-Nil bug with extra steps; a tenant
// id has no meaningful default).
func TestVEXRepository_LookupProjectTenantID_NullTenant(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewVEXRepository(db)
	projectID := uuid.New()

	mock.ExpectQuery(`SELECT tenant_id FROM projects WHERE id`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(nil))

	got, err := repo.LookupProjectTenantID(context.Background(), projectID)
	if err == nil {
		t.Fatalf("LookupProjectTenantID on a NULL tenant_id returned (%v, nil); want an explicit error, not a silent uuid.Nil", got)
	}
	if got != uuid.Nil {
		t.Errorf("LookupProjectTenantID error path returned %v, want uuid.Nil", got)
	}
}

func ssvcWithVulnRow(rows *sqlmock.Rows, decision string, now time.Time) *sqlmock.Rows {
	return rows.AddRow(
		uuid.New(), uuid.New(), uuid.New(), uuid.New(), "CVE-2024-0001",
		"none", "no", "partial", "minimal", "minimal",
		decision, false, false, nil, now,
		"notes", now, now,
		"HIGH", 7.5, false, nil,
	)
}

func TestSSVCRepository_ListAssessments_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewSSVCRepository(db)
	projectID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(`(?is)SELECT\s+COUNT\(\*\)\s+FROM\s+ssvc_assessments`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	rows := sqlmock.NewRows(ssvcWithVulnColumns)
	rows = ssvcWithVulnRow(rows, "scheduled", now)
	rows = ssvcWithVulnRow(rows, "defer", now).RowError(1, errMidIteration)
	mock.ExpectQuery(`(?is)FROM\s+ssvc_assessments\s+a`).
		WithArgs(projectID, 10, 0).
		WillReturnRows(rows)

	_, _, err := repo.ListAssessments(context.Background(), projectID, nil, 10, 0)
	requireIterationError(t, "SSVCRepository.ListAssessments", err)
}

func TestSSVCRepository_GetAssessmentHistory_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewSSVCRepository(db)
	assessmentID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "assessment_id",
		"prev_exploitation", "prev_automatable", "prev_technical_impact",
		"prev_mission_prevalence", "prev_safety_impact", "prev_decision",
		"new_exploitation", "new_automatable", "new_technical_impact",
		"new_mission_prevalence", "new_safety_impact", "new_decision",
		"changed_by", "changed_at", "change_reason",
	}).
		AddRow(uuid.New(), assessmentID,
			nil, nil, nil, nil, nil, nil,
			"none", "no", "partial", "minimal", "minimal", "defer",
			nil, now, "r1").
		AddRow(uuid.New(), assessmentID,
			nil, nil, nil, nil, nil, nil,
			"active", "yes", "total", "essential", "significant", "immediate",
			nil, now, "r2").
		RowError(1, errMidIteration)
	mock.ExpectQuery(`FROM ssvc_assessment_history`).
		WithArgs(assessmentID).
		WillReturnRows(rows)

	_, err := repo.GetAssessmentHistory(context.Background(), assessmentID)
	requireIterationError(t, "SSVCRepository.GetAssessmentHistory", err)
}

func TestSSVCRepository_GetImmediateAssessments_RowsErrSurfaced(t *testing.T) {
	db, mock := newMockDB(t)
	repo := NewSSVCRepository(db)
	now := time.Now()

	rows := sqlmock.NewRows(ssvcWithVulnColumns)
	rows = ssvcWithVulnRow(rows, "immediate", now)
	rows = ssvcWithVulnRow(rows, "immediate", now).RowError(1, errMidIteration)
	mock.ExpectQuery(`(?is)FROM\s+ssvc_assessments\s+a`).
		WillReturnRows(rows)

	_, err := repo.GetImmediateAssessments(context.Background())
	requireIterationError(t, "SSVCRepository.GetImmediateAssessments", err)
}

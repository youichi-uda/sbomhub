package repository

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// cvss_version (M67, migration 069; published since M71) is read beside
// cvss_score by the dashboard Top Risks read and reaches JSON as
// "cvss_version" — omitted when the column is NULL (never "" or null), and
// published even when cvss_score is NULL.
func TestTopRisks_CarriesCVSSVersion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	projID := uuid.New()
	mock.ExpectQuery(`(?is)v\.cvss_score,\s*v\.cvss_version,\s*COALESCE\(v\.severity`).
		WillReturnRows(sqlmock.NewRows([]string{
			"cve_id", "epss_score", "cvss_score", "cvss_version", "severity",
			"project_id", "project_name", "component_name", "component_version",
		}).
			AddRow("CVE-2026-0001", 0.5, 9.8, "3.1", "CRITICAL", projID, "app", "libx", "1.0").
			AddRow("CVE-2026-0002", 0.4, nil, "4.0", "HIGH", projID, "app", "liby", "1.0").
			AddRow("CVE-2026-0003", 0.3, 5.0, nil, "MEDIUM", projID, "app", "libz", "1.0"))

	got, err := NewDashboardRepository(db).GetTopRisksByTenant(context.Background(), uuid.New(), 10, "epss")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d rows", len(got))
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"cvss_score":9.8,"cvss_version":"3.1"`) {
		t.Errorf("row 1: want cvss_version 3.1 beside the score: %s", s)
	}
	if !strings.Contains(s, `"epss_score":0.4,"cvss_version":"4.0"`) {
		t.Errorf("row 2: a version without a usable score must still be published: %s", s)
	}
	if strings.Count(s, `"cvss_version"`) != 2 {
		t.Errorf("a NULL cvss_version must be omitted, not null/empty: %s", s)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func ssvcRowWithVersion(rows *sqlmock.Rows, score, version any, now time.Time) *sqlmock.Rows {
	return rows.AddRow(
		uuid.New(), uuid.New(), uuid.New(), uuid.New(), "CVE-2026-0001",
		"none", "no", "partial", "minimal", "minimal",
		"immediate", false, false, nil, now,
		"", now, now,
		"HIGH", score, version, false, nil,
	)
}

func assertSSVCVersionJSON(t *testing.T, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"vulnerability_cvss_score":7.5,"vulnerability_cvss_version":"3.1"`) {
		t.Errorf("row 1: want vulnerability_cvss_version 3.1 beside the score: %s", s)
	}
	if !strings.Contains(s, `"vulnerability_severity":"HIGH","vulnerability_cvss_version":"4.0"`) {
		t.Errorf("row 2: a version without a usable score must still be published: %s", s)
	}
	if strings.Count(s, `"vulnerability_cvss_version"`) != 2 {
		t.Errorf("a NULL cvss_version must be omitted, not null/empty: %s", s)
	}
}

// The SSVC assessment reads (project list and the tenant's immediate list)
// carry the vulnerability's cvss_version beside vulnerability_cvss_score.
func TestSSVCAssessments_CarryCVSSVersion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewSSVCRepository(db)
	now := time.Now()
	rows := func() *sqlmock.Rows {
		r := sqlmock.NewRows(ssvcWithVulnColumns)
		r = ssvcRowWithVersion(r, 7.5, "3.1", now)
		r = ssvcRowWithVersion(r, nil, "4.0", now)
		return ssvcRowWithVersion(r, 5.0, nil, now)
	}

	projectID := uuid.New()
	mock.ExpectQuery(`(?is)SELECT\s+COUNT\(\*\)\s+FROM\s+ssvc_assessments`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	mock.ExpectQuery(`(?is)v\.cvss_score,\s*v\.cvss_version,\s*v\.in_kev.*FROM\s+ssvc_assessments\s+a`).
		WithArgs(projectID, 50, 0).
		WillReturnRows(rows())
	list, _, err := repo.ListAssessments(context.Background(), projectID, nil, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertSSVCVersionJSON(t, list)

	mock.ExpectQuery(`(?is)v\.cvss_score,\s*v\.cvss_version,\s*v\.in_kev.*FROM\s+ssvc_assessments\s+a`).
		WillReturnRows(rows())
	imm, err := repo.GetImmediateAssessments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertSSVCVersionJSON(t, imm)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

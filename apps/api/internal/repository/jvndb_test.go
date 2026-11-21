package repository

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// Migration 072: the list attaches JVNDB advisories by CVE id (case-
// insensitively), only when the enrichment is wired, and never adds rows.
func TestJVNDBEnrichment_AttachesByCVE(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewComponentRepository(db).WithJVNDBEnrichment()
	now := time.Now()
	cols := []string{"id", "cve_id", "description", "severity", "cvss_score", "cvss_version", "epss_score", "epss_percentile", "source",
		"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use", "published_at", "updated_at", "match_method", "match_evidence"}
	mock.ExpectQuery(`FROM vulnerabilities v`).
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow(uuid.New(), "CVE-2026-114938", "d", "CRITICAL", 9.8, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "nvd_cpe", nil).
			AddRow(uuid.New(), "cve-2025-46267", "d", "HIGH", 7.0, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "nvd_cpe", nil).
			AddRow(uuid.New(), "JVNDB-2026-000001", "d", "HIGH", nil, nil, nil, nil, "JVN", false, nil, nil, nil, now, now, "jvn_keyword", nil).
			AddRow(uuid.New(), "CVE-2020-0001", "d", "LOW", 2.0, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "nvd_cpe", nil))
	pub := time.Date(2026, 11, 19, 7, 12, 0, 0, time.UTC)
	mock.ExpectQuery(`FROM jvndb_advisory_cves m`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"cve_id", "jvndb_id", "title", "published_at", "modified_at"}).
			AddRow("CVE-2025-46267", "JVNDB-2025-009576", "複数の脆弱性", pub, pub).
			AddRow("CVE-2026-114938", "JVNDB-2026-044393", "OpenJDKにおけるヒープベースのバッファオーバーフローの脆弱性", pub, nil))

	vulns, err := repo.GetVulnerabilitiesPaginated(context.Background(), uuid.New(), 100, 0, "cvss")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 4 {
		t.Fatalf("rows = %d, want 4 (the enrichment must not add or drop rows)", len(vulns))
	}
	if got := vulns[0].JVNDB; len(got) != 1 || got[0].ID != "JVNDB-2026-044393" ||
		got[0].URL != "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-044393.html" || got[0].Modified != nil {
		t.Errorf("CVE-2026-114938 jvndb = %+v", got)
	}
	if got := vulns[1].JVNDB; len(got) != 1 || got[0].ID != "JVNDB-2025-009576" {
		t.Errorf("lower-case stored cve id must match: %+v", got)
	}
	if vulns[2].JVNDB != nil || vulns[3].JVNDB != nil {
		t.Errorf("rows without an advisory must have none: %+v / %+v", vulns[2].JVNDB, vulns[3].JVNDB)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestJVNDBEnrichment_OffByDefault(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	cols := []string{"id", "cve_id", "description", "severity", "cvss_score", "cvss_version", "epss_score", "epss_percentile", "source",
		"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use", "published_at", "updated_at", "match_method", "match_evidence"}
	mock.ExpectQuery(`FROM vulnerabilities v`).
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow(uuid.New(), "CVE-2026-114938", "d", "CRITICAL", 9.8, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "nvd_cpe", nil))
	if _, err := NewComponentRepository(db).GetVulnerabilitiesPaginated(context.Background(), uuid.New(), 100, 0, "cvss"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestJVNDBEnrichment_ErrorFailsTheList(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	cols := []string{"id", "cve_id", "description", "severity", "cvss_score", "cvss_version", "epss_score", "epss_percentile", "source",
		"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use", "published_at", "updated_at", "match_method", "match_evidence"}
	mock.ExpectQuery(`FROM vulnerabilities v`).
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow(uuid.New(), "CVE-2026-114938", "d", "CRITICAL", 9.8, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "nvd_cpe", nil))
	mock.ExpectQuery(`FROM jvndb_advisory_cves m`).WillReturnError(context.DeadlineExceeded)
	vulns, err := NewComponentRepository(db).WithJVNDBEnrichment().GetVulnerabilitiesPaginated(context.Background(), uuid.New(), 100, 0, "cvss")
	if err == nil || vulns != nil {
		t.Fatalf("vulns=%v err=%v: a failed read inside the request transaction must fail the list", vulns, err)
	}
}

func TestJVNDBAdvisoryURL(t *testing.T) {
	if got := model.JVNDBAdvisoryURL("JVNDB-2025-009576"); got != "https://jvndb.jvn.jp/ja/contents/2025/JVNDB-2025-009576.html" {
		t.Errorf("url = %q", got)
	}
	for _, bad := range []string{"", "JVNDB-25-1", "javascript:alert(1)", "JVNDB-2025-009576/../x"} {
		if got := model.JVNDBAdvisoryURL(bad); got != "" {
			t.Errorf("%q -> %q, want empty", bad, got)
		}
	}
}

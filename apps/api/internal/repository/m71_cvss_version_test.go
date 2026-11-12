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

// M71: cvss_version (M67, migration 069) is read beside cvss_score by the
// reads the API publishes, and reaches JSON as "cvss_version" — omitted when
// the column is NULL, never "" or null.
func TestM71ProjectVulnList_CarriesCVSSVersion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	mock.ExpectQuery(`(?is)v\.cvss_score,\s*v\.cvss_version,`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "cve_id", "description", "severity", "cvss_score", "cvss_version",
			"epss_score", "epss_percentile", "source", "in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
			"published_at", "updated_at", "match_method", "match_evidence"}).
			AddRow(uuid.New(), "CVE-2026-34478", "d", "HIGH", 7.5, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, nil, nil).
			AddRow(uuid.New(), "CVE-2026-0002", "d", "HIGH", nil, "4.0", nil, nil, "NVD", false, nil, nil, nil, now, now, nil, nil).
			AddRow(uuid.New(), "JVNDB-2026-1", "d", "", nil, nil, nil, nil, "JVN", false, nil, nil, nil, now, now, nil, nil))

	got, err := NewComponentRepository(db).GetVulnerabilitiesPaginated(context.Background(), uuid.New(), 10, 0, "cvss")
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
	if !strings.Contains(s, `"cvss_score":7.5,"cvss_version":"3.1"`) {
		t.Errorf("row 1: want cvss_version 3.1 beside the score: %s", s)
	}
	if !strings.Contains(s, `"severity":"HIGH","cvss_version":"4.0"`) {
		t.Errorf("row 2: a version without a usable score must still be published: %s", s)
	}
	if strings.Count(s, `"cvss_version"`) != 2 {
		t.Errorf("a NULL cvss_version must be omitted, not null/empty: %s", s)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestM71SearchByCVEAndImpact_CarryCVSSVersion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewSearchRepository(db)

	mock.ExpectQuery(`(?is)cvss_score,\s*cvss_version,\s*epss_score`).
		WithArgs("CVE-2026-34478").
		WillReturnRows(sqlmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "cvss_version", "epss_score", "severity"}).
			AddRow(uuid.New(), "CVE-2026-34478", "d", 7.5, "3.1", nil, "HIGH"))
	mock.ExpectQuery(`(?is)FROM\s+projects\s+p`).WillReturnRows(sqlmock.NewRows([]string{"project_id"}))
	mock.ExpectQuery(`(?is)FROM\s+projects\s+p`).WillReturnRows(sqlmock.NewRows([]string{"project_id"}))
	res, err := repo.SearchByCVE(context.Background(), "CVE-2026-34478")
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.CVSSVersion == nil || *res.CVSSVersion != "3.1" {
		t.Fatalf("SearchByCVE CVSSVersion = %v", res)
	}

	mock.ExpectQuery(`(?is)cvss_score,\s*cvss_version,\s*epss_score,\s*in_kev`).
		WithArgs("CVE-2026-34478").
		WillReturnRows(sqlmock.NewRows([]string{"id", "severity", "cvss_score", "cvss_version", "epss_score", "in_kev"}).
			AddRow(uuid.New(), "HIGH", 7.5, "3.1", nil, false))
	meta, err := repo.GetVulnerabilityImpactMeta(context.Background(), "CVE-2026-34478")
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil || meta.CVSSVersion == nil || *meta.CVSSVersion != "3.1" {
		t.Fatalf("impact meta CVSSVersion = %+v", meta)
	}
}

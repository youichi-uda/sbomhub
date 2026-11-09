package repository

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// M60: the per-SBOM vulnerability list carries the strongest match method of
// the SBOM's links to each CVE, and a confidence label derived from it. A CVE
// whose links all predate migration 067 (NULL) is "unknown", not "low".
func TestM60GetVulnerabilities_ProjectsMatchMethodAndConfidence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewComponentRepository(db)
	now := time.Now()
	cols := []string{"id", "cve_id", "description", "severity", "cvss_score", "epss_score", "epss_percentile", "source",
		"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use", "published_at", "updated_at", "match_method", "match_evidence"}
	mock.ExpectQuery(`DISTINCT ON \(bm.vulnerability_id\) .* ORDER BY bm.vulnerability_id, CASE bm.match_method`).
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow(uuid.New(), "CVE-2021-44228", "d", "CRITICAL", 10.0, nil, nil, "NVD", true, now, now, false, now, now, "nvd_cpe", nil).
			AddRow(uuid.New(), "CVE-2021-0001", "d", "HIGH", 7.0, nil, nil, "JVN", false, nil, nil, nil, now, now, "jvn_keyword", nil).
			AddRow(uuid.New(), "CVE-2021-0002", "d", "LOW", 2.0, nil, nil, "NVD", false, nil, nil, nil, now, now, "nvd_cpe_distro", nil).
			AddRow(uuid.New(), "CVE-2020-0003", "d", "LOW", 2.0, nil, nil, "NVD", false, nil, nil, nil, now, now, nil, nil))

	got, err := repo.GetVulnerabilitiesPaginated(context.Background(), uuid.New(), 10, 0, "cvss")
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]string{{"nvd_cpe", "high"}, {"jvn_keyword", "low"}, {"nvd_cpe_distro", "medium"}, {"", "unknown"}}
	for i, w := range want {
		if got[i].MatchMethod != w[0] || got[i].MatchConfidence != w[1] {
			t.Errorf("row %d: method=%q confidence=%q, want %q/%q", i, got[i].MatchMethod, got[i].MatchConfidence, w[0], w[1])
		}
	}
}

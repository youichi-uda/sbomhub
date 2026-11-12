package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// M70: the list projects the distro labels, their confidence and — only for a
// distro label — the evidence stored with the chosen link.
func TestM70GetVulnerabilities_ProjectsDistroLabelsAndEvidence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewComponentRepository(db)
	now := time.Now()
	ev := []byte(`{"source":"osv","source_id":"secret-hash","status":"fixed","basis":"later_releases","release":"Debian:11","package":"openssl","installed":"1.1.1k-1","fixed":"1.1.1k-1","records":["DEBIAN-CVE-2021-3449"],"fetched_at":"2026-11-09T00:00:00Z","prior_method":"nvd_cpe_unverified","wm_source":"secret-hash","wm_rev":"r","wm_by_source":{"secret-hash":"r"}}`)
	cols := []string{"id", "cve_id", "description", "severity", "cvss_score", "cvss_version", "epss_score", "epss_percentile", "source",
		"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use", "published_at", "updated_at", "match_method", "match_evidence"}
	mock.ExpectQuery(`WHEN 'distro_fixed' THEN -1`).
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow(uuid.New(), "CVE-2021-3711", "d", "CRITICAL", 9.8, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "distro_affected", ev).
			AddRow(uuid.New(), "CVE-2021-3712", "d", "HIGH", 7.4, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "distro_unfixed", ev).
			AddRow(uuid.New(), "CVE-2021-3449", "d", "MEDIUM", 5.9, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "distro_fixed", ev).
			// Evidence under a non-distro method is never projected.
			AddRow(uuid.New(), "CVE-2021-0001", "d", "LOW", 2.0, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "nvd_cpe", ev).
			AddRow(uuid.New(), "CVE-2021-0002", "d", "LOW", 2.0, "3.1", nil, nil, "NVD", false, nil, nil, nil, now, now, "distro_fixed", nil))

	got, err := repo.GetVulnerabilitiesPaginated(context.Background(), uuid.New(), 10, 0, "cvss")
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		method, confidence string
		evidence           bool
	}{
		{"distro_affected", "high", true},
		{"distro_unfixed", "high", true},
		{"distro_fixed", "distro_fixed", true},
		{"nvd_cpe", "high", false},
		{"distro_fixed", "distro_fixed", false},
	}
	for i, w := range want {
		if got[i].MatchMethod != w.method || got[i].MatchConfidence != w.confidence || (len(got[i].MatchEvidence) > 0) != w.evidence {
			t.Errorf("row %d: %q / %q / evidence %s, want %+v", i, got[i].MatchMethod, got[i].MatchConfidence, got[i].MatchEvidence, w)
		}
	}
	for _, internal := range []string{"source_id", "wm_source", "wm_rev", "wm_by_source", "prior_method"} {
		if strings.Contains(string(got[2].MatchEvidence), internal) {
			t.Errorf("%s projected: %s", internal, got[2].MatchEvidence) // Codex M70 R28 Low-3
		}
	}
	if !strings.Contains(string(got[2].MatchEvidence), `"later_releases"`) {
		t.Errorf("evidence not passed through: %s", got[2].MatchEvidence)
	}
}

// The SQL ordering mirrors model.MatchMethod.FindingRank; both aggregates
// share it, carry only the method and the component id, and the evidence is
// read from that same link, never aggregated (Codex M70 R28 High-2).
func TestM70BestMatchOrderMirrorsFindingRank(t *testing.T) {
	if strings.Count(bestMatchMethodJoin, "ORDER BY "+bestMatchOrder) != 2 ||
		strings.Contains(bestMatchMethodJoin, "array_agg(bm.match_evidence") ||
		!strings.Contains(bestMatchMethodJoin, "bev.component_id = pick.component_id AND bev.vulnerability_id = pick.vulnerability_id") {
		t.Fatal("the best link is not picked by key and joined back")
	}
	for _, c := range []struct {
		m    string
		rank int
	}{
		{"distro_affected", 6}, {"distro_unfixed", 5}, {"nvd_cpe", 3}, {"nvd_cpe_distro", 2},
		{"nvd_cpe_unverified", 1}, {"nvd_keyword", 1}, {"jvn_keyword", 1}, {"cve_sync_keyword", 1}, {"distro_fixed", -1},
	} {
		if !strings.Contains(bestMatchOrder, "WHEN '"+c.m+"' THEN "+itoa(c.rank)) {
			t.Errorf("bestMatchOrder lacks %s -> %d", c.m, c.rank)
		}
	}
}

func itoa(n int) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	return string(rune('0' + n))
}

// Codex M70 R8 High-4: a same-method refresh is guarded by data_modified.
func TestM70RelabelDistro_FreshnessGuard(t *testing.T) {
	if !strings.Contains(relabelDistroFreshness, "data_modified") || !strings.Contains(relabelDistroFreshness, "<=") ||
		!strings.Contains(relabelDistroFreshness, "source_id") {
		t.Errorf("guard %q", relabelDistroFreshness)
	}
}

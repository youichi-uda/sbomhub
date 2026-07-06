package repository

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestGetTopRisksByTenant_ReadsRealEPSSColumn pins the M36-A / F432 flip:
// GetTopRisksByTenant must SELECT the real epss_score column wrapped in
// COALESCE(v.epss_score, 0), NOT the old fixed 0::numeric sentinel (which could
// never surface a synced score). The assertion is structural on the SQL, so a
// revert to 0::numeric fails the regex even if the scanned value happened to be
// 0. Two rows are returned: an un-synced one (the DB's COALESCE turns its NULL
// into 0) and a synced one whose real score passes through unchanged — proving
// the read is the live column, not a constant.
func TestGetTopRisksByTenant_ReadsRealEPSSColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewDashboardRepository(db)

	pattern := regexp.MustCompile(`(?is)` + regexp.QuoteMeta("COALESCE(v.epss_score, 0)") + `\s+as\s+epss_score`)
	if pattern.MatchString("0::numeric as epss_score") {
		t.Fatalf("pattern is vacuous: it also matches the old 0::numeric sentinel")
	}

	tenantID := uuid.New()
	projID := uuid.New()
	mock.ExpectQuery(pattern.String()).
		WithArgs(tenantID, 10).
		WillReturnRows(sqlmock.NewRows([]string{
			"cve_id", "epss_score", "cvss_score", "severity",
			"project_id", "project_name", "component_name", "component_version",
		}).
			// Un-synced CVE: COALESCE(v.epss_score, 0) -> 0.
			AddRow("CVE-2026-0001", float64(0), 9.8, "CRITICAL", projID, "app-a", "libx", "1.0").
			// Synced CVE: the real score passes through.
			AddRow("CVE-2026-0002", 0.4237, 7.5, "HIGH", projID, "app-a", "liby", "2.0"))

	risks, err := repo.GetTopRisksByTenant(context.Background(), tenantID, 10, "cvss")
	if err != nil {
		t.Fatalf("GetTopRisksByTenant: %v", err)
	}
	if len(risks) != 2 {
		t.Fatalf("len(risks) = %d, want 2", len(risks))
	}
	if risks[0].EPSSScore != 0 {
		t.Errorf("risks[0].EPSSScore = %v, want 0 (un-synced row COALESCEs to 0)", risks[0].EPSSScore)
	}
	if risks[1].EPSSScore != 0.4237 {
		t.Errorf("risks[1].EPSSScore = %v, want 0.4237 (real synced score passes through)", risks[1].EPSSScore)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestGetTopRisksByTenant_NullEPSSWithoutCoalesceErrors documents WHY the
// COALESCE is load-bearing (M36-A / F432): TopRisk.EPSSScore is a bare float64,
// so a raw SQL NULL scanned into it errors. The 055 column is nullable and stays
// NULL until epss_sync runs, so a bare `v.epss_score` read would 500 on an
// un-synced top-risk row. COALESCE(v.epss_score, 0) makes the DB return 0
// instead. Here we feed the raw NULL a bare column would yield and confirm it is
// the error path.
func TestGetTopRisksByTenant_NullEPSSWithoutCoalesceErrors(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewDashboardRepository(db)

	tenantID := uuid.New()
	projID := uuid.New()
	mock.ExpectQuery(`(?is)FROM\s+vulnerabilities\s+v`).
		WithArgs(tenantID, 10).
		WillReturnRows(sqlmock.NewRows([]string{
			"cve_id", "epss_score", "cvss_score", "severity",
			"project_id", "project_name", "component_name", "component_version",
		}).
			AddRow("CVE-2026-0003", nil, 9.8, "CRITICAL", projID, "app-a", "libx", "1.0"))

	if _, err := repo.GetTopRisksByTenant(context.Background(), tenantID, 10, "cvss"); err == nil {
		t.Fatalf("expected a scan error when a raw NULL epss_score reaches the bare float64 target (the 500 path COALESCE prevents)")
	}
}

// TestGetTopRisksByTenant_OuterOrderBy pins the F449 / M39 flip: the OUTER
// wrapper's ORDER BY must switch on sortBy. "epss" orders by exploitation
// probability (epss_score DESC NULLS LAST, cvss_score DESC); anything else
// keeps the historical cvss_score DESC. The assertion is structural on the SQL
// (regex over the emitted query), so it is non-vacuous: a revert to a single
// hardcoded ORDER BY would fail one branch or the other. The INNER DISTINCT ON
// dedup order must stay unchanged in both branches.
func TestGetTopRisksByTenant_OuterOrderBy(t *testing.T) {
	cols := []string{
		"cve_id", "epss_score", "cvss_score", "severity",
		"project_id", "project_name", "component_name", "component_version",
	}

	// otherSQL is a literal sample of the OPPOSITE branch's outer clause. The
	// per-branch wantOuter pattern must NOT match it — that is what makes the
	// assertion non-vacuous (a single hardcoded ORDER BY could only satisfy one
	// branch, and the guard proves the two patterns are genuinely exclusive).
	cases := []struct {
		name      string
		sortBy    string
		wantOuter *regexp.Regexp
		otherSQL  string
	}{
		{
			name:      "epss",
			sortBy:    "epss",
			wantOuter: regexp.MustCompile(`(?is)\)\s+sub\s+ORDER BY epss_score DESC NULLS LAST,\s*cvss_score DESC NULLS LAST,\s*cve_id\s+LIMIT`),
			otherSQL:  ") sub\n\t\tORDER BY cvss_score DESC NULLS LAST, cve_id\n\t\tLIMIT $2",
		},
		{
			name:      "cvss",
			sortBy:    "cvss",
			wantOuter: regexp.MustCompile(`(?is)\)\s+sub\s+ORDER BY cvss_score DESC NULLS LAST,\s*cve_id\s+LIMIT`),
			otherSQL:  ") sub\n\t\tORDER BY epss_score DESC NULLS LAST, cvss_score DESC NULLS LAST, cve_id\n\t\tLIMIT $2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			repo := NewDashboardRepository(db)

			// Non-vacuousness guard: the branch's pattern must not also match
			// the opposite branch's clause.
			if tc.wantOuter.MatchString(tc.otherSQL) {
				t.Fatalf("want pattern is vacuous: it also matches the opposite branch's clause %q", tc.otherSQL)
			}

			tenantID := uuid.New()
			projID := uuid.New()
			mock.ExpectQuery(tc.wantOuter.String()).
				WithArgs(tenantID, 10).
				WillReturnRows(sqlmock.NewRows(cols).
					AddRow("CVE-2026-1000", 0.9, 5.0, "MEDIUM", projID, "app", "lib", "1.0"))

			if _, err := repo.GetTopRisksByTenant(context.Background(), tenantID, 10, tc.sortBy); err != nil {
				t.Fatalf("GetTopRisksByTenant(%q): %v", tc.sortBy, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet expectations for sortBy=%q: %v", tc.sortBy, err)
			}
		})
	}
}

// TestGetTopRisksByTenant_InnerDistinctOnUnchanged confirms the DISTINCT ON
// dedup order is identical for both sortBy branches (Postgres requires the
// leading ORDER BY of DISTINCT ON to be the distinct expression). Only the
// outer wrapper order may change.
func TestGetTopRisksByTenant_InnerDistinctOnUnchanged(t *testing.T) {
	cols := []string{
		"cve_id", "epss_score", "cvss_score", "severity",
		"project_id", "project_name", "component_name", "component_version",
	}
	inner := regexp.MustCompile(`(?is)DISTINCT ON \(v\.cve_id\).*ORDER BY v\.cve_id, v\.cvss_score DESC`)

	for _, sortBy := range []string{"epss", "cvss"} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		repo := NewDashboardRepository(db)
		tenantID := uuid.New()
		projID := uuid.New()
		mock.ExpectQuery(inner.String()).
			WithArgs(tenantID, 10).
			WillReturnRows(sqlmock.NewRows(cols).
				AddRow("CVE-2026-2000", 0.1, 8.0, "HIGH", projID, "app", "lib", "1.0"))

		if _, err := repo.GetTopRisksByTenant(context.Background(), tenantID, 10, sortBy); err != nil {
			t.Fatalf("GetTopRisksByTenant(%q): %v", sortBy, err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("inner DISTINCT ON not preserved for sortBy=%q: %v", sortBy, err)
		}
		db.Close()
	}
}

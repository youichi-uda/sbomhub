package repository

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestGetTopRisksByTenant_ReadsRealEPSSColumn pins the M36-A / F432 flip:
// GetTopRisksByTenant must SELECT the real epss_score column, NOT the old
// fixed 0::numeric sentinel (which could never surface a synced score).
//
// M47 W4 inverted the shape this test pins. It previously required
// COALESCE(v.epss_score, 0) and asserted that an un-synced row reads 0 —
// i.e. it pinned the sentinel contract as correct. The column is now read
// BARE and an un-synced row must surface as nil; a synced score still passes
// through unchanged, which is what proves the read is the live column and not
// a constant. The structural negative below fails a revert to 0::numeric.
func TestGetTopRisksByTenant_ReadsRealEPSSColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewDashboardRepository(db)

	// sqlmock normalises the statement to a single spaced line, so the
	// discriminator anchors on the preceding column: the bare form emits
	// "v.cve_id, v.epss_score," while both sentinel forms interpose either
	// 0::numeric or a COALESCE wrapper.
	pattern := regexp.MustCompile(`(?is)v\.cve_id,\s*v\.epss_score,`)
	if pattern.MatchString("v.cve_id, 0::numeric as epss_score,") {
		t.Fatalf("pattern is vacuous: it also matches the old 0::numeric sentinel")
	}
	if pattern.MatchString("v.cve_id, COALESCE(v.epss_score, 0) as epss_score,") {
		t.Fatalf("pattern is vacuous: it also matches the COALESCE sentinel form")
	}

	tenantID := uuid.New()
	projID := uuid.New()
	mock.ExpectQuery(pattern.String()).
		WithArgs(tenantID, 10).
		WillReturnRows(sqlmock.NewRows([]string{
			"cve_id", "epss_score", "cvss_score", "severity",
			"project_id", "project_name", "component_name", "component_version",
		}).
			// Un-synced CVE: the bare column yields a raw NULL -> nil pointer.
			AddRow("CVE-2026-0001", nil, 9.8, "CRITICAL", projID, "app-a", "libx", "1.0").
			// Synced CVE: the real score passes through.
			AddRow("CVE-2026-0002", 0.4237, 7.5, "HIGH", projID, "app-a", "liby", "2.0"))

	risks, err := repo.GetTopRisksByTenant(context.Background(), tenantID, 10, "cvss")
	if err != nil {
		t.Fatalf("GetTopRisksByTenant: %v", err)
	}
	if len(risks) != 2 {
		t.Fatalf("len(risks) = %d, want 2", len(risks))
	}
	if risks[0].EPSSScore != nil {
		t.Errorf("un-synced risk EPSSScore = %v, want nil (un-scored is NOT 0%%)", *risks[0].EPSSScore)
	}
	if risks[1].EPSSScore == nil {
		t.Fatalf("synced risk EPSSScore = nil, want 0.4237 (real synced score passes through)")
	}
	if *risks[1].EPSSScore != 0.4237 {
		t.Errorf("risks[1].EPSSScore = %v, want 0.4237 (real synced score passes through)", *risks[1].EPSSScore)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestGetTopRisksByTenant_NoCVSSZeroSentinel pins the M46 wave-4 flip of the
// old M41 COALESCE: cvss_score must be read BARE (no COALESCE(v.cvss_score, 0))
// and scanned into the *float64 TopRisk.CVSSScore. CVSS 0.0 is a real "None"
// score, so the 0-sentinel made an un-scored (NVD "Awaiting Analysis") CRITICAL
// render as "CVSS 0.0" on the dashboard and in the PDF/Excel reports — i.e. as
// harmless. Un-scored must surface as nil (JSON: omitted), and a genuine 0.0
// must pass through non-nil so the two stay distinguishable. Structural: the
// negative regex fails on a revert to the COALESCE sentinel.
func TestGetTopRisksByTenant_NoCVSSZeroSentinel(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewDashboardRepository(db)

	// The query must carry the bare nullable column, not the 0-sentinel.
	sentinel := regexp.MustCompile(`(?is)` + regexp.QuoteMeta("COALESCE(v.cvss_score, 0)"))
	bare := regexp.MustCompile(`(?is)v\.cvss_score\s*,`)
	if !bare.MatchString("v.cvss_score,") {
		t.Fatalf("bare pattern is broken: it does not match the fixed column")
	}

	tenantID := uuid.New()
	projID := uuid.New()
	mock.ExpectQuery(bare.String()).
		WithArgs(tenantID, 10).
		WillReturnRows(sqlmock.NewRows([]string{
			"cve_id", "epss_score", "cvss_score", "severity",
			"project_id", "project_name", "component_name", "component_version",
		}).
			// Un-scored CVE: the bare column yields a raw NULL -> nil pointer.
			AddRow("CVE-2026-0003", float64(0), nil, "CRITICAL", projID, "app-a", "libz", "1.2").
			// Real "None" score: 0.0 passes through non-nil.
			AddRow("CVE-2026-0004", float64(0), float64(0), "LOW", projID, "app-a", "libw", "2.0"))

	risks, err := repo.GetTopRisksByTenant(context.Background(), tenantID, 10, "epss")
	if err != nil {
		t.Fatalf("GetTopRisksByTenant: %v", err)
	}
	if len(risks) != 2 {
		t.Fatalf("len(risks) = %d, want 2", len(risks))
	}
	if risks[0].CVSSScore != nil {
		t.Errorf("un-scored risk CVSSScore = %v, want nil (un-scored is NOT 0.0)", *risks[0].CVSSScore)
	}
	if risks[1].CVSSScore == nil {
		t.Errorf("real 0.0-scored risk CVSSScore = nil, want *0.0 (0.0 is a real 'None' score)")
	} else if *risks[1].CVSSScore != 0 {
		t.Errorf("real 0.0-scored risk CVSSScore = %v, want 0.0", *risks[1].CVSSScore)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	// Structural negative: the emitted SQL must not have reverted to the
	// sentinel. sqlmock matched `bare` above; assert the sentinel shape is
	// genuinely absent from the repository's query text by re-running against
	// an expectation that would ONLY match the sentinel form.
	db2, mock2, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db2.Close()
	repo2 := NewDashboardRepository(db2)
	mock2.ExpectQuery(sentinel.String()).WithArgs(tenantID, 10).
		WillReturnRows(sqlmock.NewRows([]string{
			"cve_id", "epss_score", "cvss_score", "severity",
			"project_id", "project_name", "component_name", "component_version",
		}))
	if _, err := repo2.GetTopRisksByTenant(context.Background(), tenantID, 10, "epss"); err == nil {
		t.Fatalf("query still matches the COALESCE(v.cvss_score, 0) sentinel form — wave-4 revert")
	}
}

// TestGetTopRisksByTenant_NullEPSSScansCleanly is the M47 W4 inversion of the
// old TestGetTopRisksByTenant_NullEPSSWithoutCoalesceErrors, which asserted
// that a raw NULL epss_score MUST error and therefore justified the COALESCE.
// That justification only held while TopRisk.EPSSScore was a bare float64.
// The field is now *float64, so the 055 column's NULL — which is the normal
// state until epss_sync runs, and the state migration 059's tombstone
// deliberately restores — must scan cleanly to nil instead of 500-ing.
//
// A real 0.0 is asserted alongside it: epss_score is DECIMAL(5,4), so a
// FIRST score below 0.00005 rounds to exactly 0.0000 on insert. That value
// must stay non-nil and distinguishable from "no score".
func TestGetTopRisksByTenant_NullEPSSScansCleanly(t *testing.T) {
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
			AddRow("CVE-2026-0003", nil, 9.8, "CRITICAL", projID, "app-a", "libx", "1.0").
			AddRow("CVE-2026-0004", float64(0), 9.8, "CRITICAL", projID, "app-a", "libx", "1.0"))

	risks, err := repo.GetTopRisksByTenant(context.Background(), tenantID, 10, "cvss")
	if err != nil {
		t.Fatalf("a raw NULL epss_score must scan cleanly into *float64, got: %v", err)
	}
	if len(risks) != 2 {
		t.Fatalf("len(risks) = %d, want 2", len(risks))
	}
	if risks[0].EPSSScore != nil {
		t.Errorf("NULL epss_score = %v, want nil", *risks[0].EPSSScore)
	}
	if risks[1].EPSSScore == nil {
		t.Fatalf("real 0.0 epss_score = nil, want *0.0 (a rounded-to-zero FIRST score is a measurement)")
	}
	if *risks[1].EPSSScore != 0 {
		t.Errorf("real 0.0 epss_score = %v, want 0.0", *risks[1].EPSSScore)
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

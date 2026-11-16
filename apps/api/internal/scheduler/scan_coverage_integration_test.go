//go:build integration

package scheduler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// Scan coverage (2026-11): a scheduled scan never queries JVN and reports it
// skipped; offline mode makes every step a no-op and reports it skipped,
// never checked.
func TestScheduledScanReportsCoverage(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	t.Cleanup(srv.Close)

	for _, tc := range []struct {
		name             string
		offline          bool
		checked, skipped []string
	}{
		{"online", false, []string{"nvd", "distro"}, []string{"jvn"}},
		{"offline", true, []string{}, []string{"nvd", "jvn", "distro"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantID := seedWave3Tenant(t, migDB, "cov"+tc.name)
			m62SchedSeedProject(t, migDB, tenantID, "covlib")
			var sbomID uuid.UUID
			tx, err := migDB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
				t.Fatal(err)
			}
			if err := tx.QueryRow(`SELECT id FROM sboms WHERE tenant_id = $1`, tenantID).Scan(&sbomID); err != nil {
				t.Fatal(err)
			}
			_ = tx.Rollback()

			tracker := service.NewScanTracker()
			cr := repository.NewComponentRepository(appDB)
			job := (&VulnerabilityScanJob{
				db: appDB,
				nvdService: service.NewNVDService(repository.NewVulnerabilityRepository(appDB), cr,
					"cov-fake-api-key", srv.URL, tc.offline),
			}).WithScanDeadline(10 * time.Second).WithScanTracker(tracker).
				WithDistroScanner(service.NewDistroService(cr, srv.URL, nil, tc.offline))
			if err := job.scanTenant(context.Background(), tenantID); err != nil {
				t.Fatalf("scheduled scan: %v", err)
			}
			st := tracker.GetStatus(sbomID)
			if st.State != service.ScanStateCompleted || !st.CheckedKnown ||
				!slices.Equal(st.Checked, tc.checked) || !slices.Equal(st.Skipped, tc.skipped) {
				t.Errorf("status %+v, want completed checked %v skipped %v", st, tc.checked, tc.skipped)
			}
		})
	}
}

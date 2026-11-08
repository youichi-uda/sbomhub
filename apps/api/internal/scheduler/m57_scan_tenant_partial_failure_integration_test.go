//go:build integration

// Package scheduler — M57: once a refused catalogue write stopped aborting the
// tenant transaction, the scheduled scan's own bookkeeping had to stop
// assuming "an error means nothing was written".
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M57ScanTenant' ./internal/scheduler
package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// TestM57ScanTenant_APartialProjectScanIsReportedAndItsFindingsCounted
// (Codex M57 R2, High).
//
// One project, one component, an NVD page holding a valid CVE A and a CVE
// whose id is one character past VARCHAR(50). Since M57 the refused catalogue
// INSERT no longer aborts the tenant transaction, so A's link commits — which
// is the point — but scanTenant was written for the old world: scanProject
// returned on the scanner's error BEFORE counting, scanTenant logged and moved
// on, and the scan log said `completed` with new_vulnerabilities 0. A's link
// was then durable but never counted as new, so no notification was ever
// sent for it — the next scan sees it as already present.
//
// Before M57 the same page aborted the transaction: nothing was written, and
// the scan log said `failed`. Both of those were honest about the outcome; the
// combination after M57 was not.
func TestM57ScanTenant_APartialProjectScanIsReportedAndItsFindingsCounted(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	tenantID := seedWave3Tenant(t, migDB, "m57partial")
	projectID, sbomID, componentID := uuid.New(), uuid.New(), uuid.New()
	execWave3AsTenant(t, migDB, tenantID, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm57')`, projectID, tenantID)
	execWave3AsTenant(t, migDB, tenantID, `INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
		VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{"bomFormat":"CycloneDX"}'::jsonb, NOW())`, sbomID, tenantID, projectID)
	execWave3AsTenant(t, migDB, tenantID, `INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
		VALUES ($1, $2, $3, 'm57lib', '1.0', 'library', 'pkg:generic/m57lib@1.0', 'MIT', NOW())`, componentID, tenantID, sbomID)

	cveA := fmt.Sprintf("CVE-2093-%07d", uuid.New().ID()%10000000)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveA); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	tooLong := "CVE-2900-" + strings.Repeat("9", 42)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"resultsPerPage": 2, "startIndex": 0, "totalResults": 2, "vulnerabilities": [
			{"cve": {"id": %q, "published": "2093-01-01T00:00:00.000", "descriptions": [{"lang": "en", "value": "A"}],
			  "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}},
			{"cve": {"id": %q, "published": "2093-01-01T00:00:00.000", "descriptions": [{"lang": "en", "value": "refused"}]}}
		]}`, cveA, tooLong)
	}))
	t.Cleanup(srv.Close)

	job := &VulnerabilityScanJob{
		db: appDB,
		nvdService: service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
			repository.NewComponentRepository(appDB), "m57-fake-api-key", srv.URL, false),
	}
	_ = job.scanTenant(context.Background(), tenantID)

	var links int
	if err := migDB.QueryRow(`SELECT count(*) FROM component_vulnerabilities cv JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.component_id = $1 AND v.cve_id = $2`, componentID, cveA).Scan(&links); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if links != 1 {
		t.Fatalf("precondition: CVE A's link is not durable (%d); the scenario is the partial commit", links)
	}

	var status string
	var newVulns sql.NullInt64
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if err := tx.QueryRow(`SELECT status, new_vulnerabilities FROM scan_logs WHERE tenant_id = $1 ORDER BY started_at DESC LIMIT 1`,
		tenantID).Scan(&status, &newVulns); err != nil {
		t.Fatalf("read scan log: %v", err)
	}
	if status != "failed" {
		t.Errorf("scan log status = %q, want failed: a scan that lost a match the database refused must not be "+
			"recorded as completed", status)
	}
	if !newVulns.Valid || newVulns.Int64 != 1 {
		t.Errorf("scan log new_vulnerabilities = %v, want 1: CVE A's link committed, and if it is not counted now it "+
			"is never notified — the next scan sees it as already present", newVulns)
	}
}

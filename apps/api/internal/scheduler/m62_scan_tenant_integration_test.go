//go:build integration

// Package scheduler — M62: the scheduled scan holds no transaction while NVD
// answers, escalates a PARTIAL fetch failure, and records the reasons.
//
//	cd apps/api && go test -tags=integration -count=1 -run 'M62' ./internal/scheduler
package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

func m62SchedSeedProject(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, components ...string) {
	t.Helper()
	projectID, sbomID := uuid.New(), uuid.New()
	execWave3AsTenant(t, migDB, tenantID, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm62')`, projectID, tenantID)
	execWave3AsTenant(t, migDB, tenantID, `INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
		VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{"bomFormat":"CycloneDX"}'::jsonb, NOW())`, sbomID, tenantID, projectID)
	for _, c := range components {
		id := uuid.New()
		execWave3AsTenant(t, migDB, tenantID, `INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
			VALUES ($1, $2, $3, $4, '1.0', 'library', $5, 'MIT', NOW())`, id, tenantID, sbomID, c, "pkg:generic/"+c+"@1.0")
	}
}

func m62SchedCVE(t *testing.T, migDB *sql.DB) string {
	t.Helper()
	cve := fmt.Sprintf("CVE-2093-%07d", uuid.New().ID()%10000000)
	t.Cleanup(func() { _, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cve) })
	return cve
}

func m62SchedLastLog(t *testing.T, migDB *sql.DB, tenantID uuid.UUID) (status string, newVulns int64, msg string) {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	var m sql.NullString
	var n sql.NullInt64
	if err := tx.QueryRow(`SELECT status, new_vulnerabilities, error_message FROM scan_logs
		WHERE tenant_id = $1 ORDER BY started_at DESC LIMIT 1`, tenantID).Scan(&status, &n, &m); err != nil {
		t.Fatalf("read scan log: %v", err)
	}
	return status, n.Int64, m.String
}

// One component answers, one fails at NVD (HTTP 500), and while the third is
// blocked at NVD no app-role backend is inside a transaction. The partial
// failure marks the tenant scan failed with reason fetch_failed, and the
// finding that did commit is counted.
func TestM62ScanTenant_NoTxDuringFetchAndPartialFailureIsFailed(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	tenantID := seedWave3Tenant(t, migDB, "m62sched")
	m62SchedSeedProject(t, migDB, tenantID, "m62ok", "m62broken", "m62slow")
	cveOK, cveSlow := m62SchedCVE(t, migDB), m62SchedCVE(t, migDB)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kw := r.URL.Query().Get("keywordSearch")
		cve := ""
		switch {
		case strings.HasPrefix(kw, "m62broken"):
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		case strings.HasPrefix(kw, "m62slow"):
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			cve = cveSlow
		case strings.HasPrefix(kw, "m62ok"):
			cve = cveOK
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "vulnerabilities": [
			{"cve": {"id": %q, "published": "2093-01-01T00:00:00.000", "descriptions": [{"lang": "en", "value": "m62"}]}}]}`, cve)
	}))
	t.Cleanup(srv.Close)

	job := (&VulnerabilityScanJob{
		db: appDB,
		nvdService: service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
			repository.NewComponentRepository(appDB), "m62-fake-api-key", srv.URL, false),
	}).WithScanDeadline(time.Minute)
	done := make(chan struct{})
	go func() { defer close(done); _ = job.scanTenant(context.Background(), tenantID) }()

	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the slow NVD request never arrived")
	}
	time.Sleep(1500 * time.Millisecond)
	var inTx int
	var detail sql.NullString
	if err := appDB.QueryRow(`SELECT count(*) FILTER (WHERE xact_start IS NOT NULL), string_agg(state || ' ' || left(query, 80), ' | ')
		FROM pg_stat_activity WHERE usename = current_user AND pid <> pg_backend_pid() AND backend_type = 'client backend'`).
		Scan(&inTx, &detail); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done

	if inTx != 0 {
		t.Errorf("while NVD was blocked, %d app-role backend(s) were in a transaction: %s", inTx, detail.String)
	}
	status, newVulns, msg := m62SchedLastLog(t, migDB, tenantID)
	if status != "failed" || msg != "scan failed (fetch_failed)" {
		t.Errorf("scan log = %q / %q, want failed / \"scan failed (fetch_failed)\": a partial fetch failure must not read as completed", status, msg)
	}
	if newVulns != 2 {
		t.Errorf("new_vulnerabilities = %d, want 2 (the two findings that committed)", newVulns)
	}
}

// The deadline is recorded as such in the scan log.
func TestM62ScanTenant_DeadlineIsRecorded(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	tenantID := seedWave3Tenant(t, migDB, "m62schedDL")
	m62SchedSeedProject(t, migDB, tenantID, "m62hang")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(srv.Close)

	job := (&VulnerabilityScanJob{
		db: appDB,
		nvdService: service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
			repository.NewComponentRepository(appDB), "m62-fake-api-key", srv.URL, false),
	}).WithScanDeadline(2 * time.Second)
	start := time.Now()
	_ = job.scanTenant(context.Background(), tenantID)
	if el := time.Since(start); el > 20*time.Second {
		t.Errorf("a 2s deadline let the scheduled scan run %s", el)
	}
	status, _, msg := m62SchedLastLog(t, migDB, tenantID)
	if status != "failed" || msg != "scan failed (deadline_exceeded)" {
		t.Errorf("scan log = %q / %q, want failed / \"scan failed (deadline_exceeded)\"", status, msg)
	}
}

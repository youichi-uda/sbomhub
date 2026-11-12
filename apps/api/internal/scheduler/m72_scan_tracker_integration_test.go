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

// Codex M72 R1 Medium-8: a scheduled project scan is visible in scan-status —
// running while it runs, then its outcome — instead of leaving the SBOM's
// previous (upload) state standing.
func TestM72ScheduledScanIsTracked(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	tenantID := seedWave3Tenant(t, migDB, "m72sched")
	m62SchedSeedProject(t, migDB, tenantID, "m72hang")
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
	// The SBOM's upload scan had completed.
	tracker.Finish(sbomID, tracker.Begin(sbomID), nil, "")

	entered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	job := (&VulnerabilityScanJob{
		db: appDB,
		nvdService: service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
			repository.NewComponentRepository(appDB), "m72-fake-api-key", srv.URL, false),
	}).WithScanDeadline(3 * time.Second).WithScanTracker(tracker)

	done := make(chan struct{})
	go func() { defer close(done); _ = job.scanTenant(context.Background(), tenantID) }()
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the scheduled scan never reached NVD")
	}
	if st, _, _ := tracker.GetDetail(sbomID); st != service.ScanStateRunning {
		t.Errorf("during the scheduled scan: %s, want running", st)
	}
	<-done
	st, msg, reasons := tracker.GetDetail(sbomID)
	if st != service.ScanStateFailed || msg != "scheduled: scan failed (deadline_exceeded)" ||
		!slices.Equal(reasons, []string{service.ScanReasonDeadlineExceeded}) {
		t.Errorf("after the scheduled scan: %s %q %v, want failed deadline_exceeded", st, msg, reasons)
	}
}

// Codex M72 R8 High-2: a scheduled scan does not wait for the tenant's scan
// slots (it would hold up every later tenant of the sequential scheduler).
func TestM72ScheduledScanDoesNotWaitForTenantSlots(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	tenantID := seedWave3Tenant(t, migDB, "m72slots")
	m62SchedSeedProject(t, migDB, tenantID, "m72free")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	t.Cleanup(srv.Close)
	// The tenant's own scans hold every slot.
	for i := 0; i < service.TenantScanConcurrency(); i++ {
		rel, err := service.AcquireTenantScanSlot(context.Background(), tenantID, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		defer rel()
	}
	job := (&VulnerabilityScanJob{
		db: appDB,
		nvdService: service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
			repository.NewComponentRepository(appDB), "m72-fake-api-key", srv.URL, false),
	}).WithScanDeadline(3 * time.Second)
	start := time.Now()
	if err := job.scanTenant(context.Background(), tenantID); err != nil {
		t.Fatalf("scheduled scan: %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("the scheduled scan waited %s for the tenant's slots", el)
	}
}

// Codex M72 R8 High-3: a panic inside a scheduled project scan is recorded
// as a failure, never as a completed scan.
func TestM72ScheduledScanPanicIsRecordedAsFailure(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	tenantID := seedWave3Tenant(t, migDB, "m72panic")
	m62SchedSeedProject(t, migDB, tenantID, "m72boom")
	var sbomID uuid.UUID
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	var projectID uuid.UUID
	if err := tx.QueryRow(`SELECT id, project_id FROM sboms WHERE tenant_id = $1`, tenantID).Scan(&sbomID, &projectID); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()

	tracker := service.NewScanTracker()
	job := (&VulnerabilityScanJob{
		db:         appDB,
		nvdService: service.NewNVDService(nil, nil, "k", "http://127.0.0.1:1", false), // nil repositories: panics
	}).WithScanDeadline(5 * time.Second).WithScanTracker(tracker)
	func() {
		defer func() { _ = recover() }()
		_, _ = job.scanProject(context.Background(), tenantID, projectID)
	}()
	if st, _, reasons := tracker.GetDetail(sbomID); st != service.ScanStateFailed || !slices.Equal(reasons, []string{service.ScanReasonError}) {
		t.Fatalf("after a panic: %s %v, want failed scan_error", st, reasons)
	}
}

//go:build integration

// Package handler — M62: the overall scan deadline and the per-SBOM write
// lock, against the real NVDService and PostgreSQL.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 -run 'M62' ./internal/handler
package handler

import (
	"context"
	"database/sql"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// The deadline fires while one component's NVD request is still pending:
// the finding verified before it is COMMITTED, the scan is reported failed
// with reason deadline_exceeded, and no transaction is left open.
func TestM62Scan_DeadlineCommitsVerifiedFindingsAndReportsFailed(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m62deadline")
	firstID := m62AddComponent(t, migDB, seed, "m62first")
	cveFirst, cveNever := m62CVE(t, migDB), m62CVE(t, migDB)
	nvdStub, srv := newM62NVD(t, map[string]string{"m62first": cveFirst, "libm47": cveNever}, "libm47")

	nvd := service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), "m62-fake-api-key", srv.URL, false)
	jvn := &stubScanner{}
	tracker := service.NewScanTracker()
	h := (&SbomHandler{db: appDB, nvdService: nvd, jvnService: jvn, scanTracker: tracker}).
		WithScanDeadline(3 * time.Second)
	tracker.MarkRunning(seed.sbomID)

	start := time.Now()
	h.runScan(context.Background(), seed.sbomID, seed.tenantID)
	elapsed := time.Since(start)
	_ = nvdStub

	if elapsed > 20*time.Second {
		t.Errorf("a 3s deadline let the scan run %s", elapsed)
	}
	st, msg, reasons := tracker.GetDetail(seed.sbomID)
	if st != service.ScanStateFailed {
		t.Fatalf("state = %s, want failed", st)
	}
	if !slices.Contains(reasons, service.ScanReasonDeadlineExceeded) {
		t.Errorf("reasons = %v (%q), want deadline_exceeded", reasons, msg)
	}
	if jvn.called != 0 {
		t.Errorf("JVN was started after the deadline had fired")
	}
	var firstLinks int
	if err := migDB.QueryRow(`SELECT count(*) FROM component_vulnerabilities cv JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.component_id = $1 AND v.cve_id = $2`, firstID, cveFirst).Scan(&firstLinks); err != nil {
		t.Fatal(err)
	}
	if firstLinks != 1 {
		t.Errorf("the finding verified before the deadline was not committed (links=%d)", firstLinks)
	}
	if n := m62LinkCount(t, migDB, seed.componentID, cveNever); n != 0 {
		t.Errorf("the component the deadline cut off has %d link(s), want 0", n)
	}
	if s := m62AppSessionState(t, appDB); s.inTx != 0 {
		t.Errorf("a transaction was left open after the deadline: %s", s.detail)
	}
}

// The write phase takes the per-SBOM advisory lock: while another session
// holds it, the scan's write waits (and nothing else does — the fetch already
// happened with no transaction open).
func TestM62Scan_WritePhaseWaitsForThePerSbomLock(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m62lock")
	cve := m62CVE(t, migDB)
	_, srv := newM62NVD(t, map[string]string{"libm47": cve})
	nvd := service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), "m62-fake-api-key", srv.URL, false)

	holder, err := migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	if _, err := holder.Exec(`SELECT pg_advisory_xact_lock($1)`, service.ScanLockKey(seed.sbomID)); err != nil {
		t.Fatal(err)
	}

	tracker := service.NewScanTracker()
	h := &SbomHandler{db: appDB, nvdService: nvd, scanTracker: tracker}
	tracker.MarkRunning(seed.sbomID)
	done := make(chan struct{})
	go func() { defer close(done); h.runScan(context.Background(), seed.sbomID, seed.tenantID) }()

	// Wait until the scan's write transaction is waiting on the advisory lock.
	waitUntil := time.Now().Add(30 * time.Second)
	for {
		var waiting int
		if err := migDB.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(waitUntil) {
			t.Fatalf("the scan's write never waited on the per-SBOM advisory lock")
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatalf("the scan finished while another session held its SBOM's write lock")
	case <-time.After(300 * time.Millisecond):
	}
	if n := m62LinkCount(t, migDB, seed.componentID, cve); n != 0 {
		t.Fatalf("a link became visible before the lock was released (%d)", n)
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("the scan did not finish after the lock was released")
	}
	if n := m62LinkCount(t, migDB, seed.componentID, cve); n != 1 {
		t.Errorf("link count after the lock was released = %d, want 1", n)
	}
	if st, _ := tracker.Get(seed.sbomID); st != service.ScanStateCompleted {
		t.Errorf("state = %s, want completed", st)
	}
}

// Two scans of the same SBOM whose NVD answers arrive together: both
// complete, nothing deadlocks, and the new findings are attributed to exactly
// ONE of them (each counts before/after inside its locked write
// transaction). Without the lock both write transactions can count the same
// findings as new.
func TestM62Scan_ConcurrentScansOfOneSbomAttributeNewFindingsOnce(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m62conc")
	names := []string{"m62c1", "m62c2", "m62c3", "m62c4"}
	cves := map[string]string{}
	for _, n := range names {
		m54AddComponent(t, migDB, seed, n)
		cves[n] = m62CVE(t, migDB)
	}
	stub, srv := newM62NVD(t, cves, names...)
	nvd := service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), "m62-fake-api-key", srv.URL, false)

	var wg sync.WaitGroup
	reports := make([]service.NVDScanReport, 2)
	errs := make([]error, 2)
	for i := range reports {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := service.WithScanScope(context.Background(), appDB, seed.tenantID)
			reports[i], errs[i] = nvd.ScanComponentsWithReport(ctx, seed.sbomID)
		}(i)
	}
	// Hold every answer until both scans have asked for all four, then
	// release them together.
	deadline := time.After(60 * time.Second)
	for got := 0; got < 2*len(names); {
		select {
		case <-stub.entered:
			got++
		case <-deadline:
			t.Fatalf("only %d of %d NVD requests arrived", got, 2*len(names))
		}
	}
	stub.releaseAll()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("scan %d failed: %v", i, err)
		}
	}
	total := reports[0].NewVulnerabilities + reports[1].NewVulnerabilities
	if total != len(names) {
		t.Errorf("new findings attributed %d + %d = %d times, want %d in all",
			reports[0].NewVulnerabilities, reports[1].NewVulnerabilities, total, len(names))
	}
}

// m62AddComponent is m54AddComponent returning the new component's id.
func m62AddComponent(t *testing.T, migDB *sql.DB, seed m47Seed, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
		VALUES ($1, $2, $3, $4, '1.0', 'library', $5, 'MIT', NOW())`,
		id, seed.tenantID, seed.sbomID, name, "pkg:generic/"+name+"@1.0"); err != nil {
		t.Fatalf("insert component %s: %v", name, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return id
}

// Codex M62 R1 High-1, the decided half: the deadline bounds FETCHING. A scan
// that fetched everything in time but whose write waited on the per-SBOM lock
// past the deadline has complete, durable results and is reported completed
// (failed means "incomplete", UPGRADE §9.3). Pinned so the choice is explicit.
func TestM62Scan_WriteWaitingPastTheDeadlineIsStillComplete(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m62latewrite")
	cve := m62CVE(t, migDB)
	_, srv := newM62NVD(t, map[string]string{"libm47": cve})
	nvd := service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), "m62-fake-api-key", srv.URL, false)

	holder, err := migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	if _, err := holder.Exec(`SELECT pg_advisory_xact_lock($1)`, service.ScanLockKey(seed.sbomID)); err != nil {
		t.Fatal(err)
	}
	tracker := service.NewScanTracker()
	h := (&SbomHandler{db: appDB, nvdService: nvd, scanTracker: tracker}).WithScanDeadline(1500 * time.Millisecond)
	done := make(chan struct{})
	go func() { defer close(done); h.runScan(context.Background(), seed.sbomID, seed.tenantID) }()

	time.Sleep(3 * time.Second) // well past the deadline, write still blocked
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("scan did not finish after the lock was released")
	}
	if n := m62LinkCount(t, migDB, seed.componentID, cve); n != 1 {
		t.Errorf("link = %d, want 1 (fetched in time, committed after the lock)", n)
	}
	if st, msg := tracker.Get(seed.sbomID); st != service.ScanStateCompleted {
		t.Errorf("state = %s (%q), want completed: every component was fetched before the deadline and written", st, msg)
	}
}

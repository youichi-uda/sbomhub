//go:build integration

// Package handler — what a failed statement costs a scan.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M50VulnScanTx' ./internal/handler
//
// History. M50 wrote this file to pin what VulnerabilityHandler.runScan's
// transaction did to the scanners' writes: they went through ONE transaction
// opened by runScan, so they were invisible to other connections mid-scan,
// and a single failed SQL statement aborted it and discarded EVERY link the
// sweep had written (measured 2026-08-05; UPGRADE §9.6 "a single refused
// statement still discards a whole sweep"). M57 moved the catalogue INSERT
// off that transaction.
//
// M62 removed the transaction from runScan altogether (no transaction may be
// open across NVD/JVN I/O — see m62_scan_no_tx_integration_test.go). Each
// scanner writes its links in one short transaction of its own, with one
// SAVEPOINT per work item, so the M50 tests' premise (a scanner writing on a
// transaction runScan hands it) no longer exists and they were replaced by
// the test below, which pins the new cost of a failed statement with the real
// NVD scanner: only the work item whose statement failed is lost, and the
// scan still reports failed.
package handler

import (
	"context"
	"testing"

	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// A link whose INSERT PostgreSQL refuses (the component was deleted between
// the scan's read and its write, so the foreign key fails) rolls back to its
// work item's savepoint: the OTHER component's link still commits, and the
// scan reports failed with reason write_refused. Before M62 the same refusal
// aborted the sweep's transaction and committed nothing.
func TestM50VulnScanTx_M62_ARefusedStatementCostsOnlyItsWorkItem(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m62poison")
	doomedID := m62AddComponent(t, migDB, seed, "m62doomed")
	cveKept, cveDoomed := m62CVE(t, migDB), m62CVE(t, migDB)
	// Both answers are held until the doomed component is deleted, so the
	// deletion happens after the scan's read and before its write.
	stub, srv := newM62NVD(t, map[string]string{"libm47": cveKept, "m62doomed": cveDoomed}, "libm47", "m62doomed")

	nvd := service.NewNVDService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), "m62-fake-api-key", srv.URL, false)
	tracker := service.NewScanTracker()
	h := &VulnerabilityHandler{db: appDB, nvdService: nvd, scanTracker: tracker}
	tracker.MarkRunning(seed.sbomID)
	done := make(chan struct{})
	go func() { defer close(done); h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd") }()

	stub.waitEnteredAny(t, 2)
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DELETE FROM components WHERE id = $1`, doomedID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	stub.releaseAll()
	<-done

	if n := m62LinkCount(t, migDB, seed.componentID, cveKept); n != 1 {
		t.Errorf("the other work item's link = %d, want 1: one refused statement must not discard the sweep", n)
	}
	st, _, reasons := tracker.GetDetail(seed.sbomID)
	if st != service.ScanStateFailed || len(reasons) != 1 || reasons[0] != service.ScanReasonWriteRefused {
		t.Errorf("state = %s reasons = %v, want failed [write_refused]", st, reasons)
	}
}

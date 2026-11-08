//go:build integration

// Package repository — M57: the global CVE catalogue must not be written, or
// held, from inside a tenant transaction.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M57' ./internal/repository
//
// # The three M55 residual Highs this file pins (repository half)
//
// Every production caller of the per-component scanners (NVDService /
// JVNService) hands them a context carrying ONE tenant transaction that lives
// for the whole sweep — minutes on a real SBOM — because `components` FORCEs
// RLS and the read needs the tenant GUC. The scanners' catalogue write,
// Create, resolved its Queryable from that context and so JOINED the tenant
// transaction. Three consequences, each measured below against PostgreSQL 15:
//
//  1. Visibility. A row Create inserted was invisible to every other
//     connection until the tenant sweep committed. The catalogue's owner
//     (scheduler.CVESyncJob, M55 decision B) refreshes on its own tx-free
//     connection, so for the whole sweep it read MetadataRowAbsent, skipped
//     the CVE, advanced its watermark past the record — and the scanner's
//     possibly-older metadata was what committed.
//  2. Durability coupling. A global row was discarded when one tenant's
//     sweep rolled back, although nothing about the row was tenant-specific.
//  3. Abort cascade. A refused catalogue INSERT aborted the TENANT
//     transaction, so every link the sweep had written was discarded with it
//     (M50 / M54: measured at 0 durable rows).
//
// Plus one consequence of the remaining coupling that M55's own invariant
// ("the scanner must not hold a lock on a global row for the length of a
// sweep", TestM55Create_ConflictTakesNoRowLock) did not cover: the LINK the
// scanner writes inside its tenant transaction takes FOR KEY SHARE on the
// referenced `vulnerabilities` row via the foreign key, and UpdateMetadata's
// `FOR UPDATE` conflicts with KEY SHARE. So the owner's refresh still queued
// behind an unrelated tenant's sweep — just through the link instead of
// through Create.
package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// m57OpenTenantTx opens the shape every scanner caller opens: a transaction on
// the app role with app.current_tenant_id bound. It is rolled back in Cleanup
// unless the test committed it.
func m57OpenTenantTx(t *testing.T, appDB *sql.DB, tenantID uuid.UUID) (*sql.Tx, context.Context, func() error) {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin tenant tx: %v", err)
	}
	done := false
	t.Cleanup(func() {
		if !done {
			_ = tx.Rollback()
		}
	})
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	return tx, database.WithTx(context.Background(), tx), func() error {
		done = true
		return tx.Commit()
	}
}

func m57ScannerVuln(t *testing.T, migDB *sql.DB, cveID string) *model.Vulnerability {
	t.Helper()
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("C27 cleanup: delete %s: %v", cveID, err)
		}
	})
	score := 2.0
	now := time.Now().UTC()
	return &model.Vulnerability{
		ID: uuid.New(), CVEID: cveID, Description: "scanner's possibly-cached copy",
		Severity: "LOW", CVSSScore: &score, Source: "NVD", UpdatedAt: &now,
	}
}

// TestM57Create_IsVisibleToTheOwnerWhileTheScannersTxIsOpen is High (1).
//
// Pre-fix: UpdateMetadata — exactly what cve_sync's refresh calls, on a
// tx-free connection — returns MetadataRowAbsent for a row the scanner has
// already "created", and the scanner's LOW is what commits.
func TestM57Create_IsVisibleToTheOwnerWhileTheScannersTxIsOpen(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	tenantID, _ := m54SeedComponentForLink(t, migDB)
	cveID := m55MetaCVEID()
	v := m57ScannerVuln(t, migDB, cveID)

	_, txCtx, commit := m57OpenTenantTx(t, appDB, tenantID)
	repo := NewVulnerabilityRepository(appDB)
	if err := repo.Create(txCtx, v); err != nil {
		t.Fatalf("Create inside the scanner's tenant tx: %v", err)
	}

	// The owner's refresh, while the sweep is still running.
	july := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	outcome, err := repo.UpdateMetadata(context.Background(), m55Meta(cveID, "CRITICAL", 9.8, "owner refresh", &july))
	if err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if outcome != MetadataWritten {
		t.Errorf("owner refresh outcome = %v, want %v: the row the scanner created is invisible to the catalogue's "+
			"owner until one tenant's sweep commits, so the refresh is skipped and the record is lost", outcome, MetadataWritten)
	}

	if err := commit(); err != nil {
		t.Fatalf("commit tenant tx: %v", err)
	}
	var severity string
	if err := migDB.QueryRow(`SELECT severity FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&severity); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if severity != "CRITICAL" {
		t.Errorf("severity after both committed = %q, want CRITICAL (the owner's newer record)", severity)
	}
}

// TestM57Create_SurvivesTheScannersRollback is the durability half of High
// (3): a catalogue row is global and must not be discarded because one
// tenant's sweep rolled back.
func TestM57Create_SurvivesTheScannersRollback(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	tenantID, _ := m54SeedComponentForLink(t, migDB)
	cveID := m55MetaCVEID()
	v := m57ScannerVuln(t, migDB, cveID)

	tx, txCtx, _ := m57OpenTenantTx(t, appDB, tenantID)
	if err := NewVulnerabilityRepository(appDB).Create(txCtx, v); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	var n int
	if err := migDB.QueryRow(`SELECT count(*) FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("catalogue rows after the tenant tx rolled back = %d, want 1: the global row was enlisted in one "+
			"tenant's transaction and died with it", n)
	}
}

// TestM57Create_RefusalDoesNotAbortTheScannersTx is the cascade half of High
// (3). The poison is data, not DDL: cve_id is VARCHAR(50).
func TestM57Create_RefusalDoesNotAbortTheScannersTx(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	tenantID, componentID := m54SeedComponentForLink(t, migDB)

	// A link written BEFORE the refusal: the thing the cascade used to take.
	good := m57ScannerVuln(t, migDB, m55MetaCVEID())
	tx, txCtx, commit := m57OpenTenantTx(t, appDB, tenantID)
	repo := NewVulnerabilityRepository(appDB)
	if err := repo.Create(txCtx, good); err != nil {
		t.Fatalf("Create (good): %v", err)
	}
	if err := repo.LinkComponent(txCtx, componentID, good.ID); err != nil {
		t.Fatalf("LinkComponent (good): %v", err)
	}

	poison := m57ScannerVuln(t, migDB, "CVE-2900-"+strings.Repeat("9", 42))
	if err := repo.Create(txCtx, poison); err == nil {
		t.Fatal("precondition: the over-long cve_id was accepted, so nothing was refused")
	}

	// The tenant transaction must still be usable.
	var one int
	if err := tx.QueryRow(`SELECT 1`).Scan(&one); err != nil {
		t.Errorf("the tenant transaction is unusable after a refused catalogue write: %v", err)
	}
	if err := commit(); err != nil {
		t.Fatalf("commit after a refused catalogue write: %v — the refusal aborted the tenant tx and the link "+
			"written before it is discarded", err)
	}
	var links int
	if err := migDB.QueryRow(`SELECT count(*) FROM component_vulnerabilities WHERE vulnerability_id = $1`, good.ID).
		Scan(&links); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if links != 1 {
		t.Errorf("durable links = %d, want 1", links)
	}
}

// TestM57Create_DoesNotDeadlockOnAnExhaustedPool pins the cost of moving
// Create off the tenant transaction, and the reason the catalogue has its own
// pool.
//
// A caller holding a tenant transaction holds one pooled connection. If
// Create then needs ANOTHER connection from the SAME pool, N concurrent sweeps
// with N == MaxOpenConns all hold one and all wait for one — and the scanners
// run on context.Background(), so they wait forever. Before the move that
// regime was starvation (every HTTP request queued until the sweeps finished);
// after a naive move it would be a permanent deadlock. The pool size here is
// 1 so one sweep is enough to reach it.
func TestM57Create_DoesNotDeadlockOnAnExhaustedPool(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	migDB := openOrSkip(t, migURL)
	tenantPool := openOrSkip(t, appURL)
	tenantPool.SetMaxOpenConns(1)
	cataloguePool := openOrSkip(t, appURL)

	tenantID, _ := m54SeedComponentForLink(t, migDB)
	v := m57ScannerVuln(t, migDB, m55MetaCVEID())
	_, txCtx, commit := m57OpenTenantTx(t, tenantPool, tenantID)

	repo := NewVulnerabilityRepository(tenantPool).WithCatalogueDB(cataloguePool)
	ctx, cancel := context.WithTimeout(txCtx, 5*time.Second)
	defer cancel()
	if err := repo.Create(ctx, v); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("Create waited for a connection from the pool the caller's own transaction exhausted: " +
				"with N sweeps and MaxOpenConns = N this never resolves")
		}
		t.Fatalf("Create: %v", err)
	}
	if err := commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestM57UpdateMetadata_IsNotBlockedByATenantTxLink: the owner's refresh must
// not queue behind a sweep that merely LINKED a component to the row.
//
// The link's foreign key takes FOR KEY SHARE on the referenced catalogue row
// and holds it until the tenant transaction ends. `FOR UPDATE` conflicts with
// KEY SHARE; `FOR NO KEY UPDATE` does not, and is still self-exclusive, which
// is the only property the staleness guard needs from the lock (two refreshes
// of one row must serialise — TestM55UpdateMetadata_StaleWaiterLosesToACommittedNewerWrite).
func TestM57UpdateMetadata_IsNotBlockedByATenantTxLink(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	june := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cveID := m55SeedCatalogueRow(t, migDB, "NVD", &june)
	var vulnID uuid.UUID
	if err := migDB.QueryRow(`SELECT id FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&vulnID); err != nil {
		t.Fatalf("read id: %v", err)
	}

	tenantID, componentID := m54SeedComponentForLink(t, migDB)
	_, txCtx, commit := m57OpenTenantTx(t, appDB, tenantID)
	if err := NewVulnerabilityRepository(appDB).LinkComponent(txCtx, componentID, vulnID); err != nil {
		t.Fatalf("LinkComponent inside the tenant tx: %v", err)
	}

	july := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	done := make(chan error, 1)
	go func() {
		_, err := NewVulnerabilityRepository(appDB).
			UpdateMetadata(context.Background(), m55Meta(cveID, "CRITICAL", 9.8, "owner refresh", &july))
		done <- err
	}()
	blocked := false
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UpdateMetadata: %v", err)
		}
	case <-time.After(5 * time.Second):
		blocked = true
		t.Error("UpdateMetadata blocked behind a tenant transaction that only LINKED a component to the row: the " +
			"refresh's row lock conflicts with the foreign key's KEY SHARE, so the catalogue owner queues for the " +
			"length of an unrelated tenant's sweep")
	}
	if err := commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if blocked {
		<-done // released by the commit; drain so the goroutine does not outlive the test
	}
}

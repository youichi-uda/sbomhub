//go:build integration

// Package repository — M54: VulnerabilityRepository.Create must leave the
// caller holding the id that is actually in the table.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M54VulnCreate' ./internal/repository
//
// # The defect
//
// Create is `INSERT … ON CONFLICT (cve_id) DO UPDATE SET …`. The SET list does
// not touch `id`, so on the conflict path the row keeps the id it already had
// and the caller's candidate uuid is never stored anywhere. Create nonetheless
// returned nil, and every caller reads the outcome as "the row now has the id
// I passed in":
//
//	// NVDService.persistWorkItem
//	existing, err := s.vulnRepo.GetByCVE(ctx, vuln.CVEID)
//	if err != nil {
//	        if err := s.vulnRepo.Create(ctx, &vuln); err != nil { … }
//	        existing = &vuln            // <- candidate uuid, not the stored one
//	}
//	… s.vulnRepo.LinkComponent(ctx, compID, existing.ID)
//
//	// JVNService.scanComponent does the same thing with vuln.ID.
//
// So the link is written against a `vulnerability_id` that does not exist,
// PostgreSQL refuses it on the foreign key, and — because every production
// caller of the scanners runs inside ONE transaction — that refusal aborts the
// transaction and discards the ENTIRE sweep, not just this row.
//
// # When it fires
//
// Only when GetByCVE MISSES and the row appears before Create runs, which
// needs a second connection: two tenants' scans overlapping on a
// newly-published CVE (the scheduler sweeps every tenant, and uploads scan
// concurrently), or a scan racing the CVE-sync job. Within one scan it cannot
// happen — M54 serialises the worker pool, and both workers are on the same
// transaction, so the second GetByCVE sees the first's write.
//
// This test does not try to win that race. It drives the STATE the race
// produces — the row already exists under a different id — which is the same
// code path with none of the timing, and pins the contract that makes the race
// harmless: after Create returns nil, v.ID is the id in the table.
//
// Raised by Codex in M54 round 3 (High).
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/model"
)

// TestM54VulnCreate_ConflictAdoptsTheStoredID pins the post-condition every
// caller already assumed.
func TestM54VulnCreate_ConflictAdoptsTheStoredID(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	migDB := openOrSkip(t, migURL)
	appDB := openOrSkip(t, appURL)

	cveID := fmt.Sprintf("CVE-2091-%07d", uuid.New().ID()%10000000)
	storedID := uuid.New()
	t.Cleanup(func() {
		// `vulnerabilities` is the shared tenant-less catalogue: reap by hand
		// (C27). component_vulnerabilities cascades from it.
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("C27 cleanup: %v", err)
		}
	})

	// Somebody else's scan got there first, under an id we will never guess.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source)
		VALUES ($1, $2, 'planted by another connection', 'LOW', 2.0, 'NVD')`,
		storedID, cveID); err != nil {
		t.Fatalf("plant the pre-existing row: %v", err)
	}

	repo := NewVulnerabilityRepository(appDB)
	now := time.Now()
	candidate := model.Vulnerability{
		ID:          uuid.New(), // the id this scan would have used
		CVEID:       cveID,
		Description: "m54 upsert probe",
		Severity:    "CRITICAL",
		Source:      "NVD",
		UpdatedAt:   &now,
	}
	if candidate.ID == storedID {
		t.Fatal("precondition: the two uuids collided, which makes this test vacuous")
	}

	if err := repo.Create(context.Background(), &candidate); err != nil {
		t.Fatalf("Create on an existing cve_id must succeed (it is an upsert): %v", err)
	}

	// The load-bearing assertion.
	if candidate.ID != storedID {
		t.Errorf("after Create, v.ID = %s, want the stored id %s.\n"+
			"ON CONFLICT DO UPDATE does not change `id`, so the candidate uuid was never "+
			"written. Callers link with v.ID immediately afterwards, so leaving the candidate "+
			"in place points the foreign key at a row that does not exist.",
			candidate.ID, storedID)
	}

	// And the consequence the callers actually suffer: the link must work.
	// Without the fix this is the statement that fails, and on the scan path
	// that failure aborts the whole sweep's transaction.
	tenantID, componentID := m54SeedComponentForLink(t, migDB)
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(
		`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
		VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING`, componentID, candidate.ID); err != nil {
		t.Errorf("linking a component to the id Create left behind failed: %v.\n"+
			"This is the foreign-key violation that aborts the scan transaction and discards "+
			"every row the sweep had written.", err)
	}

	// The row count must still be one — an upsert, not a second row.
	var n int
	if err := appDB.QueryRow(
		`SELECT COUNT(*) FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("rows for %s = %d, want 1", cveID, n)
	}
}

// m54SeedComponentForLink creates a throwaway tenant/project/sbom/component so
// the link assertion above has a valid component_id. The tenant DELETE
// cascades to all of it (C27).
func m54SeedComponentForLink(t *testing.T, migDB *sql.DB) (tenantID, componentID uuid.UUID) {
	t.Helper()
	tenantID = uuid.New()
	org := "m54-upsert-" + tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		tenantID, org, "m54 upsert", org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tid := tenantID
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tid); err != nil {
			t.Errorf("C27 cleanup: delete tenant %s: %v", tid, err)
		}
	})

	projectID, sbomID := uuid.New(), uuid.New()
	componentID = uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(
			`SELECT set_config('app.current_tenant_id', $1, true)`, tid.String()); err != nil {
			t.Fatalf("SET LOCAL: %v", err)
		}
		if _, err := tx.Exec(query, args...); err != nil {
			t.Fatalf("exec as tenant: %v\nquery: %s", err, query)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm54-upsert')`, projectID, tenantID)
	exec(`INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
	      VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{"bomFormat":"CycloneDX"}'::jsonb, NOW())`,
		sbomID, tenantID, projectID)
	exec(`INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
	      VALUES ($1, $2, $3, 'm54upsertlib', '1.0', 'library', 'pkg:generic/m54upsertlib@1.0', 'MIT', NOW())`,
		componentID, tenantID, sbomID)
	return tenantID, componentID
}

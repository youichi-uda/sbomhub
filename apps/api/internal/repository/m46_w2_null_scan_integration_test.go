//go:build integration

// Package repository — M46 Track A wave 2 nullable-column scan regression
// tests for eol.go / ipa.go / public_link.go / vex.go / ssvc.go.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M46W2_NullableColumnScan' ./internal/repository
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// Prerequisites (skipped otherwise): same as
// vulnerability_null_scan_integration_test.go (postgres up, DATABASE_URL =
// sbomhub_app / MIGRATE_DATABASE_URL = sbomhub_migrator, schema migrated).
//
// What these tests pin down (same disease as wave 1 / B2):
//
// The 022 / 014 / 009 / 003 / 021 schemas leave a set of columns nullable
// while the repositories scanned them into NULL-intolerant Go types.
// A NULL in any of them aborts the whole read with
//
//	sql: Scan error on column index N, name "<col>":
//	converting NULL to <type> is unsupported
//
// NULL rows are real: the dev DB carries 41/41 eol_products rows with NULL
// link and 14/14 ssvc_assessments rows with NULL notes (measured
// 2026-07-26), so ListProducts / GetProductBy* and every ssvc_assessments
// read were failing on live data at the time of the fix.
//
// The fix (wave 2, mirroring f97c7fa):
//   - nullable string columns are COALESCE'd to ” in the SELECTs;
//   - bool / int / timestamptz columns that carry a DDL default and
//     measured 0 real NULL rows (eol_product_cycles.is_lts / is_eol /
//     discontinued, eol_component_mappings.priority / is_active,
//     public_links.is_active / view_count / download_count / created_at /
//     updated_at) apply the DDL default at read time via COALESCE;
//   - vulnerabilities.cvss_score read by ssvc.go joins becomes *float64
//     (SSVCAssessmentWithVuln.VulnerabilityCVSSScore) — same column, same
//     no-0.0-sentinel rationale as wave 1's model.Vulnerability change;
//   - projects.tenant_id (LookupProjectTenantID) scans through
//     uuid.NullUUID and returns an explicit error on NULL instead of the
//     silent uuid.Nil that uuid.UUID.Scan(nil) produces (unit-tested in
//     m46_w2_rows_err_test.go — a NULL-tenant project cannot be seeded
//     through the NOBYPASSRLS roles this suite runs under).
//
// RLS shape: components / sboms / projects / vex_statements /
// ssvc_assessments / ssvc_assessment_history are FORCE RLS, so seeds run
// through execAsTenant (migrator role + tenant GUC) and reads run inside
// an app-role tx via readAsTenantTx — the production TenantTx shape.
// eol_* / ipa_announcements / vulnerabilities are global caches without
// tenant CASCADE; their rows are reaped explicitly via registerCleanupExec
// (C27). public_links has no RLS since migration 030 but CASCADEs off
// tenants.
//
// Populated rows carry a DISTINCT value in every column so a SELECT/Scan
// column-order regression lands a value in the wrong field and fails the
// round-trip assertions (the classic COALESCE-insertion accident).
package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/model"
)

func TestEOLReads_M46W2_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "m46w2-eol")

	// --- Global eol_* rows: register C27 cleanups before the INSERTs.
	// Deleting the products CASCADEs the cycles and mappings.
	nullProdID := uuid.New()
	popProdID := uuid.New()
	nullLogID := uuid.New()
	popLogID := uuid.New()
	registerCleanupExec(t, migDB, "m46w2 eol_products",
		`DELETE FROM eol_products WHERE id IN ($1, $2)`, nullProdID, popProdID)
	registerCleanupExec(t, migDB, "m46w2 eol_sync_logs",
		`DELETE FROM eol_sync_logs WHERE id IN ($1, $2)`, nullLogID, popLogID)

	nullProdName := "m46w2-eol-null-" + tenant.String()
	popProdName := "m46w2-eol-pop-" + tenant.String()

	// NULL product: category / link NULL — the exact shape 41/41 dev-DB
	// rows have for link (endoflife.date pre-population never set it).
	if _, err := migDB.Exec(`
		INSERT INTO eol_products (id, name, title, category, link, total_cycles)
		VALUES ($1, $2, 'm46w2 null product', NULL, NULL, 0)
	`, nullProdID, nullProdName); err != nil {
		t.Fatalf("seed NULL eol_products row: %v", err)
	}
	// Populated product: distinct value per column.
	if _, err := migDB.Exec(`
		INSERT INTO eol_products (id, name, title, category, link, total_cycles)
		VALUES ($1, $2, 'm46w2 pop product', 'database', 'https://example.test/eol-pop', 7)
	`, popProdID, popProdName); err != nil {
		t.Fatalf("seed populated eol_products row: %v", err)
	}

	// Cycles both hang off the populated product so one GetCyclesByProduct
	// call reads both shapes.
	nullCycleID := uuid.New()
	popCycleID := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO eol_product_cycles (id, product_id, cycle, release_date, eol_date, eos_date,
			latest_version, is_lts, is_eol, discontinued, link, support_end_date)
		VALUES ($1, $2, '9.9', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
	`, nullCycleID, popProdID); err != nil {
		t.Fatalf("seed NULL eol_product_cycles row: %v", err)
	}
	popRelease := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	popEOL := time.Date(2027, 3, 4, 0, 0, 0, 0, time.UTC)
	popEOS := time.Date(2027, 5, 6, 0, 0, 0, 0, time.UTC)
	popSupportEnd := time.Date(2027, 7, 8, 0, 0, 0, 0, time.UTC)
	// Alternating bools (true / false / true) pin the is_lts / is_eol /
	// discontinued column order.
	if _, err := migDB.Exec(`
		INSERT INTO eol_product_cycles (id, product_id, cycle, release_date, eol_date, eos_date,
			latest_version, is_lts, is_eol, discontinued, link, support_end_date)
		VALUES ($1, $2, '1.2', $3, $4, $5, '1.2.3', true, false, true, 'https://example.test/cycle-pop', $6)
	`, popCycleID, popProdID, popRelease, popEOL, popEOS, popSupportEnd); err != nil {
		t.Fatalf("seed populated eol_product_cycles row: %v", err)
	}

	// Mappings: component_type / purl_type / priority NULL on one row.
	// is_active must be true on both — GetMappings' WHERE is_active = true
	// can never return a NULL is_active row (NULL is not true), so that
	// COALESCE is exercised only as scan-safety, not behaviour.
	nullMapID := uuid.New()
	popMapID := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO eol_component_mappings (id, product_id, component_pattern, component_type, purl_type, priority, is_active)
		VALUES ($1, $2, $3, NULL, NULL, NULL, true)
	`, nullMapID, popProdID, "m46w2-map-null-"+tenant.String()); err != nil {
		t.Fatalf("seed NULL eol_component_mappings row: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO eol_component_mappings (id, product_id, component_pattern, component_type, purl_type, priority, is_active)
		VALUES ($1, $2, $3, 'library', 'npm', 12345, true)
	`, popMapID, popProdID, "m46w2-map-pop-"+tenant.String()); err != nil {
		t.Fatalf("seed populated eol_component_mappings row: %v", err)
	}

	repo := NewEOLRepository(appDB)
	ctx := context.Background()

	assertNullProduct := func(t *testing.T, p *model.EOLProduct, via string) {
		t.Helper()
		if p == nil {
			t.Errorf("%s: returned nil for seeded product", via)
			return
		}
		if p.Category != "" || p.Link != "" {
			t.Errorf("%s: category=%q link=%q, want \"\"/\"\" for NULL", via, p.Category, p.Link)
		}
		if p.Title != "m46w2 null product" || p.TotalCycles != 0 {
			t.Errorf("%s: title=%q total_cycles=%d round-trip mismatch", via, p.Title, p.TotalCycles)
		}
	}
	assertPopProduct := func(t *testing.T, p *model.EOLProduct, via string) {
		t.Helper()
		if p == nil {
			t.Errorf("%s: returned nil for seeded product", via)
			return
		}
		if p.Name != popProdName || p.Title != "m46w2 pop product" || p.Category != "database" ||
			p.Link != "https://example.test/eol-pop" || p.TotalCycles != 7 {
			t.Errorf("%s: round-trip mismatch: name=%q title=%q category=%q link=%q total_cycles=%d",
				via, p.Name, p.Title, p.Category, p.Link, p.TotalCycles)
		}
		if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
			t.Errorf("%s: created_at/updated_at zero, want DDL defaults", via)
		}
	}

	// --- GetProductByName on the NULL row: the measured live failure
	// (dev DB: 41/41 products carry NULL link).
	np, err := repo.GetProductByName(ctx, nullProdName)
	if err != nil {
		t.Errorf("GetProductByName on a NULL-column row must not fail, got: %v", err)
	} else {
		assertNullProduct(t, np, "GetProductByName(null)")
	}
	pp, err := repo.GetProductByID(ctx, popProdID)
	if err != nil {
		t.Errorf("GetProductByID (populated row): %v", err)
	} else {
		assertPopProduct(t, pp, "GetProductByID(pop)")
	}

	// --- ListProducts: one poisoned row used to abort the whole page.
	products, total, err := repo.ListProducts(ctx, 1000, 0)
	if err != nil {
		t.Errorf("ListProducts with NULL-column rows must not fail, got: %v", err)
	} else {
		if total < 2 {
			t.Errorf("ListProducts total = %d, want >= 2", total)
		}
		var sawNull, sawPop bool
		for i := range products {
			switch products[i].ID {
			case nullProdID:
				sawNull = true
				assertNullProduct(t, &products[i], "ListProducts(null)")
			case popProdID:
				sawPop = true
				assertPopProduct(t, &products[i], "ListProducts(pop)")
			}
		}
		if !sawNull || !sawPop {
			t.Errorf("ListProducts missing seeded rows (null=%v pop=%v)", sawNull, sawPop)
		}
	}

	assertNullCycle := func(t *testing.T, c *model.EOLProductCycle, via string) {
		t.Helper()
		if c.LatestVersion != "" || c.Link != "" {
			t.Errorf("%s: latest_version=%q link=%q, want \"\"/\"\" for NULL", via, c.LatestVersion, c.Link)
		}
		if c.IsLTS || c.IsEOL || c.Discontinued {
			t.Errorf("%s: is_lts=%v is_eol=%v discontinued=%v, want DDL default false for NULL",
				via, c.IsLTS, c.IsEOL, c.Discontinued)
		}
		if c.ReleaseDate != nil || c.EOLDate != nil || c.EOSDate != nil || c.SupportEndDate != nil {
			t.Errorf("%s: date pointers should stay nil for NULL", via)
		}
	}
	assertPopCycle := func(t *testing.T, c *model.EOLProductCycle, via string) {
		t.Helper()
		if c.Cycle != "1.2" || c.LatestVersion != "1.2.3" || c.Link != "https://example.test/cycle-pop" {
			t.Errorf("%s: cycle=%q latest_version=%q link=%q round-trip mismatch", via, c.Cycle, c.LatestVersion, c.Link)
		}
		if !c.IsLTS || c.IsEOL || !c.Discontinued {
			t.Errorf("%s: is_lts=%v is_eol=%v discontinued=%v, want true/false/true (column-order pin)",
				via, c.IsLTS, c.IsEOL, c.Discontinued)
		}
		if c.ReleaseDate == nil || !c.ReleaseDate.UTC().Equal(popRelease) ||
			c.EOLDate == nil || !c.EOLDate.UTC().Equal(popEOL) ||
			c.EOSDate == nil || !c.EOSDate.UTC().Equal(popEOS) ||
			c.SupportEndDate == nil || !c.SupportEndDate.UTC().Equal(popSupportEnd) {
			t.Errorf("%s: date round-trip mismatch: release=%v eol=%v eos=%v support_end=%v",
				via, c.ReleaseDate, c.EOLDate, c.EOSDate, c.SupportEndDate)
		}
	}

	// --- GetCyclesByProduct: release_date DESC NULLS LAST → pop first.
	cycles, err := repo.GetCyclesByProduct(ctx, popProdID)
	if err != nil {
		t.Errorf("GetCyclesByProduct with a NULL-column row must not fail, got: %v", err)
	} else if len(cycles) != 2 {
		t.Errorf("GetCyclesByProduct returned %d rows, want 2", len(cycles))
	} else {
		if cycles[0].ID != popCycleID || cycles[1].ID != nullCycleID {
			t.Errorf("GetCyclesByProduct order = [%s, %s], want [pop %s, null %s] (NULLS LAST)",
				cycles[0].ID, cycles[1].ID, popCycleID, nullCycleID)
		}
		assertPopCycle(t, &cycles[0], "GetCyclesByProduct(pop)")
		assertNullCycle(t, &cycles[1], "GetCyclesByProduct(null)")
	}

	// --- FindMatchingCycle: exact match on the NULL cycle, prefix match
	// on the populated cycle.
	if mc, err := repo.FindMatchingCycle(ctx, popProdID, "9.9"); err != nil {
		t.Errorf("FindMatchingCycle on a NULL-column row must not fail, got: %v", err)
	} else if mc == nil || mc.ID != nullCycleID {
		t.Errorf("FindMatchingCycle(9.9) = %v, want the NULL cycle %s", mc, nullCycleID)
	} else {
		assertNullCycle(t, mc, "FindMatchingCycle(null)")
	}
	if mc, err := repo.FindMatchingCycle(ctx, popProdID, "1.2.5"); err != nil {
		t.Errorf("FindMatchingCycle (populated row): %v", err)
	} else if mc == nil || mc.ID != popCycleID {
		t.Errorf("FindMatchingCycle(1.2.5) = %v, want the populated cycle %s", mc, popCycleID)
	} else {
		assertPopCycle(t, mc, "FindMatchingCycle(pop)")
	}

	// --- GetMappings (global read; other rows may exist — filter by ID).
	mappings, err := repo.GetMappings(ctx)
	if err != nil {
		t.Errorf("GetMappings with a NULL-column row must not fail, got: %v", err)
	} else {
		var sawNull, sawPop bool
		for i := range mappings {
			switch mappings[i].ID {
			case nullMapID:
				sawNull = true
				m := &mappings[i]
				if m.ComponentType != "" || m.PurlType != "" {
					t.Errorf("GetMappings(null): component_type=%q purl_type=%q, want \"\"/\"\"", m.ComponentType, m.PurlType)
				}
				if m.Priority != 0 {
					t.Errorf("GetMappings(null): priority = %d, want DDL default 0 for NULL", m.Priority)
				}
				if !m.IsActive {
					t.Errorf("GetMappings(null): is_active = false, want true (seeded true)")
				}
			case popMapID:
				sawPop = true
				m := &mappings[i]
				if m.ComponentType != "library" || m.PurlType != "npm" || m.Priority != 12345 || !m.IsActive {
					t.Errorf("GetMappings(pop): round-trip mismatch: type=%q purl=%q priority=%d active=%v",
						m.ComponentType, m.PurlType, m.Priority, m.IsActive)
				}
			}
		}
		if !sawNull || !sawPop {
			t.Errorf("GetMappings missing seeded rows (null=%v pop=%v)", sawNull, sawPop)
		}
	}

	// --- GetLatestSyncLog: seed the NULL log first (latest at that
	// point), read, then the populated log (now latest), read again.
	if _, err := migDB.Exec(`
		INSERT INTO eol_sync_logs (id, started_at, status, error_message)
		VALUES ($1, '2099-01-01T00:00:00Z', 'running', NULL)
	`, nullLogID); err != nil {
		t.Fatalf("seed NULL eol_sync_logs row: %v", err)
	}
	nl, err := repo.GetLatestSyncLog(ctx)
	if err != nil {
		t.Errorf("GetLatestSyncLog on a NULL-column row must not fail, got: %v", err)
	} else if nl == nil || nl.ID != nullLogID {
		t.Errorf("GetLatestSyncLog = %v, want the 2099-01-01 row %s", nl, nullLogID)
	} else {
		if nl.ErrorMessage != "" {
			t.Errorf("GetLatestSyncLog(null): ErrorMessage = %q, want \"\"", nl.ErrorMessage)
		}
		if nl.CompletedAt != nil {
			t.Errorf("GetLatestSyncLog(null): CompletedAt = %v, want nil", nl.CompletedAt)
		}
	}
	if _, err := migDB.Exec(`
		INSERT INTO eol_sync_logs (id, started_at, completed_at, status, products_synced, cycles_synced, components_updated, error_message)
		VALUES ($1, '2099-01-02T00:00:00Z', '2099-01-02T00:05:00Z', 'failed', 3, 4, 5, 'pop error')
	`, popLogID); err != nil {
		t.Fatalf("seed populated eol_sync_logs row: %v", err)
	}
	pl, err := repo.GetLatestSyncLog(ctx)
	if err != nil {
		t.Errorf("GetLatestSyncLog (populated row): %v", err)
	} else if pl == nil || pl.ID != popLogID {
		t.Errorf("GetLatestSyncLog = %v, want the 2099-01-02 row %s", pl, popLogID)
	} else if pl.Status != "failed" || pl.ProductsSynced != 3 || pl.CyclesSynced != 4 ||
		pl.ComponentsUpdated != 5 || pl.ErrorMessage != "pop error" || pl.CompletedAt == nil {
		t.Errorf("GetLatestSyncLog(pop) round-trip mismatch: %+v", pl)
	}

	// --- Tenant-scoped component reads (RLS via sboms join).
	projectID := uuid.New()
	sbomID := uuid.New()
	nullCompID := uuid.New()
	popCompID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46w2-eol-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO sboms (id, project_id, tenant_id, format) VALUES ($1, $2, $3, 'cyclonedx')
	`, sbomID, projectID, tenant); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
		VALUES ($1, $2, $3, 'm46w2-comp-null', NULL, NULL, NULL, NULL, NULL)
	`, nullCompID, tenant, sbomID); err != nil {
		t.Fatalf("seed NULL component: %v", err)
	}
	popCompCreatedAt := time.Date(2026, 7, 1, 12, 30, 0, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
		VALUES ($1, $2, $3, 'm46w2-comp-pop', '1.2.3', 'library', 'pkg:npm/m46w2-comp-pop@1.2.3', 'MIT', $4)
	`, popCompID, tenant, sbomID, popCompCreatedAt); err != nil {
		t.Fatalf("seed populated component: %v", err)
	}

	assertComps := func(t *testing.T, comps []model.Component, via string) {
		t.Helper()
		if len(comps) != 2 {
			t.Errorf("%s returned %d rows, want 2", via, len(comps))
			return
		}
		for i := range comps {
			switch comps[i].ID {
			case nullCompID:
				c := &comps[i]
				if c.Version != "" || c.Type != "" || c.Purl != "" || c.License != "" {
					t.Errorf("%s(null): version=%q type=%q purl=%q license=%q, want all \"\"",
						via, c.Version, c.Type, c.Purl, c.License)
				}
				if c.CreatedAt.IsZero() {
					t.Errorf("%s(null): CreatedAt is zero; COALESCE(created_at, NOW()) should yield a real timestamp", via)
				}
			case popCompID:
				c := &comps[i]
				if c.Version != "1.2.3" || c.Type != "library" ||
					c.Purl != "pkg:npm/m46w2-comp-pop@1.2.3" || c.License != "MIT" {
					t.Errorf("%s(pop): round-trip mismatch: version=%q type=%q purl=%q license=%q",
						via, c.Version, c.Type, c.Purl, c.License)
				}
				if !c.CreatedAt.UTC().Equal(popCompCreatedAt) {
					t.Errorf("%s(pop): CreatedAt = %v, want %v", via, c.CreatedAt, popCompCreatedAt)
				}
			default:
				t.Errorf("%s returned unexpected component %s", via, comps[i].ID)
			}
		}
	}

	readAsTenantTx(t, appDB, tenant, func(txCtx context.Context) {
		comps, err := repo.GetComponentsForEOLCheck(txCtx, projectID, 10)
		if err != nil {
			t.Errorf("GetComponentsForEOLCheck with NULL columns must not fail, got: %v", err)
		} else {
			assertComps(t, comps, "GetComponentsForEOLCheck")
		}
		withEOL, totalComps, err := repo.GetComponentsWithEOL(txCtx, projectID, "", 10, 0)
		if err != nil {
			t.Errorf("GetComponentsWithEOL with NULL columns must not fail, got: %v", err)
		} else {
			if totalComps != 2 {
				t.Errorf("GetComponentsWithEOL total = %d, want 2", totalComps)
			}
			assertComps(t, withEOL, "GetComponentsWithEOL")
		}
	})
}

func TestIPAReads_M46W2_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "m46w2-ipa")

	nullID := uuid.New()
	popID := uuid.New()
	registerCleanupExec(t, migDB, "m46w2 ipa_announcements",
		`DELETE FROM ipa_announcements WHERE id IN ($1, $2)`, nullID, popID)

	nullIPAID := "M46W2-IPA-NULL-" + tenant.String()[:8]
	popIPAID := "M46W2-IPA-POP-" + tenant.String()[:8]
	cveMarker := "CVE-M46W2-IPA-" + tenant.String()[:8]

	// published_at is far-future (2099) so ListAnnouncements' first
	// published_at DESC page and GetRecentAnnouncements' after-filter
	// deterministically include both rows even on a synced dev DB.
	nullPublished := time.Date(2099, 1, 2, 0, 0, 0, 0, time.UTC)
	popPublished := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := migDB.Exec(`
		INSERT INTO ipa_announcements (id, ipa_id, title, title_ja, description, category, severity, source_url, related_cves, published_at)
		VALUES ($1, $2, 'm46w2 null announcement', NULL, NULL, NULL, NULL, 'https://example.test/ipa-null', $3, $4)
	`, nullID, nullIPAID, pq.Array([]string{cveMarker}), nullPublished); err != nil {
		t.Fatalf("seed NULL ipa_announcements row: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO ipa_announcements (id, ipa_id, title, title_ja, description, category, severity, source_url, related_cves, published_at)
		VALUES ($1, $2, 'm46w2 pop announcement', 'ポップ告知', 'pop description', 'security_alert', 'HIGH', 'https://example.test/ipa-pop', $3, $4)
	`, popID, popIPAID, pq.Array([]string{cveMarker}), popPublished); err != nil {
		t.Fatalf("seed populated ipa_announcements row: %v", err)
	}

	repo := NewIPARepository(appDB)
	ctx := context.Background()

	assertNullAnn := func(t *testing.T, a *model.IPAAnnouncement, via string) {
		t.Helper()
		if a.TitleJa != "" || a.Description != "" || a.Category != "" || a.Severity != "" {
			t.Errorf("%s: title_ja=%q description=%q category=%q severity=%q, want all \"\" for NULL",
				via, a.TitleJa, a.Description, a.Category, a.Severity)
		}
		if a.Title != "m46w2 null announcement" || a.SourceURL != "https://example.test/ipa-null" {
			t.Errorf("%s: title=%q source_url=%q round-trip mismatch", via, a.Title, a.SourceURL)
		}
	}
	assertPopAnn := func(t *testing.T, a *model.IPAAnnouncement, via string) {
		t.Helper()
		if a.Title != "m46w2 pop announcement" || a.TitleJa != "ポップ告知" ||
			a.Description != "pop description" || a.Category != "security_alert" || a.Severity != "HIGH" ||
			a.SourceURL != "https://example.test/ipa-pop" {
			t.Errorf("%s: round-trip mismatch: title=%q title_ja=%q description=%q category=%q severity=%q source_url=%q",
				via, a.Title, a.TitleJa, a.Description, a.Category, a.Severity, a.SourceURL)
		}
		if len(a.RelatedCVEs) != 1 || a.RelatedCVEs[0] != cveMarker {
			t.Errorf("%s: related_cves = %v, want [%s]", via, a.RelatedCVEs, cveMarker)
		}
		if !a.PublishedAt.UTC().Equal(popPublished) {
			t.Errorf("%s: published_at = %v, want %v", via, a.PublishedAt, popPublished)
		}
	}

	// --- GetAnnouncementByIPAID on both shapes.
	na, err := repo.GetAnnouncementByIPAID(ctx, nullIPAID)
	if err != nil {
		t.Errorf("GetAnnouncementByIPAID on a NULL-column row must not fail, got: %v", err)
	} else if na == nil {
		t.Errorf("GetAnnouncementByIPAID(null) returned nil for seeded row")
	} else {
		assertNullAnn(t, na, "GetAnnouncementByIPAID(null)")
	}
	pa, err := repo.GetAnnouncementByIPAID(ctx, popIPAID)
	if err != nil {
		t.Errorf("GetAnnouncementByIPAID (populated row): %v", err)
	} else if pa == nil {
		t.Errorf("GetAnnouncementByIPAID(pop) returned nil for seeded row")
	} else {
		assertPopAnn(t, pa, "GetAnnouncementByIPAID(pop)")
	}

	// --- ListAnnouncements: first page is published_at DESC, the 2099
	// seeds lead it; one poisoned row used to abort the whole page.
	anns, total, err := repo.ListAnnouncements(ctx, "", 5, 0)
	if err != nil {
		t.Errorf("ListAnnouncements with a NULL-column row must not fail, got: %v", err)
	} else {
		if total < 2 {
			t.Errorf("ListAnnouncements total = %d, want >= 2", total)
		}
		var sawNull, sawPop bool
		for i := range anns {
			switch anns[i].ID {
			case nullID:
				sawNull = true
				assertNullAnn(t, &anns[i], "ListAnnouncements(null)")
			case popID:
				sawPop = true
				assertPopAnn(t, &anns[i], "ListAnnouncements(pop)")
			}
		}
		if !sawNull || !sawPop {
			t.Errorf("ListAnnouncements first page missing seeded rows (null=%v pop=%v)", sawNull, sawPop)
		}
	}

	// --- GetAnnouncementsByCVE: exactly the two seeded rows, newest first.
	byCVE, err := repo.GetAnnouncementsByCVE(ctx, cveMarker)
	if err != nil {
		t.Errorf("GetAnnouncementsByCVE with a NULL-column row must not fail, got: %v", err)
	} else if len(byCVE) != 2 {
		t.Errorf("GetAnnouncementsByCVE returned %d rows, want 2", len(byCVE))
	} else {
		if byCVE[0].ID != nullID || byCVE[1].ID != popID {
			t.Errorf("GetAnnouncementsByCVE order = [%s, %s], want [null %s, pop %s] (published_at DESC)",
				byCVE[0].ID, byCVE[1].ID, nullID, popID)
		}
		assertNullAnn(t, &byCVE[0], "GetAnnouncementsByCVE(null)")
		assertPopAnn(t, &byCVE[1], "GetAnnouncementsByCVE(pop)")
	}

	// --- GetRecentAnnouncements scoped to the 2099 seeds.
	recent, err := repo.GetRecentAnnouncements(ctx, time.Date(2098, 12, 31, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Errorf("GetRecentAnnouncements with a NULL-column row must not fail, got: %v", err)
	} else if len(recent) != 2 {
		t.Errorf("GetRecentAnnouncements returned %d rows, want 2", len(recent))
	}
}

func TestPublicLinkReads_M46W2_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "m46w2-plink")

	// M46 B-1: migration 058 made is_active / view_count / download_count
	// NOT NULL, so the hostile NULL seeds below need the pre-058 shape for
	// the duration of this test (restored via t.Cleanup).
	relaxPublicLinksNotNull(t, migDB)

	projectID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46w2-plink-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	// public_links has no RLS since migration 030 (plain migrator INSERT
	// works) and CASCADEs off tenants — no explicit reap needed.
	nullLinkID := uuid.New()
	popLinkID := uuid.New()
	tokNull := hex64Token()
	tokPop := hex64Token()

	// NULL link: is_active / view_count / download_count / created_at /
	// updated_at all explicitly NULL (each has a DDL default that must be
	// forced away). allowed_downloads is set so IsDownloadLimitReached
	// exercises the NULL download_count scan.
	if _, err := migDB.Exec(`
		INSERT INTO public_links (id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at)
		VALUES ($1, $2, $3, NULL, $4, 'm46w2-link-null', '2099-01-01T00:00:00Z', NULL,
			3, NULL, NULL, NULL, NULL, NULL)
	`, nullLinkID, tenant, projectID, tokNull); err != nil {
		t.Fatalf("seed NULL public_links row: %v", err)
	}
	// Populated link: distinct value per column. is_active=false doubles
	// as the column-order pin: a regression that flattened it to true
	// (e.g. a stray COALESCE(is_active, true)) would fail loudly here.
	popExpires := time.Date(2099, 2, 2, 0, 0, 0, 0, time.UTC)
	popCreated := time.Date(2026, 7, 1, 1, 2, 3, 0, time.UTC)
	popUpdated := time.Date(2026, 7, 2, 4, 5, 6, 0, time.UTC)
	if _, err := migDB.Exec(`
		INSERT INTO public_links (id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at)
		VALUES ($1, $2, $3, NULL, $4, 'm46w2-link-pop', $5, false,
			2, 'hash-pop', 7, 5, $6, $7)
	`, popLinkID, tenant, projectID, tokPop, popExpires, popCreated, popUpdated); err != nil {
		t.Fatalf("seed populated public_links row: %v", err)
	}

	repo := NewPublicLinkRepository(appDB)
	ctx := context.Background()

	assertNullLink := func(t *testing.T, l *model.PublicLink, via string) {
		t.Helper()
		// M46 B-1 High-1: is_active is AUTHORIZATION state — a NULL must
		// read as INACTIVE (fail-closed), never as the DDL default true.
		// The wave-2 revision of this assert pinned the fail-open
		// COALESCE(is_active, true); the expectation is now inverted.
		if l.IsActive {
			t.Errorf("%s: IsActive = true for a NULL is_active row, want fail-closed false (anonymous token holders must not see an active link)", via)
		}
		if l.ViewCount != 0 || l.DownloadCount != 0 {
			t.Errorf("%s: view_count=%d download_count=%d, want DDL default 0 for NULL", via, l.ViewCount, l.DownloadCount)
		}
		if l.CreatedAt.IsZero() || l.UpdatedAt.IsZero() {
			t.Errorf("%s: created_at/updated_at zero; COALESCE(.., NOW()) should yield real timestamps", via)
		}
		if l.PasswordHash != nil {
			t.Errorf("%s: PasswordHash = %v, want nil", via, *l.PasswordHash)
		}
		if l.AllowedDownloads == nil || *l.AllowedDownloads != 3 {
			t.Errorf("%s: AllowedDownloads = %v, want 3", via, l.AllowedDownloads)
		}
	}
	assertPopLink := func(t *testing.T, l *model.PublicLink, via string) {
		t.Helper()
		if l.Name != "m46w2-link-pop" || l.Token != tokPop {
			t.Errorf("%s: name=%q token=%q round-trip mismatch", via, l.Name, l.Token)
		}
		if l.IsActive {
			t.Errorf("%s: IsActive = true, want false (COALESCE must not flatten a real false)", via)
		}
		if l.ViewCount != 7 || l.DownloadCount != 5 {
			t.Errorf("%s: view_count=%d download_count=%d, want 7/5", via, l.ViewCount, l.DownloadCount)
		}
		if l.PasswordHash == nil || *l.PasswordHash != "hash-pop" {
			t.Errorf("%s: PasswordHash = %v, want hash-pop", via, l.PasswordHash)
		}
		if l.AllowedDownloads == nil || *l.AllowedDownloads != 2 {
			t.Errorf("%s: AllowedDownloads = %v, want 2", via, l.AllowedDownloads)
		}
		if !l.ExpiresAt.UTC().Equal(popExpires) || !l.CreatedAt.UTC().Equal(popCreated) || !l.UpdatedAt.UTC().Equal(popUpdated) {
			t.Errorf("%s: timestamps round-trip mismatch: expires=%v created=%v updated=%v",
				via, l.ExpiresAt, l.CreatedAt, l.UpdatedAt)
		}
	}

	// --- ListByProject: one poisoned row used to abort the whole list.
	links, err := repo.ListByProject(ctx, tenant, projectID)
	if err != nil {
		t.Errorf("ListByProject with a NULL-column row must not fail, got: %v", err)
	} else if len(links) != 2 {
		t.Errorf("ListByProject returned %d rows, want 2", len(links))
	} else {
		for i := range links {
			switch links[i].ID {
			case nullLinkID:
				assertNullLink(t, &links[i], "ListByProject(null)")
			case popLinkID:
				assertPopLink(t, &links[i], "ListByProject(pop)")
			}
		}
	}

	// --- GetByID / GetByToken on both shapes.
	if nl, err := repo.GetByID(ctx, tenant, nullLinkID); err != nil {
		t.Errorf("GetByID on a NULL-column row must not fail, got: %v", err)
	} else if nl == nil {
		t.Errorf("GetByID(null) returned nil for seeded row")
	} else {
		assertNullLink(t, nl, "GetByID(null)")
	}
	if pl, err := repo.GetByID(ctx, tenant, popLinkID); err != nil {
		t.Errorf("GetByID (populated row): %v", err)
	} else if pl == nil {
		t.Errorf("GetByID(pop) returned nil for seeded row")
	} else {
		assertPopLink(t, pl, "GetByID(pop)")
	}
	if nl, err := repo.GetByToken(ctx, tokNull); err != nil {
		t.Errorf("GetByToken on a NULL-column row must not fail, got: %v", err)
	} else if nl == nil {
		t.Errorf("GetByToken(null) returned nil for seeded row")
	} else {
		assertNullLink(t, nl, "GetByToken(null)")
	}
	if pl, err := repo.GetByToken(ctx, tokPop); err != nil {
		t.Errorf("GetByToken (populated row): %v", err)
	} else if pl == nil {
		t.Errorf("GetByToken(pop) returned nil for seeded row")
	} else {
		assertPopLink(t, pl, "GetByToken(pop)")
	}

	// --- IsDownloadLimitReached: NULL download_count counts as 0 (not
	// reached with allowed=3); populated 5 >= allowed 2 is reached.
	if reached, err := repo.IsDownloadLimitReached(ctx, tenant, nullLinkID); err != nil {
		t.Errorf("IsDownloadLimitReached on a NULL download_count must not fail, got: %v", err)
	} else if reached {
		t.Errorf("IsDownloadLimitReached(null) = true, want false (NULL counts as 0 < 3)")
	}
	if reached, err := repo.IsDownloadLimitReached(ctx, tenant, popLinkID); err != nil {
		t.Errorf("IsDownloadLimitReached (populated row): %v", err)
	} else if !reached {
		t.Errorf("IsDownloadLimitReached(pop) = false, want true (5 >= 2)")
	}
}

func TestVEXReads_M46W2_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "vex_statements") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "m46w2-vex")

	// Global vulnerabilities rows: explicit reap (tenant CASCADE is SET
	// NULL on vulnerabilities, not delete).
	vulnNullID := uuid.New()
	vulnPopID := uuid.New()
	registerCleanupExec(t, migDB, "m46w2 vex vulnerabilities",
		`DELETE FROM vulnerabilities WHERE id IN ($1, $2)`, vulnNullID, vulnPopID)
	cveNull := "CVE-M46W2-VEXN-" + tenant.String()[:8]
	cvePop := "CVE-M46W2-VEXP-" + tenant.String()[:8]
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at, updated_at)
		VALUES ($1, $2, NULL, NULL, NULL, NULL, NULL, NULL)
	`, vulnNullID, cveNull); err != nil {
		t.Fatalf("seed NULL vulnerability: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at, updated_at)
		VALUES ($1, $2, 'pop vuln', 'HIGH', 7.7, 'NVD', NOW(), NOW())
	`, vulnPopID, cvePop); err != nil {
		t.Fatalf("seed populated vulnerability: %v", err)
	}

	projectID := uuid.New()
	sbomID := uuid.New()
	compPopID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46w2-vex-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO sboms (id, project_id, tenant_id, format) VALUES ($1, $2, $3, 'cyclonedx')
	`, sbomID, projectID, tenant); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO components (id, tenant_id, sbom_id, name, version)
		VALUES ($1, $2, $3, 'm46w2-vex-comp', '2.0.0')
	`, compPopID, tenant, sbomID); err != nil {
		t.Fatalf("seed component: %v", err)
	}

	// vex_statements is FORCE RLS (023) — seed inside the tenant GUC.
	// NULL statement: justification / action_statement / impact_statement
	// all NULL — the legitimate shape for any status other than
	// not_affected (003 leaves them nullable by design).
	stmtNullID := uuid.New()
	stmtPopID := uuid.New()
	nullCreated := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	popCreated := time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)
	popUpdated := time.Date(2099, 1, 3, 6, 7, 8, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO vex_statements (id, tenant_id, project_id, vulnerability_id, component_id,
			status, justification, action_statement, impact_statement, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NULL, 'under_investigation', NULL, NULL, NULL, 'itest-null', $5, $5)
	`, stmtNullID, tenant, projectID, vulnNullID, nullCreated); err != nil {
		t.Fatalf("seed NULL vex_statement: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO vex_statements (id, tenant_id, project_id, vulnerability_id, component_id,
			status, justification, action_statement, impact_statement, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'not_affected', 'component_not_present', 'action-pop', 'impact-pop', 'itest-pop', $6, $7)
	`, stmtPopID, tenant, projectID, vulnPopID, compPopID, popCreated, popUpdated); err != nil {
		t.Fatalf("seed populated vex_statement: %v", err)
	}

	repo := NewVEXRepository(appDB)

	assertNullStmt := func(t *testing.T, v *model.VEXStatement, via string) {
		t.Helper()
		if v.Justification != "" || v.ActionStatement != "" || v.ImpactStatement != "" {
			t.Errorf("%s: justification=%q action=%q impact=%q, want all \"\" for NULL",
				via, v.Justification, v.ActionStatement, v.ImpactStatement)
		}
		if v.Status != model.VEXStatusUnderInvestigation || v.CreatedBy != "itest-null" {
			t.Errorf("%s: status=%q created_by=%q round-trip mismatch", via, v.Status, v.CreatedBy)
		}
		if v.ComponentID != nil {
			t.Errorf("%s: ComponentID = %v, want nil", via, v.ComponentID)
		}
	}
	assertPopStmt := func(t *testing.T, v *model.VEXStatement, via string) {
		t.Helper()
		if v.Status != model.VEXStatusNotAffected ||
			v.Justification != model.VEXJustificationComponentNotPresent ||
			v.ActionStatement != "action-pop" || v.ImpactStatement != "impact-pop" ||
			v.CreatedBy != "itest-pop" {
			t.Errorf("%s: round-trip mismatch: status=%q justification=%q action=%q impact=%q created_by=%q",
				via, v.Status, v.Justification, v.ActionStatement, v.ImpactStatement, v.CreatedBy)
		}
		if v.ComponentID == nil || *v.ComponentID != compPopID {
			t.Errorf("%s: ComponentID = %v, want %s", via, v.ComponentID, compPopID)
		}
		if !v.CreatedAt.UTC().Equal(popCreated) || !v.UpdatedAt.UTC().Equal(popUpdated) {
			t.Errorf("%s: created_at/updated_at = %v/%v, want %v/%v",
				via, v.CreatedAt, v.UpdatedAt, popCreated, popUpdated)
		}
	}

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		// --- LookupProjectTenantID: the uuid violation's happy path.
		if gotTenant, err := repo.LookupProjectTenantID(ctx, projectID); err != nil {
			t.Errorf("LookupProjectTenantID: %v", err)
		} else if gotTenant != tenant {
			t.Errorf("LookupProjectTenantID = %s, want %s", gotTenant, tenant)
		}

		// --- GetStatementForTenant on both shapes.
		if nv, err := repo.GetStatementForTenant(ctx, tenant, stmtNullID); err != nil {
			t.Errorf("GetStatementForTenant on a NULL-column row must not fail, got: %v", err)
		} else if nv == nil {
			t.Errorf("GetStatementForTenant(null) returned nil for seeded row")
		} else {
			assertNullStmt(t, nv, "GetStatementForTenant(null)")
			if nv.TenantID != tenant {
				t.Errorf("GetStatementForTenant(null): TenantID = %s, want %s", nv.TenantID, tenant)
			}
		}
		if pv, err := repo.GetStatementForTenant(ctx, tenant, stmtPopID); err != nil {
			t.Errorf("GetStatementForTenant (populated row): %v", err)
		} else if pv == nil {
			t.Errorf("GetStatementForTenant(pop) returned nil for seeded row")
		} else {
			assertPopStmt(t, pv, "GetStatementForTenant(pop)")
		}

		// --- GetByID on both shapes.
		if nv, err := repo.GetByID(ctx, stmtNullID); err != nil {
			t.Errorf("GetByID on a NULL-column row must not fail, got: %v", err)
		} else if nv == nil {
			t.Errorf("GetByID(null) returned nil for seeded row")
		} else {
			assertNullStmt(t, nv, "GetByID(null)")
		}
		if pv, err := repo.GetByID(ctx, stmtPopID); err != nil {
			t.Errorf("GetByID (populated row): %v", err)
		} else if pv == nil {
			t.Errorf("GetByID(pop) returned nil for seeded row")
		} else {
			assertPopStmt(t, pv, "GetByID(pop)")
		}

		// --- ListByProject: joins vulnerabilities (NULL severity row) and
		// LEFT JOINs components. Order is updated_at DESC → pop first.
		stmts, err := repo.ListByProject(ctx, projectID)
		if err != nil {
			t.Errorf("ListByProject with NULL columns must not fail, got: %v", err)
		} else if len(stmts) != 2 {
			t.Errorf("ListByProject returned %d rows, want 2", len(stmts))
		} else {
			if stmts[0].ID != stmtPopID || stmts[1].ID != stmtNullID {
				t.Errorf("ListByProject order = [%s, %s], want [pop %s, null %s] (updated_at DESC)",
					stmts[0].ID, stmts[1].ID, stmtPopID, stmtNullID)
			}
			pop, null := &stmts[0], &stmts[1]
			assertPopStmt(t, &pop.VEXStatement, "ListByProject(pop)")
			assertNullStmt(t, &null.VEXStatement, "ListByProject(null)")
			if null.VulnerabilityCVEID != cveNull || null.VulnerabilitySeverity != "" {
				t.Errorf("ListByProject(null): cve=%q severity=%q, want %q/\"\" (NULL severity)",
					null.VulnerabilityCVEID, null.VulnerabilitySeverity, cveNull)
			}
			if pop.VulnerabilityCVEID != cvePop || pop.VulnerabilitySeverity != "HIGH" {
				t.Errorf("ListByProject(pop): cve=%q severity=%q, want %q/HIGH",
					pop.VulnerabilityCVEID, pop.VulnerabilitySeverity, cvePop)
			}
			if null.ComponentName != nil || null.ComponentVersion != nil {
				t.Errorf("ListByProject(null): component name/version = %v/%v, want nil/nil",
					null.ComponentName, null.ComponentVersion)
			}
			if pop.ComponentName == nil || *pop.ComponentName != "m46w2-vex-comp" ||
				pop.ComponentVersion == nil || *pop.ComponentVersion != "2.0.0" {
				t.Errorf("ListByProject(pop): component name/version = %v/%v, want m46w2-vex-comp/2.0.0",
					pop.ComponentName, pop.ComponentVersion)
			}
		}

		// --- ListByVulnerability on the NULL statement's vulnerability.
		if byVuln, err := repo.ListByVulnerability(ctx, vulnNullID); err != nil {
			t.Errorf("ListByVulnerability with a NULL-column row must not fail, got: %v", err)
		} else if len(byVuln) != 1 || byVuln[0].ID != stmtNullID {
			t.Errorf("ListByVulnerability returned %d rows (want exactly the NULL statement)", len(byVuln))
		} else {
			assertNullStmt(t, &byVuln[0], "ListByVulnerability(null)")
		}

		// --- GetByProjectAndVulnerability: NULL component variant and
		// component-scoped variant.
		if nv, err := repo.GetByProjectAndVulnerability(ctx, projectID, vulnNullID, nil); err != nil {
			t.Errorf("GetByProjectAndVulnerability on a NULL-column row must not fail, got: %v", err)
		} else if nv == nil {
			t.Errorf("GetByProjectAndVulnerability(null) returned nil for seeded row")
		} else {
			assertNullStmt(t, nv, "GetByProjectAndVulnerability(null)")
		}
		if pv, err := repo.GetByProjectAndVulnerability(ctx, projectID, vulnPopID, &compPopID); err != nil {
			t.Errorf("GetByProjectAndVulnerability (populated row): %v", err)
		} else if pv == nil {
			t.Errorf("GetByProjectAndVulnerability(pop) returned nil for seeded row")
		} else {
			assertPopStmt(t, pv, "GetByProjectAndVulnerability(pop)")
		}
	})
}

func TestSSVCReads_M46W2_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "ssvc_assessments") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "m46w2-ssvc")

	vulnNullID := uuid.New()
	vulnPopID := uuid.New()
	registerCleanupExec(t, migDB, "m46w2 ssvc vulnerabilities",
		`DELETE FROM vulnerabilities WHERE id IN ($1, $2)`, vulnNullID, vulnPopID)
	cveNull := "CVE-M46W2-SSVN-" + tenant.String()[:8]
	cvePop := "CVE-M46W2-SSVP-" + tenant.String()[:8]
	// NULL vulnerability: severity + cvss_score NULL — the NVD "Awaiting
	// Analysis" shape the wave-1 fix measured 106 live rows of.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at, updated_at, in_kev, epss_score)
		VALUES ($1, $2, NULL, NULL, NULL, NULL, NULL, NULL, false, NULL)
	`, vulnNullID, cveNull); err != nil {
		t.Fatalf("seed NULL vulnerability: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at, updated_at, in_kev, epss_score)
		VALUES ($1, $2, 'pop vuln', 'CRITICAL', 9.1, 'NVD', NOW(), NOW(), true, 0.5)
	`, vulnPopID, cvePop); err != nil {
		t.Fatalf("seed populated vulnerability: %v", err)
	}

	projectID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46w2-ssvc-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	// ssvc_assessments is RLS'd (021) — seed inside the tenant GUC.
	// NULL assessment: notes NULL — the shape 14/14 dev-DB rows have.
	assessNullID := uuid.New()
	assessPopID := uuid.New()
	nullAssessedAt := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	popAssessedAt := time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)
	popCreatedAt := time.Date(2026, 7, 3, 1, 1, 1, 0, time.UTC)
	popUpdatedAt := time.Date(2026, 7, 4, 2, 2, 2, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO ssvc_assessments (id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact, mission_prevalence, safety_impact,
			decision, exploitation_auto, automatable_auto, assessed_by, assessed_at, notes)
		VALUES ($1, $2, $3, $4, $5, 'none', 'no', 'partial', 'minimal', 'minimal',
			'immediate', false, true, NULL, $6, NULL)
	`, assessNullID, projectID, tenant, vulnNullID, cveNull, nullAssessedAt); err != nil {
		t.Fatalf("seed NULL ssvc_assessment: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO ssvc_assessments (id, project_id, tenant_id, vulnerability_id, cve_id,
			exploitation, automatable, technical_impact, mission_prevalence, safety_impact,
			decision, exploitation_auto, automatable_auto, assessed_by, assessed_at, notes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'active', 'yes', 'total', 'essential', 'significant',
			'immediate', true, false, NULL, $6, 'notes-pop', $7, $8)
	`, assessPopID, projectID, tenant, vulnPopID, cvePop, popAssessedAt, popCreatedAt, popUpdatedAt); err != nil {
		t.Fatalf("seed populated ssvc_assessment: %v", err)
	}

	// History rows hang off the populated assessment (RLS policy derives
	// tenancy from the parent via EXISTS — migration 043).
	histNullID := uuid.New()
	histPopID := uuid.New()
	histNullChangedAt := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	histPopChangedAt := time.Date(2099, 1, 2, 0, 0, 0, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO ssvc_assessment_history (id, assessment_id,
			prev_exploitation, prev_automatable, prev_technical_impact,
			prev_mission_prevalence, prev_safety_impact, prev_decision,
			new_exploitation, new_automatable, new_technical_impact,
			new_mission_prevalence, new_safety_impact, new_decision,
			changed_by, changed_at, change_reason)
		VALUES ($1, $2, NULL, NULL, NULL, NULL, NULL, NULL,
			'none', 'no', 'partial', 'minimal', 'minimal', 'defer',
			NULL, $3, NULL)
	`, histNullID, assessPopID, histNullChangedAt); err != nil {
		t.Fatalf("seed NULL ssvc_assessment_history: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO ssvc_assessment_history (id, assessment_id,
			prev_exploitation, prev_automatable, prev_technical_impact,
			prev_mission_prevalence, prev_safety_impact, prev_decision,
			new_exploitation, new_automatable, new_technical_impact,
			new_mission_prevalence, new_safety_impact, new_decision,
			changed_by, changed_at, change_reason)
		VALUES ($1, $2, 'none', 'no', 'partial', 'minimal', 'minimal', 'defer',
			'active', 'yes', 'total', 'essential', 'significant', 'immediate',
			NULL, $3, 'because reasons')
	`, histPopID, assessPopID, histPopChangedAt); err != nil {
		t.Fatalf("seed populated ssvc_assessment_history: %v", err)
	}

	repo := NewSSVCRepository(appDB)

	assertNullAssessment := func(t *testing.T, a *model.SSVCAssessment, via string) {
		t.Helper()
		if a.Notes != "" {
			t.Errorf("%s: Notes = %q, want \"\" for NULL", via, a.Notes)
		}
		if a.Exploitation != model.SSVCExploitationNone || a.Automatable != model.SSVCAutomatableNo ||
			a.TechnicalImpact != model.SSVCTechnicalImpactPartial ||
			a.MissionPrevalence != model.SSVCMissionPrevalenceMinimal ||
			a.SafetyImpact != model.SSVCSafetyImpactMinimal ||
			a.Decision != model.SSVCDecisionImmediate {
			t.Errorf("%s: enum round-trip mismatch: %+v", via, a)
		}
		if a.ExploitationAuto || !a.AutomatableAuto {
			t.Errorf("%s: exploitation_auto=%v automatable_auto=%v, want false/true (column-order pin)",
				via, a.ExploitationAuto, a.AutomatableAuto)
		}
		if a.AssessedBy != nil {
			t.Errorf("%s: AssessedBy = %v, want nil", via, a.AssessedBy)
		}
	}
	assertPopAssessment := func(t *testing.T, a *model.SSVCAssessment, via string) {
		t.Helper()
		if a.Notes != "notes-pop" {
			t.Errorf("%s: Notes = %q, want notes-pop", via, a.Notes)
		}
		if a.Exploitation != model.SSVCExploitationActive || a.Automatable != model.SSVCAutomatableYes ||
			a.TechnicalImpact != model.SSVCTechnicalImpactTotal ||
			a.MissionPrevalence != model.SSVCMissionPrevalenceEssential ||
			a.SafetyImpact != model.SSVCSafetyImpactSignificant ||
			a.Decision != model.SSVCDecisionImmediate {
			t.Errorf("%s: enum round-trip mismatch: %+v", via, a)
		}
		if !a.ExploitationAuto || a.AutomatableAuto {
			t.Errorf("%s: exploitation_auto=%v automatable_auto=%v, want true/false (column-order pin)",
				via, a.ExploitationAuto, a.AutomatableAuto)
		}
		if !a.AssessedAt.UTC().Equal(popAssessedAt) ||
			!a.CreatedAt.UTC().Equal(popCreatedAt) || !a.UpdatedAt.UTC().Equal(popUpdatedAt) {
			t.Errorf("%s: timestamps round-trip mismatch: assessed=%v created=%v updated=%v",
				via, a.AssessedAt, a.CreatedAt, a.UpdatedAt)
		}
		if a.CVEID != cvePop {
			t.Errorf("%s: CVEID = %q, want %q", via, a.CVEID, cvePop)
		}
	}
	assertVulnJoin := func(t *testing.T, a *model.SSVCAssessmentWithVuln, via string) {
		t.Helper()
		switch a.ID {
		case assessNullID:
			if a.VulnerabilitySeverity != "" {
				t.Errorf("%s(null): severity = %q, want \"\" for NULL", via, a.VulnerabilitySeverity)
			}
			if a.VulnerabilityCVSSScore != nil {
				t.Errorf("%s(null): CVSSScore = %v, want nil for NULL (un-scored is NOT 0.0)",
					via, *a.VulnerabilityCVSSScore)
			}
			if a.VulnerabilityInKEV {
				t.Errorf("%s(null): InKEV = true, want false", via)
			}
			if a.VulnerabilityEPSSScore != nil {
				t.Errorf("%s(null): EPSSScore = %v, want nil", via, *a.VulnerabilityEPSSScore)
			}
		case assessPopID:
			if a.VulnerabilitySeverity != "CRITICAL" {
				t.Errorf("%s(pop): severity = %q, want CRITICAL", via, a.VulnerabilitySeverity)
			}
			if a.VulnerabilityCVSSScore == nil || *a.VulnerabilityCVSSScore != 9.1 {
				t.Errorf("%s(pop): CVSSScore = %v, want 9.1", via, a.VulnerabilityCVSSScore)
			}
			if !a.VulnerabilityInKEV {
				t.Errorf("%s(pop): InKEV = false, want true", via)
			}
			if a.VulnerabilityEPSSScore == nil || *a.VulnerabilityEPSSScore != 0.5 {
				t.Errorf("%s(pop): EPSSScore = %v, want 0.5", via, a.VulnerabilityEPSSScore)
			}
		}
	}

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		// --- GetAssessment on the NULL-notes row: the measured live
		// failure shape (dev DB: 14/14 assessments carry NULL notes).
		if na, err := repo.GetAssessment(ctx, projectID, vulnNullID); err != nil {
			t.Errorf("GetAssessment on a NULL-notes row must not fail, got: %v", err)
		} else if na == nil {
			t.Errorf("GetAssessment(null) returned nil for seeded row")
		} else {
			assertNullAssessment(t, na, "GetAssessment(null)")
		}
		if pa, err := repo.GetAssessment(ctx, projectID, vulnPopID); err != nil {
			t.Errorf("GetAssessment (populated row): %v", err)
		} else if pa == nil {
			t.Errorf("GetAssessment(pop) returned nil for seeded row")
		} else {
			assertPopAssessment(t, pa, "GetAssessment(pop)")
		}

		// --- GetAssessmentByCVE on both shapes.
		if na, err := repo.GetAssessmentByCVE(ctx, projectID, cveNull); err != nil {
			t.Errorf("GetAssessmentByCVE on a NULL-notes row must not fail, got: %v", err)
		} else if na == nil {
			t.Errorf("GetAssessmentByCVE(null) returned nil for seeded row")
		} else {
			assertNullAssessment(t, na, "GetAssessmentByCVE(null)")
		}
		if pa, err := repo.GetAssessmentByCVE(ctx, projectID, cvePop); err != nil {
			t.Errorf("GetAssessmentByCVE (populated row): %v", err)
		} else if pa == nil {
			t.Errorf("GetAssessmentByCVE(pop) returned nil for seeded row")
		} else {
			assertPopAssessment(t, pa, "GetAssessmentByCVE(pop)")
		}

		// --- ListAssessments: vulnerabilities join with NULL severity /
		// cvss_score. Both decisions are 'immediate' → assessed_at DESC →
		// pop first.
		assessments, total, err := repo.ListAssessments(ctx, projectID, nil, 10, 0)
		if err != nil {
			t.Errorf("ListAssessments with NULL columns must not fail, got: %v", err)
		} else {
			if total != 2 {
				t.Errorf("ListAssessments total = %d, want 2", total)
			}
			if len(assessments) != 2 {
				t.Errorf("ListAssessments returned %d rows, want 2", len(assessments))
			} else {
				if assessments[0].ID != assessPopID || assessments[1].ID != assessNullID {
					t.Errorf("ListAssessments order = [%s, %s], want [pop %s, null %s] (assessed_at DESC)",
						assessments[0].ID, assessments[1].ID, assessPopID, assessNullID)
				}
				assertPopAssessment(t, &assessments[0].SSVCAssessment, "ListAssessments(pop)")
				assertNullAssessment(t, &assessments[1].SSVCAssessment, "ListAssessments(null)")
				assertVulnJoin(t, &assessments[0], "ListAssessments")
				assertVulnJoin(t, &assessments[1], "ListAssessments")
			}
		}

		// --- GetImmediateAssessments (RLS scopes it to this tenant's
		// seeds inside the tx).
		immediate, err := repo.GetImmediateAssessments(ctx)
		if err != nil {
			t.Errorf("GetImmediateAssessments with NULL columns must not fail, got: %v", err)
		} else if len(immediate) != 2 {
			t.Errorf("GetImmediateAssessments returned %d rows, want 2", len(immediate))
		} else {
			if immediate[0].ID != assessPopID || immediate[1].ID != assessNullID {
				t.Errorf("GetImmediateAssessments order = [%s, %s], want [pop %s, null %s]",
					immediate[0].ID, immediate[1].ID, assessPopID, assessNullID)
			}
			assertVulnJoin(t, &immediate[0], "GetImmediateAssessments")
			assertVulnJoin(t, &immediate[1], "GetImmediateAssessments")
		}

		// --- GetAssessmentHistory: change_reason NULL + populated,
		// changed_at DESC → pop first. Prev pointers stay nil on the NULL
		// row and round-trip on the populated one.
		history, err := repo.GetAssessmentHistory(ctx, assessPopID)
		if err != nil {
			t.Errorf("GetAssessmentHistory with a NULL change_reason must not fail, got: %v", err)
		} else if len(history) != 2 {
			t.Errorf("GetAssessmentHistory returned %d rows, want 2", len(history))
		} else {
			if history[0].ID != histPopID || history[1].ID != histNullID {
				t.Errorf("GetAssessmentHistory order = [%s, %s], want [pop %s, null %s] (changed_at DESC)",
					history[0].ID, history[1].ID, histPopID, histNullID)
			}
			h0, h1 := &history[0], &history[1]
			if h0.ChangeReason != "because reasons" {
				t.Errorf("GetAssessmentHistory(pop): ChangeReason = %q, want %q", h0.ChangeReason, "because reasons")
			}
			if h0.PrevExploitation == nil || *h0.PrevExploitation != model.SSVCExploitationNone ||
				h0.PrevDecision == nil || *h0.PrevDecision != model.SSVCDecisionDefer {
				t.Errorf("GetAssessmentHistory(pop): prev fields round-trip mismatch: %+v", h0)
			}
			if h0.NewExploitation != model.SSVCExploitationActive || h0.NewAutomatable != model.SSVCAutomatableYes ||
				h0.NewTechnicalImpact != model.SSVCTechnicalImpactTotal ||
				h0.NewMissionPrevalence != model.SSVCMissionPrevalenceEssential ||
				h0.NewSafetyImpact != model.SSVCSafetyImpactSignificant ||
				h0.NewDecision != model.SSVCDecisionImmediate {
				t.Errorf("GetAssessmentHistory(pop): new fields round-trip mismatch: %+v", h0)
			}
			if h1.ChangeReason != "" {
				t.Errorf("GetAssessmentHistory(null): ChangeReason = %q, want \"\" for NULL", h1.ChangeReason)
			}
			if h1.PrevExploitation != nil || h1.PrevAutomatable != nil || h1.PrevTechnicalImpact != nil ||
				h1.PrevMissionPrevalence != nil || h1.PrevSafetyImpact != nil || h1.PrevDecision != nil {
				t.Errorf("GetAssessmentHistory(null): prev pointers should stay nil for NULL")
			}
		}
	})
}

// hex64Token builds a 64-hex-char token (the public_links token width)
// from two random uuids.
func hex64Token() string {
	a := uuid.New().String()
	b := uuid.New().String()
	strip := func(s string) string {
		out := make([]byte, 0, 32)
		for i := 0; i < len(s); i++ {
			if s[i] != '-' {
				out = append(out, s[i])
			}
		}
		return string(out)
	}
	return strip(a) + strip(b)
}

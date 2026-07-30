//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestM50_GetComponentsWithEOL_PopulatesTheEOLBlock pins that
// EOLRepository.GetComponentsWithEOL actually RETURNS the eol_* values its
// query selects.
//
// The defect this replaces: all five columns were scanned into local
// sql.NullString variables and then dropped on the floor, under the comment
// "Store EOL fields in component (handled by extended model if needed)".
// model.Component has carried EOLStatus / EOLProductID / EOLCycleID / EOLDate /
// EOSDate the whole time, so the comment was false and every caller received a
// zero-valued EOL block from a query that both SELECTs those columns and
// ORDERs BY eol_status.
//
// Nothing shipped wrong, because the method had no production caller — which is
// exactly why it needed pinning. This repository's recurring failure shape is
// dead code springing to life: wiring this up later would have produced a UI
// showing every component as "not assessed" while the database held the
// assessment, with no error anywhere to notice.
//
// Both shapes are asserted in one call, so the test also covers the NULL side:
// "no EOL data on record" must stay distinguishable from a real assessment, not
// collapse to a zero date or a zero UUID.
func TestM50_GetComponentsWithEOL_PopulatesTheEOLBlock(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	// eol_products / eol_product_cycles are GLOBAL (no tenant CASCADE) — reap
	// explicitly, registered before the INSERT so a later t.Fatal cannot strand
	// them (C27).
	//
	// ORDER MATTERS, and it is the opposite of the reading order: t.Cleanup runs
	// LIFO, and components.eol_product_id has an FK to eol_products, so the
	// components have to go first. Registering this BEFORE seedIntegrationTenant
	// (which registers the tenant delete that CASCADEs the components) makes the
	// tenant delete run first. Registering it after fails cleanup with
	// `violates foreign key constraint "components_eol_product_id_fkey"` —
	// observed while writing this test, which is why the ordering is spelled out
	// rather than left to the next author to rediscover.
	prodID := uuid.New()
	cycleID := uuid.New()
	registerCleanupExec(t, migDB, "m50 eol_products",
		`DELETE FROM eol_products WHERE id = $1`, prodID)

	tenant := seedIntegrationTenant(t, migDB, "m50-eol-fields")

	prodName := "m50-eol-fields-" + prodID.String()
	if _, err := migDB.Exec(`
		INSERT INTO eol_products (id, name, title, category, link, total_cycles)
		VALUES ($1, $2, 'm50 eol fields product', 'os', NULL, 1)
	`, prodID, prodName); err != nil {
		t.Fatalf("seed eol_products row: %v", err)
	}
	// Deleting the product CASCADEs the cycle.
	if _, err := migDB.Exec(`
		INSERT INTO eol_product_cycles (id, product_id, cycle)
		VALUES ($1, $2, '3.1')
	`, cycleID, prodID); err != nil {
		t.Fatalf("seed eol_product_cycles row: %v", err)
	}

	projectID := uuid.New()
	sbomID := uuid.New()
	// projects / sboms / components are FORCE RLS — even the migrator role is
	// subject to the policy, so these INSERTs must carry the tenant GUC
	// (execAsTenant), unlike the global eol_* tables above.
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm50-eol-fields-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO sboms (id, project_id, tenant_id, format) VALUES ($1, $2, $3, 'cyclonedx')
	`, sbomID, projectID, tenant); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}

	// Assessed component: every eol_* column carries a distinct value so a
	// mis-ordered Scan cannot pass by coincidence.
	assessedID := uuid.New()
	wantEOL := time.Date(2028, 4, 5, 0, 0, 0, 0, time.UTC)
	wantEOS := time.Date(2029, 6, 7, 0, 0, 0, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license,
			eol_status, eol_product_id, eol_cycle_id, eol_date, eos_date)
		VALUES ($1, $2, $3, 'm50-eol-assessed', '3.1', 'library',
			'pkg:generic/m50-eol-assessed@3.1', 'Apache-2.0',
			'eol', $4, $5, $6, $7)
	`, assessedID, tenant, sbomID, prodID, cycleID, wantEOL, wantEOS); err != nil {
		t.Fatalf("seed assessed component: %v", err)
	}

	// Unassessed component: all five NULL.
	unassessedID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license,
			eol_status, eol_product_id, eol_cycle_id, eol_date, eos_date)
		VALUES ($1, $2, $3, 'm50-eol-unassessed', '0.1', 'library',
			'pkg:generic/m50-eol-unassessed@0.1', 'MIT',
			NULL, NULL, NULL, NULL, NULL)
	`, unassessedID, tenant, sbomID); err != nil {
		t.Fatalf("seed unassessed component: %v", err)
	}

	repo := NewEOLRepository(appDB)

	readAsTenantTx(t, appDB, tenant, func(txCtx context.Context) {
		comps, total, err := repo.GetComponentsWithEOL(txCtx, projectID, "", 10, 0)
		if err != nil {
			t.Fatalf("GetComponentsWithEOL: %v", err)
		}
		if total != 2 {
			t.Errorf("total = %d, want 2", total)
		}

		var sawAssessed, sawUnassessed bool
		for i := range comps {
			c := &comps[i]
			switch c.ID {
			case assessedID:
				sawAssessed = true
				if c.EOLStatus != "eol" {
					t.Errorf("assessed: EOLStatus = %q, want \"eol\" — the query selects "+
						"eol_status and orders by it, so an empty value here means the "+
						"Scan result was discarded", c.EOLStatus)
				}
				if c.EOLProductID == nil || *c.EOLProductID != prodID {
					t.Errorf("assessed: EOLProductID = %v, want %v", c.EOLProductID, prodID)
				}
				if c.EOLCycleID == nil || *c.EOLCycleID != cycleID {
					t.Errorf("assessed: EOLCycleID = %v, want %v", c.EOLCycleID, cycleID)
				}
				if c.EOLDate == nil {
					t.Errorf("assessed: EOLDate = nil, want %v", wantEOL)
				} else if !c.EOLDate.UTC().Equal(wantEOL) {
					t.Errorf("assessed: EOLDate = %v, want %v", c.EOLDate.UTC(), wantEOL)
				}
				if c.EOSDate == nil {
					t.Errorf("assessed: EOSDate = nil, want %v", wantEOS)
				} else if !c.EOSDate.UTC().Equal(wantEOS) {
					t.Errorf("assessed: EOSDate = %v, want %v", c.EOSDate.UTC(), wantEOS)
				}

			case unassessedID:
				sawUnassessed = true
				// "Never assessed" must not become a value. An empty
				// EOLStatus is the intended representation; a zero date or a
				// zero UUID would read as real data downstream.
				if c.EOLStatus != "" {
					t.Errorf("unassessed: EOLStatus = %q, want \"\"", c.EOLStatus)
				}
				if c.EOLProductID != nil || c.EOLCycleID != nil {
					t.Errorf("unassessed: EOLProductID = %v EOLCycleID = %v, want both nil",
						c.EOLProductID, c.EOLCycleID)
				}
				if c.EOLDate != nil || c.EOSDate != nil {
					t.Errorf("unassessed: EOLDate = %v EOSDate = %v, want both nil "+
						"(a zero date would render as a real end-of-life date)",
						c.EOLDate, c.EOSDate)
				}

			default:
				t.Errorf("unexpected component %s", c.ID)
			}
		}
		if !sawAssessed || !sawUnassessed {
			t.Errorf("missing seeded components (assessed=%v unassessed=%v)",
				sawAssessed, sawUnassessed)
		}
	})
}

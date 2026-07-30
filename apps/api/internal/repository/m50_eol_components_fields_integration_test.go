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
// Three components are read in one call: two assessed with DIFFERENT values
// (which is what makes per-row pointer independence observable — see the second
// fixture) and one with all five columns NULL, so "no EOL data on record" is
// shown to stay distinguishable from a real assessment rather than collapsing to
// a zero date or a zero UUID.
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
	// BOTH products are registered here, before the tenant, for the same LIFO
	// reason. Registering the second one later (next to its INSERT, where it
	// reads better) puts it after the tenant cleanup and therefore runs it
	// FIRST — straight back into the same FK violation.
	prodID := uuid.New()
	cycleID := uuid.New()
	prod2ID := uuid.New()
	cycle2ID := uuid.New()
	registerCleanupExec(t, migDB, "m50 eol_products",
		`DELETE FROM eol_products WHERE id IN ($1, $2)`, prodID, prod2ID)

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

	// Second assessed component, with DIFFERENT product / cycle / dates.
	//
	// This row exists to prove per-row pointer independence, which two rows
	// cannot (Codex round 1, #2). With one assessed row and one NULL row, a
	// genuine last-row aliasing bug — backing variables hoisted out of the
	// `for rows.Next()` loop and re-pointed every iteration — would still pass:
	// the NULL row leaves those variables untouched, so the assessed row keeps
	// the right values by accident. Two rows that BOTH carry values, with
	// distinct values, is what makes sharing observable.
	assessed2ID := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO eol_products (id, name, title, category, link, total_cycles)
		VALUES ($1, $2, 'm50 eol fields product 2', 'os', NULL, 1)
	`, prod2ID, "m50-eol-fields-2-"+prod2ID.String()); err != nil {
		t.Fatalf("seed second eol_products row: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO eol_product_cycles (id, product_id, cycle)
		VALUES ($1, $2, '4.2')
	`, cycle2ID, prod2ID); err != nil {
		t.Fatalf("seed second eol_product_cycles row: %v", err)
	}
	wantEOL2 := time.Date(2030, 8, 9, 0, 0, 0, 0, time.UTC)
	wantEOS2 := time.Date(2031, 10, 11, 0, 0, 0, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license,
			eol_status, eol_product_id, eol_cycle_id, eol_date, eos_date)
		VALUES ($1, $2, $3, 'm50-eol-assessed-2', '4.2', 'library',
			'pkg:generic/m50-eol-assessed-2@4.2', 'BSD-3-Clause',
			'eos', $4, $5, $6, $7)
	`, assessed2ID, tenant, sbomID, prod2ID, cycle2ID, wantEOL2, wantEOS2); err != nil {
		t.Fatalf("seed second assessed component: %v", err)
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
		if total != 3 {
			t.Errorf("total = %d, want 3", total)
		}

		var sawAssessed, sawAssessed2, sawUnassessed bool
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

			case assessed2ID:
				sawAssessed2 = true
				// Same assertions, DIFFERENT expected values. If the four
				// pointers were shared across loop iterations, one of these two
				// assessed rows would carry the other's product / cycle / dates
				// and this branch (or the one above) would fail.
				if c.EOLStatus != "eos" {
					t.Errorf("assessed2: EOLStatus = %q, want \"eos\"", c.EOLStatus)
				}
				if c.EOLProductID == nil || *c.EOLProductID != prod2ID {
					t.Errorf("assessed2: EOLProductID = %v, want %v (pointer shared with "+
						"the other assessed row?)", c.EOLProductID, prod2ID)
				}
				if c.EOLCycleID == nil || *c.EOLCycleID != cycle2ID {
					t.Errorf("assessed2: EOLCycleID = %v, want %v (pointer shared with "+
						"the other assessed row?)", c.EOLCycleID, cycle2ID)
				}
				if c.EOLDate == nil {
					t.Errorf("assessed2: EOLDate = nil, want %v", wantEOL2)
				} else if !c.EOLDate.UTC().Equal(wantEOL2) {
					t.Errorf("assessed2: EOLDate = %v, want %v (pointer shared?)",
						c.EOLDate.UTC(), wantEOL2)
				}
				if c.EOSDate == nil {
					t.Errorf("assessed2: EOSDate = nil, want %v", wantEOS2)
				} else if !c.EOSDate.UTC().Equal(wantEOS2) {
					t.Errorf("assessed2: EOSDate = %v, want %v (pointer shared?)",
						c.EOSDate.UTC(), wantEOS2)
				}

			case unassessedID:
				sawUnassessed = true
				// This is a NULL-status row, which is NOT how a
				// never-assessed component normally looks (Codex round 2 #3 —
				// round 1's comment called "" the "intended representation",
				// which overstates it). ComponentRepository.Create omits
				// eol_status and takes the DDL default 'unknown', and
				// MatchComponentToEOL also starts from 'unknown'; the live dev
				// DB had zero NULL and zero empty rows. The row is seeded with
				// explicit NULLs to exercise the nullable scan path.
				//
				// "" here is a CONSEQUENCE of model.Component typing EOLStatus
				// as a plain string, not a designed sentinel — see the scan
				// loop's note on the collision this leaves open. The four
				// pointer fields are the ones that genuinely keep "absent"
				// distinct: a zero date or a zero UUID would read as real data
				// downstream.
				if c.EOLStatus != "" {
					t.Errorf("unassessed: EOLStatus = %q, want \"\" (SQL NULL maps to the "+
						"empty string because the model field is a plain string)", c.EOLStatus)
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
		if !sawAssessed || !sawAssessed2 || !sawUnassessed {
			t.Errorf("missing seeded components (assessed=%v assessed2=%v unassessed=%v)",
				sawAssessed, sawAssessed2, sawUnassessed)
		}
	})
}

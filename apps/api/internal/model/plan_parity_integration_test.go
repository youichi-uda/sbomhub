//go:build integration

// Package model — real-PG integration companion for the F299 parity
// meta-test (M20-2 #116).
//
// Why this file exists (anti-pattern 21 sqlmock semantics limitation
// evolution — M8 教訓 #21 + M17 Recovery R1/R2):
//
//	The unit test TestPlanFeatureRegistryParity_F299 in
//	plan_parity_test.go hand-parses the 008 seed + 049 backfill from
//	disk. That is fast, hermetic, and catches the two silent gaps
//	M20-2 was scoped to close (audit_logs missing from SQL side +
//	priority_support missing from Go side). What it does NOT catch:
//
//	  - JSONB serialisation surprises that only surface when the row
//	    round-trips through PostgreSQL's parser and back through
//	    lib/pq (key-order stability, whitespace normalisation, type
//	    coercion for ambiguous scalars like true vs "true").
//
//	  - Migration ordering / dependency corruption where a later
//	    migration silently overwrites plan_limits.features on some
//	    plan (e.g. a hypothetical 05x migration that upserts new
//	    plan tiers and forgets to preserve existing keys).
//
//	  - RLS or role-permission accidents that would deny the app
//	    role the ability to SELECT features from plan_limits.
//	    plan_limits is structurally exempt from RLS per
//	    migrations/CLAUDE.md (subscriptions/plan_limits family is a
//	    tenant-agnostic global config table), but that exemption is
//	    a promise the code makes — this test smokes it.
//
//	This is the FIRST wave in M20 that introduces a new migration
//	(049), so it is also the only M20 wave where a real-PG smoke is
//	load-bearing (M20-1 and M20-3 are pure Go changes).
//
// Run with:
//
//	cd apps/api && go test -tags=integration \
//	    ./internal/model/... -run RealPG_F299
//
// Prerequisites (skipped otherwise):
//
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to any role that can SELECT from plan_limits.
//     The app role (NOBYPASSRLS) is fine because plan_limits is
//     structurally RLS-exempt.
//   - Schema migrated at least through 049
//     (`go run ./cmd/migrate up`).
//
// What this test file pins down:
//
//  1. Migration 049 was applied: every plan_limits row carries the
//     audit_logs key.
//
//  2. Post-049 per-plan features JSONB matches Go DefaultPlanLimits
//     exactly (same key set, same boolean value on every key).
package model

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// planParityIntEnv returns a DATABASE_URL or skips the test loudly.
func planParityIntEnv(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("plan parity integration test requires DATABASE_URL. " +
			"Run `docker compose up -d postgres`, set DATABASE_URL to " +
			"the sbomhub_app connection string, migrate through 049, " +
			"then re-run with -tags=integration.")
	}
	return url
}

// planParityOpenOrSkip opens the DB or skips on unreachability.
func planParityOpenOrSkip(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open failed (%v) — skipping plan parity integration test", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("DB unreachable (%v) — skipping plan parity integration test", err)
	}
	return db
}

// TestPlanFeatureParity_RealPG_F299 pins the SQL-side plan_limits
// features JSONB against Go DefaultPlanLimits after the 049 backfill
// has been applied. See file header for scope and prerequisites.
func TestPlanFeatureParity_RealPG_F299(t *testing.T) {
	url := planParityIntEnv(t)
	db := planParityOpenOrSkip(t, url)
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Guard: skip if the schema is not migrated far enough.
	var haveTable bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'plan_limits'
		)
	`).Scan(&haveTable); err != nil {
		t.Skipf("plan_limits existence check failed: %v — skipping", err)
	}
	if !haveTable {
		t.Skip("plan_limits table not found — run migrate up through 049 first")
	}

	plans := []string{
		PlanFree,
		PlanStarter,
		PlanPro,
		PlanTeam,
		PlanEnterprise,
	}

	// Fetch every seeded plan's features JSONB in one round-trip.
	rows, err := db.QueryContext(ctx, `
		SELECT plan, features::text
		  FROM plan_limits
		 ORDER BY plan
	`)
	if err != nil {
		t.Fatalf("F299 real-PG: SELECT plan_limits failed: %v", err)
	}
	defer func() { _ = rows.Close() }()

	sqlSide := make(map[string]map[string]bool)
	for rows.Next() {
		var plan, featuresJSON string
		if err := rows.Scan(&plan, &featuresJSON); err != nil {
			t.Fatalf("F299 real-PG: row scan failed: %v", err)
		}
		features := make(map[string]bool)
		if err := json.Unmarshal([]byte(featuresJSON), &features); err != nil {
			t.Errorf("F299 real-PG: plan=%q features JSONB decode failed "+
				"as map[string]bool: %v (raw=%s). If a non-bool value "+
				"was introduced, extend both this test AND HasFeature() "+
				"together — that shape change is out of the current "+
				"parity contract.", plan, err, featuresJSON)
			continue
		}
		sqlSide[plan] = features
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("F299 real-PG: row iteration error: %v", err)
	}

	// Cross-check: every declared plan has a row.
	for _, p := range plans {
		if _, ok := sqlSide[p]; !ok {
			t.Errorf("F299 real-PG: plan_limits row missing for plan=%q "+
				"(migration 008 seed corrupted?)", p)
		}
	}

	// Guard: 049 backfill actually applied.
	for plan, feats := range sqlSide {
		if _, ok := feats["audit_logs"]; !ok {
			t.Errorf("F299 real-PG: plan=%q features JSONB missing "+
				"audit_logs key. Migration 049 "+
				"(plan_features_parity_backfill) did not run — "+
				"re-run `go run ./cmd/migrate up`.", plan)
		}
	}

	// Direction 1 + 2 combined: for every plan, Go side and SQL
	// side must expose the same key set and the same boolean per key.
	for _, plan := range plans {
		limits := DefaultPlanLimits(plan)
		if limits.Features == nil {
			t.Errorf("F299 real-PG: DefaultPlanLimits(%q).Features is nil", plan)
			continue
		}
		goSide := make(map[string]bool, len(limits.Features))
		for k, v := range limits.Features {
			b, ok := v.(bool)
			if !ok {
				t.Errorf("F299 real-PG: Go plan=%q key=%q value is %T not bool",
					plan, k, v)
				continue
			}
			goSide[k] = b
		}

		sqlPlan := sqlSide[plan]
		if sqlPlan == nil {
			continue
		}

		// Go → SQL.
		for k, goVal := range goSide {
			sqlVal, ok := sqlPlan[k]
			if !ok {
				t.Errorf("F299 real-PG direction 1 (Go → SQL): plan=%q "+
					"key=%q present in Go DefaultPlanLimits (=%v) but "+
					"missing from plan_limits.features JSONB in the "+
					"live DB.", plan, k, goVal)
				continue
			}
			if goVal != sqlVal {
				t.Errorf("F299 real-PG direction 2: plan=%q key=%q "+
					"Go=%v but live-DB plan_limits.features=%v",
					plan, k, goVal, sqlVal)
			}
		}
		// SQL → Go.
		for k, sqlVal := range sqlPlan {
			if _, ok := goSide[k]; !ok {
				t.Errorf("F299 real-PG direction 1 (SQL → Go): plan=%q "+
					"key=%q present in live-DB plan_limits.features "+
					"(=%v) but missing from Go DefaultPlanLimits.",
					plan, k, sqlVal)
			}
		}
	}
}

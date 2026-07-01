package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestPlanFeatureRegistryParity_F299 is the first horizontal replication
// of anti-pattern 58 (emit / registry parity in dual-list systems)
// outside the audit dimension (F271 Action / F281 Resource). The
// "dual list" here is:
//
//	(Go side)  model.DefaultPlanLimits(plan).Features — the fallback
//	           used when middleware.CheckFeature() cannot reach the DB
//	           (SubscriptionRepository lookup failure, self-hosted
//	           mode variants, etc.).
//
//	(SQL side) apps/api/migrations/008_subscriptions.up.sql's
//	           plan_limits INSERT seed + 024_fix_plan_limits_audit_logs
//	           (BUG-06 backfill on pro/team/enterprise) + F299
//	           backfill in
//	           apps/api/migrations/049_plan_features_parity_backfill.up.sql
//	           (free/starter audit_logs=false completeness).
//	           Read at runtime by SubscriptionRepository.GetPlanLimits()
//	           and passed straight into HasFeature() — this is the
//	           authoritative production path.
//
// Both sides expose the same feature-key universe to CheckFeature()'s
// caller. If they drift, HasFeature() silently returns different
// answers on the two lookup paths, and any endpoint gated on a key
// that only one side declares will forbid or admit tenants
// depending on internal plumbing accidents rather than plan design.
//
// This test catches two real production silent gaps that were live
// on 2026-07-01 (M20-2 evidence):
//
//   - Gap A "priority_support": present in the SQL seed 008 on
//     pro/team/enterprise, ABSENT from Go DefaultPlanLimits — the
//     fallback path silently answered false for a marketed feature.
//     Fixed on the Go side in this wave (DefaultPlanLimits now
//     declares priority_support on all five plans: free/starter
//     false, pro/team/enterprise true). Fixed on the SQL side by
//     migration 049 adding priority_support=false to free/starter
//     so per-plan key sets match.
//   - Gap B "audit_logs" (production bug residual): initially
//     ABSENT from the SQL seed 008 on every plan while Go
//     DefaultPlanLimits declared audit_logs on all five plans
//     (pro/team/enterprise=true, starter/free=false). Migration
//     024_fix_plan_limits_audit_logs partially closed this in an
//     earlier wave (BUG-06) by UPDATE'ing pro/team/enterprise to
//     audit_logs=true, but intentionally left free/starter unset
//     because a missing key already answered false at runtime.
//     That left the SQL-side key SET incomplete relative to Go:
//     the key was declared on only 3 of 5 SQL rows even though Go
//     declares it on all 5. Migration 049 (this wave) backfills
//     audit_logs=false on free/starter so both sides declare the
//     key on every plan.
//
// Directions (F276 factuality trade-off, same pattern as F271 / F281):
//
//	(1) Direction 1 — key-set union equality: the union of feature
//	    keys across all 5 Go plans must exactly equal the union of
//	    feature keys across all 5 SQL seed rows (post-049). A
//	    documented allowlist would sit next to the diff assertion
//	    with an F# reason if a wave intentionally defers a key on
//	    one side (kept intentionally EMPTY at F299 initial so future
//	    silent divergence trips CI loud).
//
//	(2) Direction 2 — per-plan value equality: for every plan × key
//	    pair, the Go boolean must equal the SQL boolean. Catches
//	    "value flipped on one side only" — e.g. a wave that flips
//	    priority_support to true on the Pro plan in Go but forgets
//	    the matching UPDATE in a new migration.
//
// What THIS test DOES catch:
//
//   - New feature key added to Go DefaultPlanLimits without a
//     matching plan_limits seed / backfill migration (silent
//     Gap A shape).
//   - New feature key added to a plan_limits seed / backfill
//     migration without a matching entry in Go DefaultPlanLimits
//     (silent Gap B shape — the real production audit_logs bug).
//     F317 (M20-2 Phase D R2, Codex adjunct v2 5th continue application):
//     the SQL-side parser scans EVERY `apps/api/migrations/*.up.sql`
//     for `UPDATE plan_limits SET features = features || ...` in
//     lexicographic (migration-number) order, not the previously
//     hardcoded 008 / 024 / 049 triplet, so a future 050+ migration
//     that adds a new plan_limits feature-key backfill is picked up
//     automatically. The pre-F317 hardcode made the meta-test's
//     "future silent divergence trips CI" claim narrower than it read.
//   - Per-plan value flip on only one side (Direction 2).
//   - Registry typos on the SQL side that decode as valid JSON
//     but do not match a Go key.
//
// What THIS test does NOT catch (documented factuality trade-off,
// mirrors the F276 note on F271 / F281):
//
//   - Wire-value stability of the feature-key STRING. Both sides
//     use the same key string; a coordinated rename ("audit_logs"
//     → "auditLog") on both sides in the same PR would pass this
//     test even though it would break the CheckFeature() call in
//     cmd/server/main.go. That call still has the raw string, so a
//     rename would fail at runtime, not at CI time; policing
//     wire-value stability is out of scope for this parity test.
//   - SQL JSONB type stability. The test decodes with
//     encoding/json.Unmarshal into map[string]bool — a seed that
//     emitted "audit_logs": "yes" instead of "audit_logs": true
//     would fail to decode and be surfaced as a parse error, but
//     the test does not enforce a JSON Schema-level shape check.
//   - Migration ordering / rollback correctness. The 049 down
//     migration removes the audit_logs key on every row; this test
//     asserts the union with 049 UP applied, not the reversibility
//     of the down.
//   - RLS policy correctness on plan_limits. plan_limits is a
//     tenant-agnostic global table (structurally exempted per
//     migrations/CLAUDE.md), so this test does not enforce RLS
//     policy on it.
//   - Real-PG semantics. sqlmock-style unit assertions cannot
//     catch cascade bugs the way M8 教訓 #21 + M17 Recovery R1
//     documented; a companion //go:build integration test
//     (TestPlanFeatureParity_RealPG_F299 in
//     plan_parity_integration_test.go) runs the full migration
//     chain against docker-compose postgres and reads back the
//     JSONB via database/sql for the smoke-level parity check.
//
// Adding a new feature key going forward: add the key to every plan
// in model/plan.go DefaultPlanLimits AND in a new migration that
// backfills plan_limits.features with the same key. Add the key to
// no allowlist. Do not silence this test.
func TestPlanFeatureRegistryParity_F299(t *testing.T) {
	// The five plans this product exposes. Both sides seed exactly
	// these; if a new plan is added, add it here and to both sides.
	plans := []string{
		PlanFree,
		PlanStarter,
		PlanPro,
		PlanTeam,
		PlanEnterprise,
	}

	// Go side: read DefaultPlanLimits directly.
	goSide := make(map[string]map[string]bool, len(plans))
	for _, plan := range plans {
		limits := DefaultPlanLimits(plan)
		if limits.Features == nil {
			t.Fatalf("F299 setup: DefaultPlanLimits(%q).Features is nil", plan)
		}
		goSide[plan] = make(map[string]bool, len(limits.Features))
		for k, v := range limits.Features {
			b, ok := v.(bool)
			if !ok {
				t.Errorf("F299 Go side: plan=%q key=%q value is %T not bool",
					plan, k, v)
				continue
			}
			goSide[plan][k] = b
		}
	}

	// SQL side: parse the 008 seed + 049 backfill from disk.
	sqlSide, err := parsePlanFeaturesFromMigrations(t, plans)
	if err != nil {
		t.Fatalf("F299 setup: parse SQL seed / backfill failed: %v", err)
	}

	// -------- Direction 1: key-set union equality --------

	goKeys := unionKeys(goSide)
	sqlKeys := unionKeys(sqlSide)

	// Documented exception allowlist mirroring the F271 / F281
	// pattern. Kept intentionally EMPTY at F299 initial so a future
	// wave that adds a feature key on only one side has a visible
	// deferral slot (with F# reason) rather than silencing the
	// parity contract. See F271 knownEmitNotRegistered head comment
	// for the shrink discipline.
	knownGoOnlyMissingFromSQL := map[string]string{}
	knownSQLOnlyMissingFromGo := map[string]string{}

	for k := range goKeys {
		if _, ok := sqlKeys[k]; ok {
			continue
		}
		if _, ok := knownGoOnlyMissingFromSQL[k]; ok {
			continue
		}
		t.Errorf("F299 direction 1 failure (Go → SQL): feature key %q "+
			"is present in Go DefaultPlanLimits Features but ABSENT "+
			"from every plan_limits.features JSONB row after applying "+
			"008_subscriptions.up.sql INSERT seed + every subsequent "+
			"`UPDATE plan_limits SET features = features || ...` "+
			"backfill migration in apps/api/migrations in numeric order "+
			"(F317 dynamic scan). Either add the matching key to the "+
			"SQL seed / a new backfill migration, or (if the deferral "+
			"is intentional) add it to knownGoOnlyMissingFromSQL with "+
			"an F# reason.", k)
	}

	for k := range sqlKeys {
		if _, ok := goKeys[k]; ok {
			continue
		}
		if _, ok := knownSQLOnlyMissingFromGo[k]; ok {
			continue
		}
		t.Errorf("F299 direction 1 failure (SQL → Go): feature key %q "+
			"is present in plan_limits.features JSONB (008 INSERT seed "+
			"+ all subsequent `UPDATE plan_limits SET features = "+
			"features || ...` backfill migrations discovered by F317 "+
			"dynamic scan) but ABSENT from every Go DefaultPlanLimits "+
			"plan Features map. Either add the matching key to "+
			"model/plan.go DefaultPlanLimits, or (if the deferral is "+
			"intentional) add it to knownSQLOnlyMissingFromGo with an "+
			"F# reason.", k)
	}

	// -------- Direction 2: per-plan key-set + value equality --------
	//
	// For each plan, the Go Features map and the parsed SQL features
	// JSONB must have the exact same set of keys, and every shared
	// key must have the exact same boolean value. This catches the
	// "key present on one side for plan X but not the other" gap
	// that Direction 1's union-based check would silently pass as
	// long as some OTHER plan carries the key on the missing side
	// (real gap shape M20-2 F299 observed on 2026-07-02 during the
	// real-PG smoke: Go was extended to declare priority_support on
	// free/starter as false so the fallback path answered "no" for
	// a paid feature; the SQL seed omits the key on free/starter
	// because the runtime answer is the same false, but the DECLARED
	// key SET differs — Direction 2 catches that).

	for _, plan := range plans {
		goPlan := goSide[plan]
		sqlPlan := sqlSide[plan]
		if sqlPlan == nil {
			t.Errorf("F299 direction 2 failure: SQL side has no plan_limits "+
				"row for plan=%q", plan)
			continue
		}
		// Go → SQL per plan.
		for k, goVal := range goPlan {
			sqlVal, ok := sqlPlan[k]
			if !ok {
				t.Errorf("F299 direction 2 failure (Go → SQL per plan): "+
					"plan=%q key=%q present in Go DefaultPlanLimits "+
					"(=%v) but absent from plan_limits.features JSONB "+
					"for this specific plan. Either add the key to the "+
					"SQL seed / backfill migration for %q, or (if the "+
					"deferral is intentional) add {plan}:{key} to "+
					"knownGoOnlyPerPlanMissingFromSQL with an F# reason.",
					plan, k, goVal, plan)
				continue
			}
			if goVal != sqlVal {
				t.Errorf("F299 direction 2 failure (value mismatch): "+
					"plan=%q key=%q Go DefaultPlanLimits=%v but SQL "+
					"seed/backfill=%v. One side was updated without "+
					"the other.", plan, k, goVal, sqlVal)
			}
		}
		// SQL → Go per plan.
		for k, sqlVal := range sqlPlan {
			if _, ok := goPlan[k]; !ok {
				t.Errorf("F299 direction 2 failure (SQL → Go per plan): "+
					"plan=%q key=%q present in plan_limits.features JSONB "+
					"(=%v) but absent from Go DefaultPlanLimits for this "+
					"specific plan. Either add the key to model/plan.go "+
					"DefaultPlanLimits for %q, or (if the deferral is "+
					"intentional) add {plan}:{key} to "+
					"knownSQLOnlyPerPlanMissingFromGo with an F# reason.",
					plan, k, sqlVal, plan)
			}
		}
	}
}

// parsePlanFeaturesFromMigrations reconstructs the SQL-side
// plan_limits.features state by scanning every migration in
// apps/api/migrations that touches plan_limits.features.
//
// Scan protocol (F317, M20-2 Phase D R2 Codex adjunct v2 5th continue
// application):
//
//   - The 008_subscriptions.up.sql INSERT seed is required and always
//     applied first. It is the origin of every plan_limits row so the
//     later UPDATE backfills have something to merge into.
//   - Every *.up.sql in the directory is then scanned in lexicographic
//     order (which matches migration-number order for the 001-049
//     zero-padded convention this repo uses). Any file whose contents
//     match a `UPDATE plan_limits SET features = features || ... ` shape
//     — either the IN (...) or the `= 'x'` per-plan form — is treated
//     as a backfill and its deltas are folded into the seed. 008 itself
//     is skipped in this pass (it has no matching UPDATE shape).
//   - PostgreSQL `||` right-hand-side wins on key collision, so later
//     migrations override earlier ones as they would in a live upgrade.
//
// Rationale: prior to F317 this parser was hardcoded to the three
// known migrations at the time of writing (008 / 024 / 049). A future
// 050+ migration that added a new plan_limits feature-key backfill
// would have been silently invisible to the unit meta-test, keeping
// the parity gap latent until the //go:build integration companion
// ran against real postgres. The dynamic scan closes that gap so the
// meta-test's "future silent divergence trips CI" claim in the head
// docstring is factually broad.
func parsePlanFeaturesFromMigrations(t *testing.T, plans []string) (map[string]map[string]bool, error) {
	t.Helper()

	migrationsDir := migrationsDirAbs(t)

	// 1) 008 INSERT seed — must exist as the origin of every plan row.
	const seedFile = "008_subscriptions.up.sql"
	seedPath := filepath.Join(migrationsDir, seedFile)
	seed, err := parse008Seed(seedPath)
	if err != nil {
		return nil, err
	}

	// 2) Discover every *.up.sql in numeric (lexicographic) order and
	// fold in any `UPDATE plan_limits SET features = features || ...`
	// backfills. hasPlanLimitsFeaturesUpdate does a cheap grep first so
	// unrelated migrations short-circuit; applyBackfillUpdates then
	// parses and applies the deltas.
	upFiles, err := filepath.Glob(filepath.Join(migrationsDir, "*.up.sql"))
	if err != nil {
		return nil, err
	}
	sort.Strings(upFiles)
	for _, path := range upFiles {
		if filepath.Base(path) == seedFile {
			continue
		}
		hit, err := hasPlanLimitsFeaturesUpdate(path)
		if err != nil {
			return nil, err
		}
		if !hit {
			continue
		}
		if err := applyBackfillUpdates(seed, path); err != nil {
			return nil, err
		}
	}

	// Ensure every declared plan is present.
	for _, p := range plans {
		if _, ok := seed[p]; !ok {
			t.Errorf("F299 setup: plan_limits row for plan=%q missing "+
				"from parsed SQL seed", p)
		}
	}
	return seed, nil
}

// planLimitsFeaturesUpdateProbeRe is a cheap grep that identifies any
// migration whose body carries an `UPDATE plan_limits SET features =
// features || ...` backfill (either IN (...) or `= 'x'` shape). Used
// by parsePlanFeaturesFromMigrations to short-circuit unrelated
// migrations without paying the (?s) multi-line regex cost on every
// file. F317 (M20-2 Phase D R2).
var planLimitsFeaturesUpdateProbeRe = regexp.MustCompile(`UPDATE\s+plan_limits\s+SET\s+features\s*=\s*features\s*\|\|`)

func hasPlanLimitsFeaturesUpdate(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return planLimitsFeaturesUpdateProbeRe.Match(raw), nil
}

// migrationsDirAbs returns the absolute path to apps/api/migrations
// regardless of the working directory the test was launched from.
// runtime.Caller anchors on this file's location.
func migrationsDirAbs(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("F299 setup: runtime.Caller failed")
	}
	// this file: apps/api/internal/model/plan_parity_test.go
	// target:    apps/api/migrations
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations"))
}

// insertRowRe matches the per-plan tuple in the 008 INSERT statement:
//
//	('free', 1, 2, 5, 2, 60, '{"vulnerability_alerts": true, ...}')
//
// Captures the plan name and the JSONB body (still SQL-quoted with
// single quotes).
var insertRowRe = regexp.MustCompile(`\(\s*'([a-z_]+)'\s*,\s*-?\d+\s*,\s*-?\d+\s*,\s*-?\d+\s*,\s*-?\d+\s*,\s*-?\d+\s*,\s*'(\{[^']*\})'\s*\)`)

func parse008Seed(path string) (map[string]map[string]bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Trim to the INSERT INTO plan_limits statement so we do not
	// accidentally pick up other tables' inserts.
	src := string(raw)
	i := strings.Index(src, "INSERT INTO plan_limits")
	if i < 0 {
		return nil, &parseErr{path: path, msg: "INSERT INTO plan_limits not found"}
	}
	// End at the terminating semicolon after the last value row.
	tail := src[i:]
	j := strings.Index(tail, ";")
	if j < 0 {
		return nil, &parseErr{path: path, msg: "no terminating ; after INSERT INTO plan_limits"}
	}
	block := tail[:j]

	out := make(map[string]map[string]bool)
	matches := insertRowRe.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		return nil, &parseErr{path: path, msg: "no plan_limits value rows matched"}
	}
	for _, m := range matches {
		plan := m[1]
		jsonBody := m[2]
		features := make(map[string]bool)
		if err := json.Unmarshal([]byte(jsonBody), &features); err != nil {
			return nil, &parseErr{path: path, msg: "JSONB decode failed for plan=" + plan + ": " + err.Error()}
		}
		out[plan] = features
	}
	return out, nil
}

// backfillUpdateInRe matches
//
//	UPDATE plan_limits SET features = features || '{...}'::jsonb
//	  ... WHERE plan IN ('a', 'b', ...);
//
// (024 and 049 style). Captures the JSON delta and the IN list.
var backfillUpdateInRe = regexp.MustCompile(`(?s)UPDATE\s+plan_limits\s+SET\s+features\s*=\s*features\s*\|\|\s*'(\{[^']*\})'::jsonb\s*(?:,[^;]*?)?WHERE\s+plan\s+IN\s*\(([^)]*)\)\s*;`)

// backfillUpdateEqRe matches
//
//	UPDATE plan_limits SET features = features || '{...}'::jsonb
//	  ... WHERE plan = 'x';
//
// (024's per-plan style, `WHERE plan = '<name>'`). Captures the JSON
// delta and the single plan name.
var backfillUpdateEqRe = regexp.MustCompile(`(?s)UPDATE\s+plan_limits\s+SET\s+features\s*=\s*features\s*\|\|\s*'(\{[^']*\})'::jsonb\s*(?:,[^;]*?)?WHERE\s+plan\s*=\s*'([a-z_]+)'\s*;`)

// planNameRe extracts a bare plan name from a quoted IN (...) list
// entry (e.g. `'free'`).
var planNameRe = regexp.MustCompile(`'([a-z_]+)'`)

// applyBackfillUpdates parses UPDATE ... plan_limits statements in a
// migration file and folds them into `seed` in file order (later
// wins on key collision, matching PostgreSQL `||` right-hand-side
// wins semantics).
func applyBackfillUpdates(seed map[string]map[string]bool, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	src := string(raw)

	total := 0

	// IN (...) form (049 primary + 024 enterprise).
	for _, m := range backfillUpdateInRe.FindAllStringSubmatch(src, -1) {
		jsonDelta := m[1]
		inList := m[2]

		delta := make(map[string]bool)
		if err := json.Unmarshal([]byte(jsonDelta), &delta); err != nil {
			return &parseErr{path: path, msg: "JSONB delta decode failed: " + err.Error()}
		}
		var targetPlans []string
		for _, sm := range planNameRe.FindAllStringSubmatch(inList, -1) {
			targetPlans = append(targetPlans, sm[1])
		}
		if len(targetPlans) == 0 {
			return &parseErr{path: path, msg: "no plan names found in IN (...) clause"}
		}
		for _, plan := range targetPlans {
			mergeDelta(seed, plan, delta)
		}
		total++
	}

	// = 'x' form (024 per-plan style).
	for _, m := range backfillUpdateEqRe.FindAllStringSubmatch(src, -1) {
		jsonDelta := m[1]
		plan := m[2]

		delta := make(map[string]bool)
		if err := json.Unmarshal([]byte(jsonDelta), &delta); err != nil {
			return &parseErr{path: path, msg: "JSONB delta decode failed: " + err.Error()}
		}
		mergeDelta(seed, plan, delta)
		total++
	}

	if total == 0 {
		return &parseErr{path: path, msg: "no UPDATE plan_limits ... jsonb ... WHERE ... matched"}
	}
	return nil
}

func mergeDelta(seed map[string]map[string]bool, plan string, delta map[string]bool) {
	if seed[plan] == nil {
		seed[plan] = make(map[string]bool)
	}
	for k, v := range delta {
		seed[plan][k] = v
	}
}

func unionKeys(byPlan map[string]map[string]bool) map[string]struct{} {
	out := make(map[string]struct{})
	for _, m := range byPlan {
		for k := range m {
			out[k] = struct{}{}
		}
	}
	return out
}

// sortedKeys is unused by the assertions but kept here so a future
// wave writing a diff-view helper can render deterministically.
func sortedKeys(m map[string]struct{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

type parseErr struct {
	path string
	msg  string
}

func (e *parseErr) Error() string { return e.path + ": " + e.msg }

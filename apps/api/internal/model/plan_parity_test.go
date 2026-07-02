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

	// F320 (M21-2 Phase D, F307 close): the Direction 2 error messages
	// below name knownGoOnlyPerPlanMissingFromSQL and
	// knownSQLOnlyPerPlanMissingFromGo as the shrink-pattern
	// escape-hatch maps a wave would populate to defer a per-plan
	// key/value gap. Pre-F320 those maps were only NAMED in the error
	// strings and had no declaration — so an author following the
	// error message to add a deferral entry would find no map to
	// touch, and the meta-test's "add {plan}:{key} to
	// knownGoOnlyPerPlanMissingFromSQL" instruction was factually
	// non-executable. F320 declares both maps as intentionally-empty
	// skeletons mirroring the F271 knownEmitNotRegistered /
	// F281 knownResourceEmitNotRegistered / F299 Direction 1
	// knownGoOnlyMissingFromSQL + knownSQLOnlyMissingFromGo
	// discipline: keyed by `plan + "/" + key` (colon-free so JSON
	// path notation works), value is the F# reason for deferral.
	// Kept empty at F320 so future silent per-plan divergence trips
	// CI loud; a future wave populating an entry MUST come with an
	// F# reason and a shrink-target wave.
	knownGoOnlyPerPlanMissingFromSQL := map[string]string{}
	knownSQLOnlyPerPlanMissingFromGo := map[string]string{}

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
				// F320 (M21-2): consult the skeleton allowlist before
				// erroring so a wave can defer a per-plan gap with an
				// F# reason instead of silencing the assertion.
				if _, deferred := knownGoOnlyPerPlanMissingFromSQL[plan+"/"+k]; deferred {
					continue
				}
				t.Errorf("F299 direction 2 failure (Go → SQL per plan): "+
					"plan=%q key=%q present in Go DefaultPlanLimits "+
					"(=%v) but absent from plan_limits.features JSONB "+
					"for this specific plan. Either add the key to the "+
					"SQL seed / backfill migration for %q, or (if the "+
					"deferral is intentional) add %q to "+
					"knownGoOnlyPerPlanMissingFromSQL with an F# reason.",
					plan, k, goVal, plan, plan+"/"+k)
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
				// F320 (M21-2): consult the skeleton allowlist before
				// erroring so a wave can defer a per-plan gap with an
				// F# reason instead of silencing the assertion.
				if _, deferred := knownSQLOnlyPerPlanMissingFromGo[plan+"/"+k]; deferred {
					continue
				}
				t.Errorf("F299 direction 2 failure (SQL → Go per plan): "+
					"plan=%q key=%q present in plan_limits.features JSONB "+
					"(=%v) but absent from Go DefaultPlanLimits for this "+
					"specific plan. Either add the key to model/plan.go "+
					"DefaultPlanLimits for %q, or (if the deferral is "+
					"intentional) add %q to "+
					"knownSQLOnlyPerPlanMissingFromGo with an F# reason.",
					plan, k, sqlVal, plan, plan+"/"+k)
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
// migration file and folds them into `seed` in SOURCE-POSITION order
// (later wins on key collision, matching PostgreSQL `||` right-hand-
// side wins semantics — which itself follows statement execution
// order in the migration).
//
// F320 (M21-2 Phase D, F308 close): pre-F320 this function ran the
// IN (...) regex over the entire file body first, then the = 'x'
// regex second — so an interleaved sequence like [IN@line10,
// =@line20, IN@line30] would be folded as [IN10, IN30, =20],
// silently permuting the source order. The 8 / 024 / 049 shape at
// M20 close did not induce the reordering (024 uses only the = 'x'
// shape; 049 uses only the IN (...) shape) so the bug was latent,
// but a future migration mixing both shapes would have hit it. F320
// scans matches from both regexes and folds them by their byte
// offset in the source (earlier offset applied first), so PostgreSQL
// `||` last-write-wins semantics hold regardless of which
// regex-flavor the author picks per statement.
//
// F320 (M21-2 Phase D, F308 sibling): the pre-F320 `IN (...) form
// (049 primary + 024 enterprise)` and `= 'x' form (024 per-plan
// style)` inline comments were factually incorrect on the 024
// enterprise attribution — 024's per-plan enterprise UPDATE uses
// the `= 'enterprise'` shape, not the IN (...) shape, and the
// enterprise-only IN clauses in migrations use single-plan lists
// like IN ('enterprise') which are semantically identical to
// = 'enterprise' but not what the pre-F320 comment described. The
// updated comments below reference the shape of the SQL rather
// than pinning specific migrations, which is both more accurate
// and future-migration-proof.
func applyBackfillUpdates(seed map[string]map[string]bool, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return applyBackfillUpdatesFromSource(seed, string(raw), path)
}

// applyBackfillUpdatesFromSource is the in-memory core of
// applyBackfillUpdates, split out (F332, M22-2) so the byte-offset
// source-order fold can be exercised against a synthetic SQL string
// without touching the real migration files on disk (see
// TestPlanBackfillSourceOrder_F332). `label` is used in place of a
// file path in parse-error messages.
func applyBackfillUpdatesFromSource(seed map[string]map[string]bool, src, label string) error {
	// backfillMatch carries a single UPDATE statement's parse result
	// plus the byte offset in the source at which the UPDATE keyword
	// appeared, so all matches from both regex flavors can be sorted
	// into execution order regardless of which regex captured them.
	type backfillMatch struct {
		offset      int             // byte offset of the leading UPDATE keyword in src
		delta       map[string]bool // decoded JSON delta
		targetPlans []string        // one or more plan names the delta applies to
	}
	var matches []backfillMatch

	// IN (...) form — a single UPDATE targeting one or more plans via
	// WHERE plan IN ('a', 'b', ...). Common shape for multi-plan
	// backfills (e.g. 049 free/starter audit_logs=false) but also
	// used for single-plan IN clauses like IN ('enterprise').
	for _, loc := range backfillUpdateInRe.FindAllStringSubmatchIndex(src, -1) {
		jsonDelta := src[loc[2]:loc[3]]
		inList := src[loc[4]:loc[5]]

		delta := make(map[string]bool)
		if err := json.Unmarshal([]byte(jsonDelta), &delta); err != nil {
			return &parseErr{path: label, msg: "JSONB delta decode failed: " + err.Error()}
		}
		var targetPlans []string
		for _, sm := range planNameRe.FindAllStringSubmatch(inList, -1) {
			targetPlans = append(targetPlans, sm[1])
		}
		if len(targetPlans) == 0 {
			return &parseErr{path: label, msg: "no plan names found in IN (...) clause"}
		}
		matches = append(matches, backfillMatch{
			offset:      loc[0],
			delta:       delta,
			targetPlans: targetPlans,
		})
	}

	// = 'x' form — a single UPDATE targeting exactly one plan via
	// WHERE plan = 'x'. Common shape for per-plan backfills where a
	// migration writes a different JSON delta per plan (e.g. 024's
	// per-plan audit_logs=true UPDATE for pro/team/enterprise, each
	// as its own = 'x' UPDATE statement).
	for _, loc := range backfillUpdateEqRe.FindAllStringSubmatchIndex(src, -1) {
		jsonDelta := src[loc[2]:loc[3]]
		plan := src[loc[4]:loc[5]]

		delta := make(map[string]bool)
		if err := json.Unmarshal([]byte(jsonDelta), &delta); err != nil {
			return &parseErr{path: label, msg: "JSONB delta decode failed: " + err.Error()}
		}
		matches = append(matches, backfillMatch{
			offset:      loc[0],
			delta:       delta,
			targetPlans: []string{plan},
		})
	}

	if len(matches) == 0 {
		return &parseErr{path: label, msg: "no UPDATE plan_limits ... jsonb ... WHERE ... matched"}
	}

	// Fold in source-position order so PostgreSQL `||` last-write-
	// wins semantics track statement execution order in the
	// migration (F320 F308 close — pre-F320 grouped by regex flavor
	// which could permute interleaved statements).
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].offset < matches[j].offset
	})
	for _, m := range matches {
		for _, plan := range m.targetPlans {
			mergeDelta(seed, plan, m.delta)
		}
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

// TestPlanBackfillSourceOrder_F332 (M22-2, F327 INFO_DEFER close) is a
// companion micro-test that exercises the byte-offset source-order fold
// in applyBackfillUpdatesFromSource (the
// regexp.FindAllStringSubmatchIndex + sort.Slice path F320 introduced)
// against an IN-memory synthetic SQL fixture whose UPDATE statements
// INTERLEAVE the two regex flavors (IN (...) and = 'x').
//
// Why this test exists: the real migration fixtures at M21 close do not
// exercise the reordering path — 024 uses only the = 'x' shape and 049
// uses only the IN (...) shape, so within each file the per-flavor
// match lists are already in source order and the F320 sort is a no-op.
// A regression that re-grouped folds by regex flavor (the exact pre-F320
// bug shape) would therefore pass the F299 parity test on today's real
// fixtures and only surface once a future migration mixed both shapes
// in one file. This micro-test pins the source-order contract now, as
// companion protection until a real migration (050+) mixes both shapes
// and exercises the path on the real fixture; it deliberately uses a
// synthetic in-memory string and touches no real migration file.
//
// The fixture is constructed so that folding grouped-by-flavor (all
// matches of one regex flavor first, then all matches of the other —
// the pre-F320 bug shape, in EITHER grouping direction) yields
// DIFFERENT final values than folding by byte offset:
//
//   - "f332_flag" on free: IN(true) → ='free'(false) → IN(true).
//     Source order ends true; IN-first flavor-grouping ([IN,IN] then
//     [=]) ends false.
//   - "f332_late" on starter: ='starter'(false) → IN(true).
//     Source order ends true; IN-first flavor-grouping ([IN] then
//     [=]) ends false.
//   - "f332_eq_last" on free: IN(true) → ='free'(false). Source
//     order ends false; =-first flavor-grouping ([=] then [IN]) ends
//     true.
//
// F335 (M22 R2): the third key exists because the original fixture
// could NOT discriminate the =-first grouping direction — every
// mixed-flavor key's FINAL source-order write was IN-flavor, so a
// fold that grouped all = 'x' matches before all IN (...) matches
// still converged to the source-order result and escaped both this
// test and F299 (mutation-verified: flavor-loop swap + sort.Slice
// deletion passed both against the pre-F335 fixture). "f332_eq_last"
// puts the final source-order write on the = 'x' flavor, so each
// grouping direction is now pinned by at least one key (F276
// factuality lineage: the "in both grouping directions" claim above
// is now backed by the fixture instead of contradicted by it).
func TestPlanBackfillSourceOrder_F332(t *testing.T) {
	const src = `
-- F332 synthetic interleaved fixture (in-memory only; NOT a real
-- migration). Statement order deliberately alternates the IN (...)
-- and = 'x' UPDATE shapes so byte-offset order != regex-flavor order.
UPDATE plan_limits SET features = features || '{"f332_flag": true}'::jsonb WHERE plan IN ('free', 'starter');

UPDATE plan_limits SET features = features || '{"f332_flag": false, "f332_eq_only": true}'::jsonb WHERE plan = 'free';

UPDATE plan_limits SET features = features || '{"f332_flag": true}'::jsonb WHERE plan IN ('free');

UPDATE plan_limits SET features = features || '{"f332_late": false}'::jsonb WHERE plan = 'starter';

UPDATE plan_limits SET features = features || '{"f332_late": true}'::jsonb WHERE plan IN ('starter');

UPDATE plan_limits SET features = features || '{"f332_eq_last": true}'::jsonb WHERE plan IN ('free');

UPDATE plan_limits SET features = features || '{"f332_eq_last": false}'::jsonb WHERE plan = 'free';
`

	seed := map[string]map[string]bool{
		"free":    {},
		"starter": {},
	}
	if err := applyBackfillUpdatesFromSource(seed, src, "F332-in-memory-fixture"); err != nil {
		t.Fatalf("F332 setup: applyBackfillUpdatesFromSource failed: %v", err)
	}

	want := map[string]map[string]bool{
		"free": {
			"f332_flag":    true, // IN(true) → =(false) → IN(true): last write in SOURCE order wins
			"f332_eq_only": true,
			// F335: final source-order write is the = 'x' flavor, so an
			// =-first flavor-grouped fold ends true instead — the ONLY
			// key that discriminates that grouping direction.
			"f332_eq_last": false, // IN(true) → =(false): last write in SOURCE order wins
		},
		"starter": {
			"f332_flag": true, // only statement 1 targets starter for this key
			"f332_late": true, // =(false) → IN(true): last write in SOURCE order wins
		},
	}

	for plan, wantFeatures := range want {
		gotFeatures := seed[plan]
		for k, wantVal := range wantFeatures {
			gotVal, ok := gotFeatures[k]
			if !ok {
				t.Errorf("F332 failure: plan=%q key=%q missing from folded "+
					"result — the backfill parser dropped a statement.",
					plan, k)
				continue
			}
			if gotVal != wantVal {
				t.Errorf("F332 failure: plan=%q key=%q folded to %v, want %v "+
					"— the parser is not applying interleaved IN (...) and "+
					"= 'x' UPDATE statements in byte-offset (source) order; "+
					"PostgreSQL || last-write-wins semantics would diverge "+
					"from this fold on a live upgrade.", plan, k, gotVal, wantVal)
			}
		}
		if len(gotFeatures) != len(wantFeatures) {
			t.Errorf("F332 failure: plan=%q folded key set has %d keys, want "+
				"%d (got %v) — the parser picked up keys no fixture "+
				"statement declares for this plan.",
				plan, len(gotFeatures), len(wantFeatures), gotFeatures)
		}
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

// F320 (M21-2 Phase D, F314 close): the pre-F320 `sortedKeys`
// helper was unused by any assertion and kept as speculative
// scaffold for "a future wave writing a diff-view helper" — YAGNI.
// A future wave that actually needs deterministic key iteration for
// a diff-view helper can add the helper back at that point with the
// concrete call site rather than as speculation. Removing keeps
// `.golangci.yml` unused-linter strict-mode from tripping and
// reduces test-file surface area.

type parseErr struct {
	path string
	msg  string
}

func (e *parseErr) Error() string { return e.path + ": " + e.msg }

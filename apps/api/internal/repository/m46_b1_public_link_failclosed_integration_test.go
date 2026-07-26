//go:build integration

// Package repository — M46 Codex round B-1 High-1 / High-2: the anonymous
// public-link path must be FAIL-CLOSED against NULL authorization state.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M46B1' ./internal/repository
//
// High-1: wave 2 read the DDL default at read time — COALESCE(is_active,
// TRUE) — which turned a NULL is_active row into an ACTIVE share link for
// anyone holding the token (fail-open authorization). The fix flips the
// token path to COALESCE(is_active, false) (a link that cannot prove it is
// active is inactive) and migration 058 backfills NULL→false + adds NOT
// NULL so the anomaly class dies at the DDL layer.
//
// High-2: the wave-2 read-side COALESCE(download_count, 0) left the write
// side at `download_count = download_count + 1` — NULL + 1 = NULL in SQL,
// so a NULL-counter link with allowed_downloads=1 passed `0 < 1` on every
// request: unlimited anonymous downloads. The fix COALESCEs the increment
// AND merges check+increment into one conditional UPDATE
// (TryConsumeDownload) so concurrent requests cannot race past the cap
// (TOCTOU) either.
//
// Because migration 058 makes the three columns NOT NULL, seeding the
// hostile NULL rows requires temporarily relaxing the constraints (the
// pre-058 shape); relaxPublicLinksNotNull restores the exact prior state
// via t.Cleanup, so the test proves the code stays fail-closed even if a
// NULL ever reappears (constraint dropped out-of-band, pre-058 DB).

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// publicLinksNotNullAdvisoryLock serialises every test that temporarily
// relaxes the migration-058 NOT NULL constraints on public_links.
//
// `go test ./...` runs packages CONCURRENTLY against the one dev database,
// and the repository / service / handler packages each need the pre-058
// (nullable) shape to seed their hostile rows. Without a lock, package A's
// cleanup can re-add NOT NULL while package B still has NULL rows in
// flight — a real competing-DDL race that shows up as a flaky
// "read back as ACTIVE" failure (observed once in a full ./... run,
// 2026-07-26). The lock is held on a dedicated *sql.Conn because
// PostgreSQL advisory locks are session-scoped and *sql.DB is a pool.
//
// Any new test that relaxes these constraints MUST take this lock. Go
// test files cannot be imported across packages, so the same numeric key
// is duplicated verbatim in
// service/m46_b1_public_link_failclosed_integration_test.go and
// handler/m46_b1_public_download_cap_integration_test.go — keep the three
// in sync.
const publicLinksNotNullAdvisoryLock = 4600581

// lockPublicLinksSchema acquires the cross-package advisory lock and
// releases it via t.Cleanup. Returns the pinned connection so the caller
// runs its DDL on the same session.
func lockPublicLinksSchema(t *testing.T, migDB *sql.DB) *sql.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := migDB.Conn(ctx)
	if err != nil {
		t.Fatalf("pin conn for public_links schema lock: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, publicLinksNotNullAdvisoryLock); err != nil {
		_ = conn.Close()
		t.Fatalf("acquire public_links schema lock: %v", err)
	}
	t.Cleanup(func() {
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, publicLinksNotNullAdvisoryLock); err != nil {
			t.Errorf("release public_links schema lock: %v", err)
		}
		_ = conn.Close()
	})
	return conn
}

// relaxPublicLinksNotNull drops the 058 NOT NULL constraints on
// public_links.is_active / view_count / download_count for the duration of
// the test (no-op for any column that is still nullable, i.e. pre-058
// schema). Cleanup backfills leftover NULLs with the fail-closed values and
// restores exactly the constraints that were present before.
//
// Takes the cross-package advisory lock first — see
// publicLinksNotNullAdvisoryLock. All DDL runs on the locked session so the
// relax/restore window cannot interleave with another package's.
func relaxPublicLinksNotNull(t *testing.T, migDB *sql.DB) {
	t.Helper()
	ctx := context.Background()
	conn := lockPublicLinksSchema(t, migDB)

	cols := map[string]string{
		"is_active":      "false",
		"view_count":     "0",
		"download_count": "0",
	}
	wasNotNull := map[string]bool{}
	for col := range cols {
		var notNull bool
		if err := conn.QueryRowContext(ctx, `
			SELECT a.attnotnull FROM pg_attribute a
			WHERE a.attrelid = 'public.public_links'::regclass AND a.attname = $1
		`, col).Scan(&notNull); err != nil {
			t.Fatalf("read NOT NULL state of public_links.%s: %v", col, err)
		}
		wasNotNull[col] = notNull
		if notNull {
			if _, err := conn.ExecContext(ctx, `ALTER TABLE public_links ALTER COLUMN `+col+` DROP NOT NULL`); err != nil {
				t.Fatalf("relax public_links.%s: %v", col, err)
			}
		}
	}
	// Registered AFTER lockPublicLinksSchema's cleanup, so it runs BEFORE
	// the unlock (t.Cleanup is LIFO) — the constraints are always back in
	// place before another package can take the lock.
	t.Cleanup(func() {
		for col, def := range cols {
			if !wasNotNull[col] {
				continue
			}
			if _, err := conn.ExecContext(ctx, fmt.Sprintf(
				`UPDATE public_links SET %s = %s WHERE %s IS NULL`, col, def, col)); err != nil {
				t.Errorf("re-backfill public_links.%s: %v", col, err)
				continue
			}
			if _, err := conn.ExecContext(ctx, `ALTER TABLE public_links ALTER COLUMN `+col+` SET NOT NULL`); err != nil {
				t.Errorf("restore NOT NULL on public_links.%s: %v", col, err)
			}
		}
	})
}

// seedM46B1PublicLink inserts a public_links row via the migrator conn
// (public_links has no RLS since 030). Pass nil for the NULLable attack
// columns.
func seedM46B1PublicLink(t *testing.T, migDB *sql.DB, tenant, project uuid.UUID,
	name string, isActive any, allowedDownloads any, downloadCount any) (uuid.UUID, string) {
	t.Helper()
	id := uuid.New()
	token := hex64Token()
	if _, err := migDB.Exec(`
		INSERT INTO public_links (id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at)
		VALUES ($1, $2, $3, NULL, $4, $5, '2099-01-01T00:00:00Z', $6, $7, NULL, 0, $8, NOW(), NOW())
	`, id, tenant, project, token, name, isActive, allowedDownloads, downloadCount); err != nil {
		t.Fatalf("seed public link %s: %v", name, err)
	}
	return id, token
}

// TestM46B1_PublicLink_NullIsActive_FailClosed pins High-1 at the
// repository layer: every read path must report a NULL is_active link as
// INACTIVE. Pre-fix, COALESCE(is_active, true) reported it active and the
// service's `if !link.IsActive` guard waved the anonymous caller through
// (measured red). The end-to-end service-level denial is pinned in
// internal/service/m46_b1_public_link_failclosed_integration_test.go.
func TestM46B1_PublicLink_NullIsActive_FailClosed(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	relaxPublicLinksNotNull(t, migDB)

	tenant := seedIntegrationTenant(t, migDB, "m46b1-plinkA")
	projectID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46b1-plink-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	linkID, token := seedM46B1PublicLink(t, migDB, tenant, projectID,
		"m46b1-null-active", nil /* is_active NULL */, nil, 0)

	repo := NewPublicLinkRepository(appDB)
	ctx := context.Background()

	// GetByToken is the anonymous attack surface: the token holder must
	// NOT see an active link.
	if l, err := repo.GetByToken(ctx, token); err != nil {
		t.Errorf("GetByToken(NULL is_active): %v", err)
	} else if l == nil {
		t.Errorf("GetByToken(NULL is_active) returned nil for seeded row")
	} else if l.IsActive {
		t.Errorf("GetByToken: NULL is_active read back as ACTIVE — anonymous token holders can read the SBOM (fail-open)")
	}

	// Dashboard-side reads must agree (one consistent fail-closed rule).
	if l, err := repo.GetByID(ctx, tenant, linkID); err != nil {
		t.Errorf("GetByID(NULL is_active): %v", err)
	} else if l == nil {
		t.Errorf("GetByID(NULL is_active) returned nil for seeded row")
	} else if l.IsActive {
		t.Errorf("GetByID: NULL is_active read back as ACTIVE, want inactive (fail-closed)")
	}
	if links, err := repo.ListByProject(ctx, tenant, projectID); err != nil {
		t.Errorf("ListByProject(NULL is_active): %v", err)
	} else {
		for i := range links {
			if links[i].ID == linkID && links[i].IsActive {
				t.Errorf("ListByProject: NULL is_active read back as ACTIVE, want inactive (fail-closed)")
			}
		}
	}
}

// TestM46B1_PublicLink_NullDownloadCount_CapEnforced pins High-2's NULL
// arithmetic half: with download_count = NULL and allowed_downloads = 1,
// the pre-fix increment (download_count + 1 = NULL) never advanced the
// counter, so IsDownloadLimitReached stayed false forever — unlimited
// anonymous downloads (measured red on both asserts).
func TestM46B1_PublicLink_NullDownloadCount_CapEnforced(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	relaxPublicLinksNotNull(t, migDB)

	tenant := seedIntegrationTenant(t, migDB, "m46b1-plinkB")
	projectID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46b1-cap-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	linkID, _ := seedM46B1PublicLink(t, migDB, tenant, projectID,
		"m46b1-null-count", true, 1 /* allowed_downloads */, nil /* download_count NULL */)

	repo := NewPublicLinkRepository(appDB)
	ctx := context.Background()

	// First download: the handler's pre-fix sequence was check → serve →
	// increment. The increment MUST move the counter off NULL.
	if err := repo.IncrementDownload(ctx, tenant, linkID); err != nil {
		t.Fatalf("IncrementDownload: %v", err)
	}
	var count sql.NullInt64
	if err := migDB.QueryRow(
		`SELECT download_count FROM public_links WHERE id = $1`, linkID).Scan(&count); err != nil {
		t.Fatalf("read download_count back: %v", err)
	}
	if !count.Valid {
		t.Errorf("IncrementDownload on a NULL counter left NULL (NULL + 1 = NULL) — the cap can never be consumed")
	} else if count.Int64 != 1 {
		t.Errorf("download_count = %d after one increment from NULL, want 1", count.Int64)
	}

	// Second request: the cap (1) must now be reached.
	reached, err := repo.IsDownloadLimitReached(ctx, tenant, linkID)
	if err != nil {
		t.Fatalf("IsDownloadLimitReached: %v", err)
	}
	if !reached {
		t.Errorf("IsDownloadLimitReached = false after consuming the 1-download cap — unlimited anonymous downloads")
	}
}

// TestM46B1_PublicLink_TryConsumeDownload_Atomic pins High-2's TOCTOU
// half: N concurrent download attempts against a 1-download link (counter
// starting at the hostile NULL) must yield EXACTLY one success — the
// check+increment is a single conditional UPDATE, so no interleaving can
// oversell the cap. It also proves the no-cap and depleted-cap semantics.
func TestM46B1_PublicLink_TryConsumeDownload_Atomic(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	relaxPublicLinksNotNull(t, migDB)

	tenant := seedIntegrationTenant(t, migDB, "m46b1-plinkC")
	projectID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46b1-atomic-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	capLinkID, _ := seedM46B1PublicLink(t, migDB, tenant, projectID,
		"m46b1-atomic-cap", true, 1 /* allowed_downloads */, nil /* download_count NULL */)

	repo := NewPublicLinkRepository(appDB)
	ctx := context.Background()

	const attackers = 8
	results := make([]bool, attackers)
	errs := make([]error, attackers)
	var wg sync.WaitGroup
	for i := 0; i < attackers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = repo.TryConsumeDownload(ctx, tenant, capLinkID)
		}(i)
	}
	wg.Wait()

	successes := 0
	for i := 0; i < attackers; i++ {
		if errs[i] != nil {
			t.Fatalf("TryConsumeDownload[%d]: %v", i, errs[i])
		}
		if results[i] {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("%d of %d concurrent downloads passed a 1-download cap, want exactly 1 (TOCTOU)", successes, attackers)
	}
	var finalCount int
	if err := migDB.QueryRow(
		`SELECT COALESCE(download_count, -1) FROM public_links WHERE id = $1`, capLinkID).Scan(&finalCount); err != nil {
		t.Fatalf("read final download_count: %v", err)
	}
	if finalCount != 1 {
		t.Errorf("final download_count = %d, want 1 (NULL start must not survive the consume)", finalCount)
	}

	// Depleted cap: further attempts must keep failing.
	if ok, err := repo.TryConsumeDownload(ctx, tenant, capLinkID); err != nil {
		t.Fatalf("TryConsumeDownload (depleted): %v", err)
	} else if ok {
		t.Errorf("TryConsumeDownload succeeded on a depleted cap")
	}

	// No cap (allowed_downloads NULL): consume must always succeed and
	// still advance the counter.
	freeLinkID, _ := seedM46B1PublicLink(t, migDB, tenant, projectID,
		"m46b1-atomic-free", true, nil /* no cap */, nil)
	for i := 0; i < 3; i++ {
		if ok, err := repo.TryConsumeDownload(ctx, tenant, freeLinkID); err != nil {
			t.Fatalf("TryConsumeDownload (no cap, %d): %v", i, err)
		} else if !ok {
			t.Errorf("TryConsumeDownload (no cap) = false on attempt %d, want true", i)
		}
	}
	var freeCount int
	if err := migDB.QueryRow(
		`SELECT COALESCE(download_count, -1) FROM public_links WHERE id = $1`, freeLinkID).Scan(&freeCount); err != nil {
		t.Fatalf("read no-cap download_count: %v", err)
	}
	if freeCount != 3 {
		t.Errorf("no-cap download_count = %d after 3 consumes from NULL, want 3", freeCount)
	}
}

// TestM46B1_PublicLink_FinalGateRevalidatesLiveness pins the codex round 1
// / Medium-1 fix: TryConsumeDownload and TryRegisterView are the LAST
// authorization checks before the response is written, so they must
// re-evaluate is_active and expires_at server-side. The anonymous flows
// validate those in Go against the row read at the START of the request
// and then do several more round-trips to load the SBOM — an owner who
// revokes the link (or an expires_at that simply passes) during that
// window previously had no effect on the in-flight response.
//
// Revoking mid-flight is not directly schedulable in a test, so this pins
// the equivalent server-side predicate: a link that is inactive / expired
// / NULL-active at UPDATE time is refused by both gates.
func TestM46B1_PublicLink_FinalGateRevalidatesLiveness(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	relaxPublicLinksNotNull(t, migDB)

	tenant := seedIntegrationTenant(t, migDB, "m46b1-plinkD")
	projectID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46b1-gate-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	repo := NewPublicLinkRepository(appDB)
	ctx := context.Background()

	// Baseline: a live link passes both gates (guards against a predicate
	// so strict it refuses everything, which would make the cases below
	// vacuous).
	liveID, _ := seedM46B1PublicLink(t, migDB, tenant, projectID, "m46b1-gate-live", true, nil, 0)
	if ok, err := repo.TryRegisterView(ctx, tenant, liveID); err != nil || !ok {
		t.Fatalf("TryRegisterView on a live link = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := repo.TryConsumeDownload(ctx, tenant, liveID); err != nil || !ok {
		t.Fatalf("TryConsumeDownload on a live link = (%v, %v), want (true, nil)", ok, err)
	}

	revokedID, _ := seedM46B1PublicLink(t, migDB, tenant, projectID, "m46b1-gate-revoked", false, nil, 0)
	nullActiveID, _ := seedM46B1PublicLink(t, migDB, tenant, projectID, "m46b1-gate-nullactive", nil, nil, 0)

	expiredID := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO public_links (id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			allowed_downloads, password_hash, view_count, download_count, created_at, updated_at)
		VALUES ($1, $2, $3, NULL, $4, 'm46b1-gate-expired', NOW() - INTERVAL '1 hour', true,
			NULL, NULL, 0, 0, NOW(), NOW())
	`, expiredID, tenant, projectID, hex64Token()); err != nil {
		t.Fatalf("seed expired link: %v", err)
	}

	for _, tc := range []struct {
		name string
		id   uuid.UUID
	}{
		{"revoked (is_active=false)", revokedID},
		{"NULL is_active", nullActiveID},
		{"expired", expiredID},
	} {
		if ok, err := repo.TryConsumeDownload(ctx, tenant, tc.id); err != nil {
			t.Errorf("TryConsumeDownload(%s): %v", tc.name, err)
		} else if ok {
			t.Errorf("TryConsumeDownload admitted a %s link — SBOM bytes would be served after revocation", tc.name)
		}
		if ok, err := repo.TryRegisterView(ctx, tenant, tc.id); err != nil {
			t.Errorf("TryRegisterView(%s): %v", tc.name, err)
		} else if ok {
			t.Errorf("TryRegisterView admitted a %s link — project metadata would be served after revocation", tc.name)
		}
	}

	// A refused gate must not have moved the counters either.
	var views, downloads int
	if err := migDB.QueryRow(
		`SELECT COALESCE(view_count, -1), COALESCE(download_count, -1) FROM public_links WHERE id = $1`,
		revokedID).Scan(&views, &downloads); err != nil {
		t.Fatalf("read revoked counters: %v", err)
	}
	if views != 0 || downloads != 0 {
		t.Errorf("revoked link counters = view %d / download %d, want 0/0 (a refused gate must not consume)", views, downloads)
	}
}

// TestM46B1_PublicLink_FinalGateUsesWallClock pins the codex round 2 /
// Medium-1 fix: the liveness predicate must be evaluated with
// clock_timestamp(), not NOW().
//
// NOW() is transaction_timestamp() — frozen when the statement's implicit
// transaction starts and NOT re-read while the statement waits on a lock.
// So an admission UPDATE that queues behind a concurrent writer just
// before expires_at re-evaluates the freshly committed row against its own
// stale pre-expiry clock and admits the request AFTER the link expired.
//
// The scenario is fully deterministic: hold the row's lock in an
// uncommitted tx, start the gate (it blocks), let the expiry pass, then
// release the lock. With NOW() the gate returns true (measured red); with
// clock_timestamp() it returns false.
func TestM46B1_PublicLink_FinalGateUsesWallClock(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "components") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "m46b1-plinkE")
	projectID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'm46b1-clock-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	repo := NewPublicLinkRepository(appDB)
	ctx := context.Background()

	// gateRace seeds a link expiring shortly, blocks its row behind an
	// uncommitted writer, fires `gate` (which must wait on the lock), lets
	// the expiry elapse, then releases the blocker and returns the gate's
	// verdict.
	//
	// blockerCommits selects WHICH lock-release path is exercised, and the
	// distinction is the whole point of codex round 3's finding: under
	// READ COMMITTED an UPDATE waiting on a row lock only re-evaluates its
	// WHERE clause when the blocker COMMITS a modified row (EvalPlanQual).
	// On ROLLBACK the waiter proceeds against the row it qualified BEFORE
	// the wait — so an inline predicate silently reverts to the stale
	// clock. Locking with FOR UPDATE first and testing the locked row
	// afterwards makes both paths behave the same.
	gateRace := func(t *testing.T, label string, blockerCommits bool, gate func(uuid.UUID) (bool, error)) bool {
		t.Helper()
		linkID := uuid.New()
		if _, err := migDB.Exec(`
			INSERT INTO public_links (id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
				allowed_downloads, password_hash, view_count, download_count, created_at, updated_at)
			VALUES ($1, $2, $3, NULL, $4, $5, clock_timestamp() + INTERVAL '1 second', true,
				NULL, NULL, 0, 0, NOW(), NOW())
		`, linkID, tenant, projectID, hex64Token(), "m46b1-clock-"+label); err != nil {
			t.Fatalf("seed soon-to-expire link (%s): %v", label, err)
		}

		blocker, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin blocker tx (%s): %v", label, err)
		}
		committed := false
		defer func() {
			if !committed {
				_ = blocker.Rollback()
			}
		}()
		// Take the row lock without changing anything meaningful.
		if _, err := blocker.Exec(
			`UPDATE public_links SET name = name WHERE id = $1`, linkID); err != nil {
			t.Fatalf("blocker lock (%s): %v", label, err)
		}

		type verdict struct {
			ok  bool
			err error
		}
		done := make(chan verdict, 1)
		go func() {
			ok, gErr := gate(linkID)
			done <- verdict{ok, gErr}
		}()

		// Let the gate reach the lock wait, then let the link expire while
		// it is parked there.
		time.Sleep(300 * time.Millisecond)
		select {
		case v := <-done:
			t.Fatalf("%s did not block on the row lock (returned %v, %v) — the race this test pins cannot occur", label, v.ok, v.err)
		default:
		}
		time.Sleep(1200 * time.Millisecond)

		if blockerCommits {
			if err := blocker.Commit(); err != nil {
				t.Fatalf("commit blocker (%s): %v", label, err)
			}
		} else if err := blocker.Rollback(); err != nil {
			t.Fatalf("rollback blocker (%s): %v", label, err)
		}
		committed = true // suppress the deferred rollback either way

		select {
		case v := <-done:
			if v.err != nil {
				t.Fatalf("%s returned an error: %v", label, v.err)
			}
			return v.ok
		case <-time.After(10 * time.Second):
			t.Fatalf("%s never returned after the blocker committed", label)
			return false
		}
	}

	for _, release := range []struct {
		name    string
		commits bool
	}{
		{"blocker COMMITs", true},
		// codex round 3: the ROLLBACK path is the one an inline
		// (non-FOR-UPDATE) predicate silently fails — no EvalPlanQual
		// re-check happens, so the waiter uses its pre-wait clock.
		{"blocker ROLLBACKs", false},
	} {
		if admitted := gateRace(t, "TryConsumeDownload/"+release.name, release.commits, func(id uuid.UUID) (bool, error) {
			return repo.TryConsumeDownload(ctx, tenant, id)
		}); admitted {
			t.Errorf("TryConsumeDownload admitted a link that expired while the statement waited on the row lock (%s) — the gate must lock with FOR UPDATE and then evaluate expiry against clock_timestamp()", release.name)
		}

		if admitted := gateRace(t, "TryRegisterView/"+release.name, release.commits, func(id uuid.UUID) (bool, error) {
			return repo.TryRegisterView(ctx, tenant, id)
		}); admitted {
			t.Errorf("TryRegisterView admitted a link that expired while the statement waited on the row lock (%s) — the gate must lock with FOR UPDATE and then evaluate expiry against clock_timestamp()", release.name)
		}
	}
}

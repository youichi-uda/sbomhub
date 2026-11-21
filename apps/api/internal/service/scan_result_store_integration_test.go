//go:build integration

package service

// Recorded scan results (migration 071, scan_result_store.go) on a real
// PostgreSQL (role split, FORCE RLS) and a real Redis: what is recorded,
// by which replica, how readers fall back to it once the live status is gone,
// and the rolling-upgrade cases with an OLDER replica (a3a785e's scripts,
// verbatim in scan_run_oldreplica_test.go; an older replica records nothing).

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/sbomhub/sbomhub/internal/database"
)

type resultEnv struct {
	mig, app *sql.DB
	rdb      *redis.Client
}

func newResultEnv(t *testing.T) resultEnv {
	t.Helper()
	appURL, migURL := wave3SvcEnv(t)
	return resultEnv{mig: wave3SvcOpenOrSkip(t, migURL), app: wave3SvcOpenOrSkip(t, appURL), rdb: m72Redis(t)}
}

// seedSBOM seeds a tenant with one project and one SBOM.
func (e resultEnv) seedSBOM(t *testing.T) (tenantID, sbomID uuid.UUID) {
	t.Helper()
	tenantID = wave3SvcSeedTenant(t, e.mig, "scanresult")
	projectID := uuid.New()
	sbomID = uuid.New()
	wave3SvcExecAsTenant(t, e.mig, tenantID, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'p')`, projectID, tenantID)
	wave3SvcExecAsTenant(t, e.mig, tenantID, `INSERT INTO sboms (id, tenant_id, project_id, format, version) VALUES ($1, $2, $3, 'cyclonedx', '1.5')`, sbomID, tenantID, projectID)
	return tenantID, sbomID
}

// tracker is a replica of this version on e's Redis and database.
func (e resultEnv) tracker(t *testing.T) *ScanTracker {
	t.Helper()
	tr := process(e.rdb, 0, time.Hour)
	tr.WithResultStore(e.app)
	fastTiming(tr)
	return tr
}

// fastTiming makes tr's re-checks and retries fast.
func fastTiming(tr *ScanTracker) {
	tr.results.timing.rechecks = []time.Duration{300 * time.Millisecond, 600 * time.Millisecond}
	tr.results.timing.recheckEvery = 300 * time.Millisecond
	tr.results.timing.retries = []time.Duration{10 * time.Millisecond}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e resultEnv) row(t *testing.T, tenantID, sbomID uuid.UUID) scanResultRow {
	t.Helper()
	r, err := (&pgScanResultStore{db: e.app}).read(context.Background(), tenantID, sbomID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e resultEnv) lose(t *testing.T, sbomID uuid.UUID) {
	t.Helper()
	must(t, e.rdb.Del(context.Background(), scanStatusKeys(sbomID)...).Err())
}

var fullCoverage = ScanCoverage{Checked: []string{"nvd", "jvn", "distro"}, Reported: true}

func TestScanResultPG_StoreRoundTripRLSAndOrdering(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	other, _ := e.seedSBOM(t)
	st := &pgScanResultStore{db: e.app}
	ctx := context.Background()

	// A finding linked to the SBOM, for vuln_total.
	compID, vulnID := uuid.New(), uuid.New()
	wave3SvcExecAsTenant(t, e.mig, tenant, `INSERT INTO components (id, tenant_id, sbom_id, name) VALUES ($1, $2, $3, 'c')`, compID, tenant, id)
	if _, err := e.mig.Exec(`INSERT INTO vulnerabilities (id, cve_id) VALUES ($1, $2)`, vulnID, "CVE-2099-"+vulnID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.mig.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID) })
	wave3SvcExecAsTenant(t, e.mig, tenant, `INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1, $2)`, compID, vulnID)

	start := time.Now().Add(-time.Second)
	must(t, st.open(ctx, tenant, id, 7, start, false))
	r := e.row(t, tenant, id)
	if !r.found || r.status != "" || r.openRuns["7"].Start != start.UnixMilli() || r.openRuns["7"].Seq != r.rev ||
		r.lastOpenSeq != r.rev || r.lastStarted.UnixMilli() != start.UnixMilli() {
		t.Fatalf("after open: %+v", r)
	}
	fin := time.Now().Truncate(time.Millisecond)
	must(t, st.close(ctx, tenant, id, []uint64{7}, &scanResultRecord{state: ScanStateCompleted, checked: []string{}, checkedKnown: true,
		skipped: []string{"nvd", "jvn", "distro"}, run: "r1", finishedAt: fin, coveredSeq: -1}, time.Hour))
	r = e.row(t, tenant, id)
	if r.status != "completed" || len(r.openRuns) != 0 || !r.checkedKnown || len(r.checked) != 0 || r.run != "r1" ||
		!r.finishedAt.Equal(fin) || !slices.Equal(r.skipped, []string{"nvd", "jvn", "distro"}) || r.resultSeq != r.rev {
		t.Fatalf("after close: %+v", r)
	}
	var total int
	if err := e.mig.QueryRow(`SELECT vuln_total FROM tenant_sbom_scan_results WHERE sbom_id = $1`, id).Scan(&total); err == nil {
		t.Fatalf("the migrator role must not read the row without the tenant GUC (FORCE RLS)")
	}
	tx, _ := e.app.Begin()
	_, _ = tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenant.String())
	if err := tx.QueryRow(`SELECT vuln_total FROM tenant_sbom_scan_results WHERE sbom_id = $1`, id).Scan(&total); err != nil || total != 1 {
		t.Fatalf("vuln_total %d, %v", total, err)
	}
	_ = tx.Rollback()

	// An older result never replaces a newer one; a newer one does.
	must(t, st.close(ctx, tenant, id, nil, &scanResultRecord{state: ScanStateFailed, errMsg: "x", reasons: []string{"fetch_failed"}, finishedAt: fin.Add(-time.Minute)}, time.Hour))
	if r := e.row(t, tenant, id); r.status != "completed" {
		t.Fatalf("an older result replaced a newer one: %+v", r)
	}
	must(t, st.close(ctx, tenant, id, nil, &scanResultRecord{state: ScanStateFailed, errMsg: "x", reasons: []string{"fetch_failed"}, finishedAt: fin.Add(time.Minute)}, time.Hour))
	if r := e.row(t, tenant, id); r.status != "failed" || r.checkedKnown || !slices.Equal(r.reasons, []string{"fetch_failed"}) {
		t.Fatalf("a newer result: %+v", r)
	}

	// RLS: another tenant reads nothing and cannot write the SBOM's row.
	if r, err := st.read(ctx, other, id); err != nil || r.found {
		t.Fatalf("other tenant read %+v %v", r, err)
	}
	if err := st.open(ctx, other, id, 9, time.Now(), false); err == nil {
		t.Fatal("another tenant must not write a row for this SBOM")
	}
	if r := e.row(t, tenant, id); r.openRuns["9"].Start != 0 {
		t.Fatalf("other tenant's open landed: %+v", r)
	}

	// A deleted SBOM takes its row along.
	wave3SvcExecAsTenant(t, e.mig, tenant, `DELETE FROM sboms WHERE id = $1`, id)
	if r := e.row(t, tenant, id); r.found {
		t.Fatalf("row kept after the SBOM was deleted: %+v", r)
	}
	// An open for a missing SBOM fails (logged by the recorder), nothing more.
	if err := st.open(ctx, tenant, id, 1, time.Now(), false); err == nil {
		t.Fatal("open of a deleted SBOM must fail")
	}
}

// The scenario of the report: a scan finished, its live status is gone
// (expired, evicted, FLUSHDB), and scan-status answers its recorded result.
func TestScanResultPG_RecordedAfterTheLiveStatusIsGone(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	a, b := e.tracker(t), e.tracker(t)
	gen, run := a.BeginRun(id)
	a.Attach(tenant, id, gen)
	a.FinishCoverage(id, gen, nil, "", fullCoverage)
	eventually(t, "the recorded result", func() bool { return e.row(t, tenant, id).status == "completed" })

	live := b.GetStatusRecorded(context.Background(), tenant, id)
	if live.State != ScanStateCompleted || live.Source != ScanStatusSourceLive || live.Run != run {
		t.Fatalf("live: %+v", live)
	}
	r := e.row(t, tenant, id)
	if r.run != run || !r.checkedKnown || len(r.openRuns) != 0 {
		t.Fatalf("row: %+v", r)
	}
	e.lose(t, id)
	for _, tr := range []*ScanTracker{a, b} {
		d := tr.GetStatusRecorded(context.Background(), tenant, id)
		if d.State != ScanStateCompleted || d.Source != ScanStatusSourceRecorded || d.Run != "" ||
			!slices.Equal(d.Checked, []string{"nvd", "jvn", "distro"}) || !d.CheckedKnown || !d.LastScanAt.Equal(r.finishedAt) {
			t.Fatalf("recorded: %+v", d)
		}
	}
	// Without the fallback (GetStatus), as before: unknown.
	if d := b.GetStatus(id); d.State != ScanStateUnknown {
		t.Fatalf("GetStatus: %+v", d)
	}
	// Redis unreadable is not "no entry": no recorded answer.
	c := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() { _ = c.Close() })
	down := NewScanTracker().WithRedis(c).WithResultStore(e.app)
	if d := down.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateUnknown {
		t.Fatalf("redis down: %+v", d)
	}
}

func TestScanResultPG_OverlapAcrossReplicasRecordsTheGroup(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	a, b := e.tracker(t), e.tracker(t)
	g1 := a.Begin(id)
	a.Attach(tenant, id, g1)
	g2 := b.Begin(id)
	b.Attach(tenant, id, g2)
	eventually(t, "both opens", func() bool { return len(e.row(t, tenant, id).openRuns) == 2 })
	a.FinishCoverage(id, g1, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)", ScanCoverage{Checked: []string{"jvn", "distro"}, Reported: true})
	eventually(t, "a's close", func() bool { return len(e.row(t, tenant, id).openRuns) == 1 })
	if r := e.row(t, tenant, id); r.status != "" {
		t.Fatalf("recorded while b still runs: %+v", r)
	}
	b.FinishCoverage(id, g2, nil, "", fullCoverage)
	eventually(t, "the group's result", func() bool { return e.row(t, tenant, id).status == "failed" })
	e.lose(t, id)
	// (a and b still answer their own memory's failed, live, as before;
	// a replica without it reads the recorded result.)
	d := e.tracker(t).GetStatusRecorded(context.Background(), tenant, id)
	if d.State != ScanStateFailed || !slices.Equal(d.Reasons, []string{ScanReasonFetchFailed}) ||
		!slices.Equal(d.Checked, []string{"jvn", "distro"}) || d.Source != ScanStatusSourceRecorded {
		t.Fatalf("recorded: %+v", d)
	}
}

// A running scan is never hidden by an older recorded row: not while its
// live status exists, and not while it is lost (eviction) until its run
// rejoins.
func TestScanResultPG_ARunningScanIsNeverHidden(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	a, b := e.tracker(t), e.tracker(t)
	g1 := a.Begin(id)
	a.Attach(tenant, id, g1)
	a.Finish(id, g1, nil, "")
	eventually(t, "the first result", func() bool { return e.row(t, tenant, id).status == "completed" })

	b.hbInterval = 50 * time.Millisecond
	g2 := b.Begin(id)
	b.Attach(tenant, id, g2)
	eventually(t, "the second open", func() bool { return len(e.row(t, tenant, id).openRuns) == 1 })
	if d := a.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateRunning || d.Source != ScanStatusSourceLive {
		t.Fatalf("while b scans: %+v", d)
	}
	e.lose(t, id)
	// Lost: unknown (b's open run), never the recorded completed.
	if d := a.GetStatusRecorded(context.Background(), tenant, id); d.State == ScanStateCompleted {
		t.Fatalf("the lost running scan was hidden by the recorded row: %+v", d)
	}
	// b's heartbeat restarts its heartbeat loop and rejoins.
	b.qMu.Lock()
	b.ensureHeartbeatLocked()
	b.qMu.Unlock()
	eventually(t, "the rejoin", func() bool { return a.GetStatusRecorded(context.Background(), tenant, id).State == ScanStateRunning })
	b.Finish(id, g2, nil, "")
	eventually(t, "the second result", func() bool { r := e.row(t, tenant, id); return len(r.openRuns) == 0 && r.status != "" })
}

// A run whose process died: unknown while it could still be running, then
// failed (interrupted) once it cannot, after its live status is gone.
func TestScanResultPG_InterruptedRun(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	a, b := e.tracker(t), e.tracker(t)
	g1 := a.Begin(id)
	a.Attach(tenant, id, g1)
	a.Finish(id, g1, nil, "")
	eventually(t, "the first result", func() bool { return e.row(t, tenant, id).status == "completed" })

	// Started right after the result (well within recordClockSlack): later
	// by its open's sequence (Codex R1 Medium-2).
	dead := e.tracker(t)
	g := dead.Begin(id)
	dead.Attach(tenant, id, g)
	eventually(t, "the open", func() bool { return len(e.row(t, tenant, id).openRuns) == 1 })
	// The process dies: no finish. Its live status expires.
	e.lose(t, id)
	if d := b.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateUnknown {
		t.Fatalf("while it could still run: %+v", d)
	}
	b.results.staleAfter = 200 * time.Millisecond
	time.Sleep(300 * time.Millisecond)
	d := b.GetStatusRecorded(context.Background(), tenant, id)
	if d.State != ScanStateFailed || !slices.Equal(d.Reasons, []string{ScanReasonInterrupted}) || d.Source != ScanStatusSourceRecorded || d.LastScanAt.IsZero() {
		t.Fatalf("stale open run: %+v", d)
	}
	// The next scan's result supersedes it and clears the stale run.
	a.results.staleAfter = 200 * time.Millisecond
	g3 := a.Begin(id)
	a.Attach(tenant, id, g3)
	a.Finish(id, g3, nil, "")
	eventually(t, "the next result", func() bool { r := e.row(t, tenant, id); return len(r.openRuns) == 0 })
	e.lose(t, id)
	if d := b.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateCompleted {
		t.Fatalf("after the next scan: %+v", d)
	}
}

// A young key held running (Redis can evict): the finish sees running, the
// re-check records the result once the hold is over.
func TestScanResultPG_YoungHoldIsRecordedByTheRecheck(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	a := e.tracker(t)
	a.shared.(*redisScanStatusStore).scripts = newStatusScriptsYoung(a.maxRunAge, 200*time.Millisecond)
	g := a.Begin(id)
	a.Attach(tenant, id, g)
	a.Finish(id, g, nil, "")
	eventually(t, "the close", func() bool { r := e.row(t, tenant, id); return r.found && len(r.openRuns) == 0 })
	eventually(t, "the re-checked result", func() bool { return e.row(t, tenant, id).status == "completed" })
}

// Rolling upgrade: an older replica (a3a785e's scripts) records nothing.
func TestScanResultPG_OlderReplicaFinishesTheGroup(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	ctx := context.Background()
	a := e.tracker(t)
	old := prevScripts(a.maxRunAge)
	keys := scanStatusKeys(id)

	// This version's run and an older replica's in one group; the older one
	// finishes last. This version's finish sees running; its re-check
	// records the group's result (without scan_run: the older replica's
	// write dropped it).
	g := a.Begin(id)
	a.Attach(tenant, id, g)
	must(t, old.begin.Run(ctx, e.rdb, keys, "77", 90000, 3600000, "0").Err())
	a.FinishCoverage(id, g, nil, "", fullCoverage)
	eventually(t, "the close", func() bool { r := e.row(t, tenant, id); return r.found && len(r.openRuns) == 0 })
	if r := e.row(t, tenant, id); r.status != "" {
		t.Fatalf("recorded while the older replica runs: %+v", r)
	}
	must(t, old.finish.Run(ctx, e.rdb, keys, "77", 3600000, "jvn: scan failed (fetch_failed)", `["fetch_failed"]`, "[]", "").Err())
	eventually(t, "the re-checked result", func() bool { return e.row(t, tenant, id).status == "failed" })
	if r := e.row(t, tenant, id); r.run != "" || !slices.Equal(r.reasons, []string{"fetch_failed"}) {
		t.Fatalf("row: %+v", r)
	}
	first := e.row(t, tenant, id)

	// A whole scan by an older replica alone: nothing recorded; once its
	// live status is gone, readers get the previous recorded result, with
	// its own last_scan_at.
	must(t, old.begin.Run(ctx, e.rdb, keys, "78", 90000, 3600000, "0").Err())
	must(t, old.finish.Run(ctx, e.rdb, keys, "78", 3600000, "", "[]", "[]", "").Err())
	if d := a.GetStatusRecorded(ctx, tenant, id); d.State != ScanStateCompleted || d.Source != ScanStatusSourceLive {
		t.Fatalf("live older-replica result: %+v", d)
	}
	e.lose(t, id)
	d := a.GetStatusRecorded(ctx, tenant, id)
	if d.State != ScanStateFailed || d.Source != ScanStatusSourceRecorded || !d.LastScanAt.Equal(first.finishedAt) {
		t.Fatalf("after the older replica's scan: %+v", d)
	}
}

// A database failure never fails or holds up the scan.
func TestScanResultPG_DatabaseFailureNeverFailsTheScan(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	appURL, _ := wave3SvcEnv(t)
	broken, err := sql.Open("postgres", appURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = broken.Close()
	a := process(e.rdb, 0, time.Hour)
	a.WithResultStore(broken)
	fastTiming(a)
	g := a.Begin(id)
	start := time.Now()
	a.Attach(tenant, id, g) // bounded by attachWait
	if time.Since(start) > a.results.timing.attachWait+time.Second {
		t.Fatalf("Attach waited %v", time.Since(start))
	}
	start = time.Now()
	if !a.Finish(id, g, nil, "") || time.Since(start) > time.Second {
		t.Fatal("the finish must not wait on the database")
	}
	if st, _, _ := detail(a, id, a); st != ScanStateCompleted {
		t.Fatalf("live: %s", st)
	}
	eventually(t, "the recorder", func() bool {
		a.results.mu.Lock()
		defer a.results.mu.Unlock()
		return !a.results.running && len(a.results.queue) == 0
	})
	e.lose(t, id)
	if d := a.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateUnknown {
		t.Fatalf("unreadable database: %+v", d)
	}
}

// Codex R1 High-2: a tenant cannot create the row of another tenant's SBOM
// (which would occupy its primary key and keep it from being recorded): not
// through the store, and not through SQL (migration 071's trigger).
func TestScanResultPG_AnotherTenantCannotCreateTheRow(t *testing.T) {
	e := newResultEnv(t)
	victim, id := e.seedSBOM(t)
	attacker, _ := e.seedSBOM(t)
	st := &pgScanResultStore{db: e.app}
	ctx := context.Background()
	if err := st.open(ctx, attacker, id, 1, time.Now(), false); err == nil {
		t.Fatal("open of another tenant's SBOM must fail")
	}
	tx, err := e.app.Begin()
	must(t, err)
	_, _ = tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, attacker.String())
	if _, err := tx.Exec(`INSERT INTO tenant_sbom_scan_results (sbom_id, tenant_id) VALUES ($1, $2)`, id, attacker); err == nil {
		_ = tx.Commit()
		t.Fatal("the database accepted a row naming another tenant's SBOM")
	}
	_ = tx.Rollback()
	// The SBOM's own tenant records it normally.
	must(t, st.open(ctx, victim, id, 2, time.Now(), false))
	if r := e.row(t, victim, id); r.openRuns["2"].Start == 0 {
		t.Fatalf("victim row: %+v", r)
	}
}

// Codex R1 High-3: two results published in the same millisecond are ordered
// by the Redis write counter: the older one, written last, does not win.
func TestScanResultPG_SameMillisecondOlderResultDoesNotOverwrite(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	st := &pgScanResultStore{db: e.app}
	ctx := context.Background()
	at := time.Now().Truncate(time.Millisecond)
	must(t, st.close(ctx, tenant, id, nil, &scanResultRecord{state: ScanStateFailed, errMsg: "b", reasons: []string{"fetch_failed"},
		finishedAt: at, born: 100, ver: 9}, time.Hour))
	must(t, st.close(ctx, tenant, id, nil, &scanResultRecord{state: ScanStateCompleted, finishedAt: at, born: 100, ver: 8}, time.Hour))
	if r := e.row(t, tenant, id); r.status != "failed" {
		t.Fatalf("the older same-millisecond result won: %+v", r)
	}
	must(t, st.close(ctx, tenant, id, nil, &scanResultRecord{state: ScanStateCompleted, finishedAt: at, born: 100, ver: 10}, time.Hour))
	if r := e.row(t, tenant, id); r.status != "completed" {
		t.Fatalf("the newer same-millisecond result lost: %+v", r)
	}
}

// Codex R1 Medium-4: a recorded read inside the request's transaction uses
// that transaction (no second pool connection), and a failure inside it does
// not abort the request's transaction.
func TestScanResultPG_ReadUsesTheRequestTransaction(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	st := &pgScanResultStore{db: e.app}
	must(t, st.open(context.Background(), tenant, id, 3, time.Now(), false))

	appURL, _ := wave3SvcEnv(t)
	one, err := sql.Open("postgres", appURL)
	must(t, err)
	t.Cleanup(func() { _ = one.Close() })
	one.SetMaxOpenConns(1)
	tx, err := one.Begin()
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenant.String())
	must(t, err)
	ctx, cancel := context.WithTimeout(database.WithTx(context.Background(), tx), 2*time.Second)
	defer cancel()
	r, err := (&pgScanResultStore{db: one}).read(ctx, tenant, id)
	if err != nil || r.openRuns["3"].Start == 0 {
		t.Fatalf("read in the request transaction: %+v, %v", r, err)
	}
	// The request transaction is still usable after the read.
	var n int
	if err := tx.QueryRow(`SELECT 1`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("request transaction after the read: %v", err)
	}
}

// Codex R1 Medium-3: an older replica's run that outlasts the first
// re-checks is still recorded once it finishes (re-checks continue while a
// scan could run).
func TestScanResultPG_LongOlderReplicaRunIsRecordedLater(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	ctx := context.Background()
	a := e.tracker(t)
	old := prevScripts(a.maxRunAge)
	keys := scanStatusKeys(id)
	g := a.Begin(id)
	a.Attach(tenant, id, g)
	must(t, old.begin.Run(ctx, e.rdb, keys, "88", 90000, 3600000, "0").Err())
	a.FinishCoverage(id, g, nil, "", fullCoverage)
	// Past both initial re-checks (300ms, 600ms).
	time.Sleep(1500 * time.Millisecond)
	if r := e.row(t, tenant, id); r.status != "" {
		t.Fatalf("recorded while the older replica runs: %+v", r)
	}
	must(t, old.finish.Run(ctx, e.rdb, keys, "88", 3600000, "", "[]", "[]", "").Err())
	eventually(t, "the later re-check", func() bool { return e.row(t, tenant, id).status == "completed" })
}

// Codex R2 High-1: a recorder that replays a result it read BEFORE a newer
// open was written must not cover that open (the replay keeps the result's
// covered sequence, it does not advance it to the replay's write).
func TestScanResultPG_ReplayedResultDoesNotCoverALaterOpen(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	st := &pgScanResultStore{db: e.app}
	ctx := context.Background()
	at := time.Now().Truncate(time.Millisecond)
	s0, err := st.seq(ctx, tenant, id)
	must(t, err)
	rec := func() *scanResultRecord {
		return &scanResultRecord{state: ScanStateCompleted, finishedAt: at, born: 1, ver: 5, coveredSeq: s0}
	}
	must(t, st.close(ctx, tenant, id, nil, rec(), time.Hour))
	// A later run starts (within the clock slack) ...
	must(t, st.open(ctx, tenant, id, 42, at.Add(time.Second), false))
	// ... and a delayed recorder replays the same result read before it.
	must(t, st.close(ctx, tenant, id, nil, rec(), time.Hour))
	r := e.row(t, tenant, id)
	if r.openRuns["42"].Seq <= r.resultSeq {
		t.Fatalf("the replay covered a later open: open seq %d, result seq %d", r.openRuns["42"].Seq, r.resultSeq)
	}
	// The later run closes without a recorded result: unknown, not the old one.
	must(t, st.close(ctx, tenant, id, []uint64{42}, nil, time.Hour))
	if d, ok := recordedStatus(e.row(t, tenant, id), time.Hour, time.Now()); ok {
		t.Fatalf("a later run without a result was hidden behind the older one: %+v", d)
	}
}

// Codex R2 Medium-3: a read whose context is already done fails, and the
// request transaction stays usable (the savepoint cleanup has its own bound).
func TestScanResultPG_CancelledReadLeavesTheRequestTransactionUsable(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	tx, err := e.app.Begin()
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenant.String())
	must(t, err)
	ctx, cancel := context.WithCancel(database.WithTx(context.Background(), tx))
	cancel()
	if _, err := (&pgScanResultStore{db: e.app}).read(ctx, tenant, id); err == nil {
		t.Fatal("a read with a cancelled context succeeded")
	}
	var n int
	if err := tx.QueryRow(`SELECT 1`).Scan(&n); err != nil {
		t.Fatalf("request transaction after a cancelled read: %v", err)
	}
}

// Codex R5 Medium-2: a short scan whose open was unacked (its Begin had not
// reached Redis yet) and that then finished and recorded its own result
// reads that result, not unknown.
func TestScanResultPG_UnackedRunsOwnResultIsRead(t *testing.T) {
	e := newResultEnv(t)
	tenant, id := e.seedSBOM(t)
	st := &pgScanResultStore{db: e.app}
	ctx := context.Background()
	now := time.Now()
	must(t, st.open(ctx, tenant, id, 5, now, true))
	s0, err := st.seq(ctx, tenant, id)
	must(t, err)
	// Its result is read back after its finish: covered sequence = the
	// row's sequence then (the open included), published right after it.
	must(t, st.close(ctx, tenant, id, []uint64{5}, &scanResultRecord{state: ScanStateCompleted,
		finishedAt: now.Add(100 * time.Millisecond), born: 1, ver: 3, coveredSeq: s0 - 1}, time.Hour))
	r := e.row(t, tenant, id)
	if r.lastOpenUnacked {
		t.Fatalf("the run's own result left the unacked mark: %+v", r)
	}
	if d, ok := recordedStatus(r, time.Hour, time.Now()); !ok || d.State != ScanStateCompleted {
		t.Fatalf("got %+v ok=%v, want its completed result", d, ok)
	}
}

package service

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// memResultStore is scanResultStore in memory, with pgScanResultStore's
// rules (the database version is tested in
// scan_result_store_integration_test.go).
type memResultStore struct {
	mu      sync.Mutex
	rows    map[uuid.UUID]*scanResultRow
	tenants map[uuid.UUID]uuid.UUID
	ops     []string
	failAll bool
	// failNext fails that many writes, then succeeds; openDelay delays
	// every open.
	failNext  int
	openDelay time.Duration
	// readHook runs inside read, before the row is returned.
	readHook func()
}

func newMemResultStore() *memResultStore {
	return &memResultStore{rows: map[uuid.UUID]*scanResultRow{}, tenants: map[uuid.UUID]uuid.UUID{}}
}

var errMemStore = errors.New("mem store: failing")

func (m *memResultStore) row(tenantID, sbomID uuid.UUID, create bool) *scanResultRow {
	r := m.rows[sbomID]
	if r == nil && create {
		r = &scanResultRow{found: true, openRuns: map[string]openRun{}}
		m.rows[sbomID] = r
		m.tenants[sbomID] = tenantID
	}
	if r != nil && m.tenants[sbomID] != tenantID {
		return nil // RLS: another tenant's row is invisible
	}
	return r
}

func (m *memResultStore) open(_ context.Context, tenantID, sbomID uuid.UUID, gen uint64, at time.Time, unacked bool) error {
	time.Sleep(m.openDelay)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ops = append(m.ops, "open:"+genString(gen))
	if m.fail() {
		return errMemStore
	}
	r := m.row(tenantID, sbomID, true)
	r.rev++
	r.openRuns[genString(gen)] = openRun{Start: at.UnixMilli(), Seq: r.rev, Unacked: unacked}
	r.lastOpenSeq, r.lastOpenUnacked = r.rev, unacked
	if at.After(r.lastStarted) {
		r.lastStarted = at
	}
	return nil
}

func (m *memResultStore) close(_ context.Context, tenantID, sbomID uuid.UUID, gens []uint64, rec *scanResultRecord, staleAfter time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tag := "close:"
	for i, g := range gens {
		if i > 0 {
			tag += ","
		}
		tag += genString(g)
	}
	if rec != nil {
		tag += ":" + string(rec.state)
	}
	m.ops = append(m.ops, tag)
	if m.fail() {
		return errMemStore
	}
	r := m.row(tenantID, sbomID, rec != nil)
	if r == nil {
		return nil
	}
	var closedSeq int64
	for _, g := range gens {
		if o, ok := r.openRuns[genString(g)]; ok {
			closedSeq = max(closedSeq, o.Seq)
		}
		delete(r.openRuns, genString(g))
	}
	r.rev++
	if rec != nil && (r.status == "" || newerOrSame(rec.finishedAt, rec.born, rec.ver, r.finishedAt, r.born, r.ver)) {
		r.resultSeq = max(coveredBy(rec, lockedRow{resultSeq: r.resultSeq}, r.rev), closedSeq)
		if closedSeq > 0 && closedSeq == r.lastOpenSeq {
			r.lastOpenUnacked = false
		}
		dropCovered(r.openRuns, r.resultSeq, rec.finishedAt, staleAfter, time.Now())
		r.born, r.ver = rec.born, rec.ver
		r.status = string(rec.state)
		r.errMsg, r.reasons = "", nil
		if rec.state == ScanStateFailed {
			r.errMsg, r.reasons = rec.errMsg, rec.reasons
		}
		r.skipped = rec.skipped
		r.checked, r.checkedKnown = rec.checked, rec.checkedKnown
		r.run = rec.run
		r.finishedAt = rec.finishedAt
	}
	return nil
}

// fail reports whether this write fails. m.mu is held.
func (m *memResultStore) fail() bool {
	if m.failAll {
		return true
	}
	if m.failNext > 0 {
		m.failNext--
		return true
	}
	return false
}

func (m *memResultStore) seq(_ context.Context, tenantID, sbomID uuid.UUID) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.row(tenantID, sbomID, false); r != nil {
		return r.rev, nil
	}
	return 0, nil
}

func (m *memResultStore) read(_ context.Context, tenantID, sbomID uuid.UUID) (scanResultRow, error) {
	if m.readHook != nil {
		m.readHook()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAll {
		return scanResultRow{}, errMemStore
	}
	r := m.row(tenantID, sbomID, false)
	if r == nil {
		return scanResultRow{}, nil
	}
	c := *r
	c.openRuns = map[string]openRun{}
	for k, v := range r.openRuns {
		c.openRuns[k] = v
	}
	return c, nil
}

func (m *memResultStore) get(sbomID uuid.UUID) scanResultRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.rows[sbomID]; r != nil {
		return *r
	}
	return scanResultRow{}
}

// recordingTracker is an in-memory tracker (no Redis) recording into a
// memResultStore.
func recordingTracker(t *testing.T) (*ScanTracker, *memResultStore) {
	t.Helper()
	tr := NewScanTracker()
	st := newMemResultStore()
	tr.withResultStore(st)
	return tr, st
}

// expire drops sbomID's live (in-memory) entry, as retention does.
func expire(tr *ScanTracker, sbomID uuid.UUID) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	delete(tr.entries, sbomID)
}

func TestRecordedStatus(t *testing.T) {
	now := time.Now()
	stale := time.Hour
	fin := now.Add(-3 * 24 * time.Hour)
	// rev 7: the result was written at seq 5, the last open at seq 3.
	base := scanResultRow{found: true, status: "completed", finishedAt: fin, lastStarted: fin.Add(-time.Minute),
		checked: []string{"distro", "nvd", "jvn"}, checkedKnown: true, run: "r1", rev: 7,
		resultSeq: 5, lastOpenSeq: 3, openRuns: map[string]openRun{}}
	failed := base
	failed.status, failed.errMsg, failed.reasons = "failed", "upload: scan failed (fetch_failed)", []string{"fetch_failed"}
	failed.checked = []string{"jvn", "nvd", "distro"}
	failed.skipped = []string{"jvn"}

	t.Run("no row", func(t *testing.T) {
		if _, ok := recordedStatus(scanResultRow{}, stale, now); ok {
			t.Fatal("no row must be unknown")
		}
	})
	t.Run("completed", func(t *testing.T) {
		d, ok := recordedStatus(base, stale, now)
		if !ok || d.State != ScanStateCompleted || d.Source != ScanStatusSourceRecorded || !d.LastScanAt.Equal(fin) ||
			!d.CheckedKnown || !slices.Equal(d.Checked, []string{"nvd", "jvn", "distro"}) || d.Run != "" || d.Version != "d7" {
			t.Fatalf("got %+v ok=%v", d, ok)
		}
	})
	t.Run("failed keeps reasons and coverage rules", func(t *testing.T) {
		d, ok := recordedStatus(failed, stale, now)
		if !ok || d.State != ScanStateFailed || d.Error != failed.errMsg || !slices.Equal(d.Reasons, []string{"fetch_failed"}) ||
			!slices.Equal(d.Skipped, []string{"jvn"}) {
			t.Fatalf("got %+v", d)
		}
		// normaliseCoverage: the failed marker names no source, so coverage
		// is unknown (as for a live answer).
		if d.CheckedKnown {
			t.Fatalf("checked of a failure naming no source must be unknown: %+v", d)
		}
	})
	t.Run("coverage not reported", func(t *testing.T) {
		r := base
		r.checked, r.checkedKnown = nil, false
		d, _ := recordedStatus(r, stale, now)
		if d.CheckedKnown || d.Checked != nil {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("an open run younger than a scan can run hides nothing: unknown", func(t *testing.T) {
		r := base
		r.openRuns = map[string]openRun{"9": {Start: now.Add(-time.Minute).UnixMilli(), Seq: 2}}
		if d, ok := recordedStatus(r, stale, now); ok {
			t.Fatalf("got %+v, want unknown", d)
		}
	})
	t.Run("a stale open run started after the result: interrupted", func(t *testing.T) {
		r := base
		st := now.Add(-2 * time.Hour)
		r.openRuns = map[string]openRun{"9": {Start: st.UnixMilli(), Seq: 6}}
		r.lastStarted, r.lastOpenSeq = st, 6
		d, ok := recordedStatus(r, stale, now)
		if !ok || d.State != ScanStateFailed || !slices.Equal(d.Reasons, []string{ScanReasonInterrupted}) ||
			d.Error != scanInterruptedMarker || d.LastScanAt.UnixMilli() != st.UnixMilli() || d.CheckedKnown || d.Skipped != nil {
			t.Fatalf("got %+v ok=%v", d, ok)
		}
	})
	// Codex R1 Medium-2: a run started within the clock slack after the
	// result, whose open was written after it, is a later run.
	t.Run("a stale open written after the result is later, however close its start", func(t *testing.T) {
		r := base
		st := fin.Add(2 * time.Second)
		r.openRuns = map[string]openRun{"9": {Start: st.UnixMilli(), Seq: 6}}
		r.lastStarted, r.lastOpenSeq = st, 6
		d, ok := recordedStatus(r, stale, now)
		if !ok || d.State != ScanStateFailed || !slices.Equal(d.Reasons, []string{ScanReasonInterrupted}) {
			t.Fatalf("got %+v ok=%v, want interrupted", d, ok)
		}
	})
	// Codex R3 High-2: an open whose Begin had not reached the shared status
	// may predate nothing: only a start clearly before the result covers it.
	t.Run("an unacked stale open is covered only by a start clearly before the result", func(t *testing.T) {
		r := base
		r.openRuns = map[string]openRun{"9": {Start: fin.Add(time.Second).UnixMilli(), Seq: 2, Unacked: true}}
		if d, ok := recordedStatus(r, stale, now); !ok || d.State != ScanStateFailed {
			t.Fatalf("got %+v ok=%v, want interrupted", d, ok)
		}
		r.openRuns = map[string]openRun{"9": {Start: fin.Add(-time.Hour).UnixMilli(), Seq: 2, Unacked: true}}
		if d, ok := recordedStatus(r, stale, now); !ok || d.State != ScanStateCompleted {
			t.Fatalf("got %+v ok=%v, want the result", d, ok)
		}
	})
	t.Run("a stale open written before the result and started before it is covered", func(t *testing.T) {
		r := base
		r.openRuns = map[string]openRun{"9": {Start: fin.Add(-time.Hour).UnixMilli(), Seq: 2}}
		d, ok := recordedStatus(r, stale, now)
		if !ok || d.State != ScanStateCompleted {
			t.Fatalf("got %+v ok=%v", d, ok)
		}
	})
	t.Run("a stale open written before the result but started well after it is later", func(t *testing.T) {
		r := base
		st := fin.Add(time.Hour)
		r.openRuns = map[string]openRun{"9": {Start: st.UnixMilli(), Seq: 2}}
		d, ok := recordedStatus(r, stale, now)
		if !ok || d.State != ScanStateFailed {
			t.Fatalf("got %+v ok=%v, want interrupted", d, ok)
		}
	})
	t.Run("a stale open run and no result: interrupted", func(t *testing.T) {
		st := now.Add(-2 * time.Hour)
		r := scanResultRow{found: true, openRuns: map[string]openRun{"9": {Start: st.UnixMilli(), Seq: 1}}, lastStarted: st, lastOpenSeq: 1, rev: 1}
		d, ok := recordedStatus(r, stale, now)
		if !ok || d.State != ScanStateFailed {
			t.Fatalf("got %+v ok=%v", d, ok)
		}
	})
	t.Run("a later start closed without a result: unknown (by sequence)", func(t *testing.T) {
		r := base
		r.lastOpenSeq = 6
		r.lastStarted = fin.Add(time.Second)
		if d, ok := recordedStatus(r, stale, now); ok {
			t.Fatalf("got %+v, want unknown", d)
		}
	})
	// Codex R4 Medium-1: the latest open's unacked mark survives its close.
	t.Run("a later unacked start closed without a result: unknown", func(t *testing.T) {
		r := base
		r.lastOpenSeq, r.lastOpenUnacked = 4, true // sequence covered, start within the slack
		r.lastStarted = fin.Add(time.Second)
		if d, ok := recordedStatus(r, stale, now); ok {
			t.Fatalf("got %+v, want unknown", d)
		}
	})
	t.Run("a later start closed without a result: unknown (by time)", func(t *testing.T) {
		r := base
		r.lastStarted = fin.Add(time.Hour)
		if d, ok := recordedStatus(r, stale, now); ok {
			t.Fatalf("got %+v, want unknown", d)
		}
	})
	t.Run("a start within the clock slack, written before the result, belongs to it", func(t *testing.T) {
		r := base
		r.lastStarted = fin.Add(recordClockSlack / 2)
		if _, ok := recordedStatus(r, stale, now); !ok {
			t.Fatal("want the recorded result")
		}
	})
	t.Run("only open runs, none stale: unknown", func(t *testing.T) {
		r := scanResultRow{found: true, openRuns: map[string]openRun{"9": {Start: now.UnixMilli(), Seq: 1}}, lastStarted: now, lastOpenSeq: 1}
		if _, ok := recordedStatus(r, stale, now); ok {
			t.Fatal("want unknown")
		}
	})
	t.Run("a bad status is unknown", func(t *testing.T) {
		r := base
		r.status = "running"
		if _, ok := recordedStatus(r, stale, now); ok {
			t.Fatal("want unknown")
		}
	})
}

func TestNewerOrSame(t *testing.T) {
	t0 := time.UnixMilli(1_000)
	cases := []struct {
		t         time.Time
		born, ver int64
		want      bool
	}{
		{t0.Add(time.Millisecond), 0, 0, true},
		{t0.Add(-time.Millisecond), 9, 9, false},
		{t0, 5, 4, false}, // same ms, older write of the same key: Codex R1 High-3
		{t0, 5, 6, true},
		{t0, 5, 5, true}, // the same result again
		{t0, 6, 1, true}, // a later incarnation of the key
		{t0, 4, 9, false},
	}
	// Codex R7 Medium-1: within one key incarnation the write counter is
	// causal; a Redis clock step back must not let an older write win.
	if newerOrSame(t0.Add(time.Second), 5, 4, t0, 5, 5) {
		t.Error("a lower write counter of the same key won on a later time")
	}
	if !newerOrSame(t0.Add(-time.Second), 5, 6, t0, 5, 5) {
		t.Error("a higher write counter of the same key lost on an earlier time")
	}
	for _, c := range cases {
		if c.born == 5 && c.t.Equal(t0) == false {
			continue // same incarnation, different time: covered above
		}
		if got := newerOrSame(c.t, c.born, c.ver, t0, 5, 5); got != c.want {
			t.Errorf("newerOrSame(%v, %d, %d) = %v, want %v", c.t, c.born, c.ver, got, c.want)
		}
	}
	if b, v := parseSharedVersion("s1700000000123456:42"); b != 1700000000123456 || v != 42 {
		t.Fatalf("parse: %d %d", b, v)
	}
	if b, v := parseSharedVersion("l7"); b != 0 || v != 0 {
		t.Fatalf("parse local: %d %d", b, v)
	}
}

// Codex R1 High-1: Attach returns once the run's start is recorded, so a
// reader that finds no live status sees the run.
func TestScanResult_AttachWaitsForTheOpen(t *testing.T) {
	tr, st := recordingTracker(t)
	st.openDelay = 50 * time.Millisecond
	tenant, id := uuid.New(), uuid.New()
	g := tr.Begin(id)
	tr.Attach(tenant, id, g)
	if r := st.get(id); r.openRuns[genString(g)].Start == 0 {
		t.Fatalf("Attach returned before the open was written: %+v", r)
	}
	// Bounded: a store that never answers in time does not hold the scan.
	tr.results.timing.attachWait = 20 * time.Millisecond
	st.openDelay = 300 * time.Millisecond
	g2 := tr.Begin(id)
	start := time.Now()
	tr.Attach(tenant, id, g2)
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("Attach waited %v", time.Since(start))
	}
	tr.results.waitIdle()
}

// Codex R1 High-4: a transient failure of the finishing write is retried, so
// a completed scan is not left open (and later read as interrupted).
func TestScanResult_FailedWritesAreRetried(t *testing.T) {
	tr, st := recordingTracker(t)
	tr.results.timing.retries = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	tenant, id := uuid.New(), uuid.New()
	g := tr.Begin(id)
	tr.Attach(tenant, id, g)
	st.mu.Lock()
	st.failNext = 2
	st.mu.Unlock()
	tr.Finish(id, g, nil, "")
	deadline := time.Now().Add(5 * time.Second)
	for r := st.get(id); r.status != "completed" || len(r.openRuns) != 0; r = st.get(id) {
		if time.Now().After(deadline) {
			t.Fatalf("after two failed attempts: %+v", r)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Codex R6 Medium-2: a write that fails does not hold the worker, so another
// scan's start is recorded (and its Attach returns) at once.
func TestScanResult_AFailedWriteDoesNotHoldOtherScans(t *testing.T) {
	tr, st := recordingTracker(t)
	tr.results.timing.retries = []time.Duration{time.Second}
	st.mu.Lock()
	st.failNext = 1 // A's open
	st.mu.Unlock()
	tenant := uuid.New()
	a, b := uuid.New(), uuid.New()
	tr.Attach(tenant, a, tr.Begin(a))
	gb := tr.Begin(b)
	start := time.Now()
	tr.Attach(tenant, b, gb)
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("B's Attach waited %v behind A's failed write", d)
	}
	if st.get(b).openRuns[genString(gb)].Start == 0 {
		t.Fatal("B's open was not written")
	}
}

func TestScanResult_RecordsTheTerminalResultWithoutRedis(t *testing.T) {
	tr, st := recordingTracker(t)
	tenant, id := uuid.New(), uuid.New()
	gen, run := tr.BeginRun(id)
	tr.Attach(tenant, id, gen)
	tr.FinishCoverage(id, gen, nil, "", ScanCoverage{Checked: []string{"nvd", "jvn", "distro"}, Reported: true})
	tr.results.waitIdle()

	// Live first: the in-memory entry answers, marked live.
	if d := tr.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateCompleted || d.Source != ScanStatusSourceLive || !d.LastScanAt.IsZero() || d.Run != run {
		t.Fatalf("live answer: %+v", d)
	}
	expire(tr, id)
	if d := tr.GetStatus(id); d.State != ScanStateUnknown || d.Source != "" {
		t.Fatalf("without the recorded result: %+v", d)
	}
	d := tr.GetStatusRecorded(context.Background(), tenant, id)
	if d.State != ScanStateCompleted || d.Source != ScanStatusSourceRecorded || d.LastScanAt.IsZero() ||
		!d.CheckedKnown || !slices.Equal(d.Checked, []string{"nvd", "jvn", "distro"}) || d.Run != "" {
		t.Fatalf("recorded answer: %+v", d)
	}
	if r := st.get(id); r.run != run || len(r.openRuns) != 0 {
		t.Fatalf("row: %+v", r)
	}
	// Another tenant sees nothing (the row is the SBOM's tenant's).
	if d := tr.GetStatusRecorded(context.Background(), uuid.New(), id); d.State != ScanStateUnknown {
		t.Fatalf("other tenant: %+v", d)
	}
}

func TestScanResult_ARunningScanIsNeverHiddenByTheRecordedRow(t *testing.T) {
	tr, _ := recordingTracker(t)
	tenant, id := uuid.New(), uuid.New()
	g1 := tr.Begin(id)
	tr.Attach(tenant, id, g1)
	tr.Finish(id, g1, nil, "")
	tr.results.waitIdle()
	expire(tr, id)
	g2 := tr.Begin(id)
	tr.Attach(tenant, id, g2)
	tr.results.waitIdle()
	if d := tr.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateRunning || d.Source != ScanStatusSourceLive {
		t.Fatalf("a running scan: %+v", d)
	}
	// The live entry lost while it runs (a restart of this process): its
	// open run makes the answer unknown, never the older completed.
	expire(tr, id)
	if d := tr.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateUnknown {
		t.Fatalf("an open run must not be hidden: %+v", d)
	}
}

func TestScanResult_OverlappingRunsRecordTheGroupOnce(t *testing.T) {
	tr, st := recordingTracker(t)
	tenant, id := uuid.New(), uuid.New()
	g1 := tr.Begin(id)
	tr.Attach(tenant, id, g1)
	g2 := tr.Begin(id)
	tr.Attach(tenant, id, g2)
	tr.FinishCoverage(id, g1, []string{"fetch_failed"}, "upload: scan failed (fetch_failed)", ScanCoverage{Checked: []string{"jvn", "distro"}, Reported: true})
	tr.FinishCoverage(id, g2, nil, "", ScanCoverage{Checked: []string{"nvd", "jvn", "distro"}, Reported: true})
	tr.results.waitIdle()
	want := []string{"open:" + genString(g1), "open:" + genString(g2), "close:" + genString(g1), "close:" + genString(g2) + ":failed"}
	if !slices.Equal(st.ops, want) {
		t.Fatalf("ops %v, want %v", st.ops, want)
	}
	expire(tr, id)
	d := tr.GetStatusRecorded(context.Background(), tenant, id)
	if d.State != ScanStateFailed || !slices.Equal(d.Reasons, []string{"fetch_failed"}) {
		t.Fatalf("got %+v", d)
	}
}

func TestScanResult_UnattachedRunsAndLegacyMarksRecordNothing(t *testing.T) {
	tr, st := recordingTracker(t)
	tenant, id := uuid.New(), uuid.New()
	g := tr.Begin(id)
	tr.Finish(id, g, nil, "")
	// Attach after the finish is ignored.
	tr.Attach(tenant, id, g)
	tr.results.waitIdle()
	if len(st.ops) != 0 {
		t.Fatalf("ops %v", st.ops)
	}
	// A legacy Mark* ends an attached run: its open run goes, no result.
	g2 := tr.Begin(id)
	tr.Attach(tenant, id, g2)
	tr.MarkFailed(id, "tenant context missing")
	tr.results.waitIdle()
	if want := []string{"open:" + genString(g2), "close:" + genString(g2)}; !slices.Equal(st.ops, want) {
		t.Fatalf("ops %v, want %v", st.ops, want)
	}
	if r := st.get(id); r.status != "" || len(r.openRuns) != 0 {
		t.Fatalf("row %+v", r)
	}
}

func TestScanResult_AStoreFailureNeverFailsTheScan(t *testing.T) {
	tr, st := recordingTracker(t)
	tr.results.timing.retries = []time.Duration{time.Millisecond}
	st.failAll = true
	tenant, id := uuid.New(), uuid.New()
	g := tr.Begin(id)
	tr.Attach(tenant, id, g)
	if !tr.Finish(id, g, nil, "") {
		t.Fatal("finish refused")
	}
	tr.results.waitIdle()
	if d := tr.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateCompleted {
		t.Fatalf("live: %+v", d)
	}
	expire(tr, id)
	if d := tr.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateUnknown {
		t.Fatalf("unreadable store: %+v", d)
	}
}

func TestScanResult_RecordLuaExtendsGet(t *testing.T) {
	if len(scanStatusRecordLua) <= len(scanStatusGetLua) {
		t.Fatal("record script must extend get")
	}
}

// Codex R2 Medium-1: a database that fails at once does not hold the scan:
// Attach waits for the open's first attempt only, not for its retries.
func TestScanResult_AttachDoesNotWaitForRetries(t *testing.T) {
	tr, st := recordingTracker(t)
	st.failAll = true
	tr.results.timing.retries = []time.Duration{time.Second}
	id := uuid.New()
	g := tr.Begin(id)
	start := time.Now()
	tr.Attach(uuid.New(), id, g)
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("Attach waited %v on a failing database", d)
	}
	tr.results.waitIdle()
}

// Codex R2 High-2: opens and closes are not dropped at the re-check cap.
func TestScanResult_OpensAndClosesSurviveABackedUpQueue(t *testing.T) {
	r := newScanRecorder(newMemResultStore(), time.Hour)
	r.mu.Lock()
	r.running = true // no worker: the queue only grows
	r.mu.Unlock()
	for i := 0; i < recordQueueCap; i++ {
		r.enqueue(recordOp{kind: recDrop, sbomID: uuid.New()})
	}
	r.enqueue(recordOp{kind: recOpen, sbomID: uuid.New()})
	r.enqueue(recordOp{kind: recClose, sbomID: uuid.New()})
	r.enqueue(recordOp{kind: recRecheck, sbomID: uuid.New()})
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) != recordQueueCap+2 || r.queue[len(r.queue)-1].kind != recClose {
		t.Fatalf("queue %d, last %v: want the open and close kept, the re-check dropped", len(r.queue), r.queue[len(r.queue)-1].kind)
	}
}

// Codex R2 Medium-2: a coalesced write closes at most maxRecClosed recorded
// runs (the merge stays bounded).
func TestScanResult_MergeRecClosedIsBounded(t *testing.T) {
	m := newMergeSet()
	tenant := uuid.New()
	for i := 0; i < maxRecClosed; i++ {
		if !m.addRecClosed(uint64(i+1), tenant) {
			t.Fatalf("refused at %d", i)
		}
	}
	if m.addRecClosed(1<<40, tenant) || len(m.recClosed) != maxRecClosed {
		t.Fatalf("not bounded: %d", len(m.recClosed))
	}
}

// Codex R3 High-1: an open whose every attempt failed is written again later
// (until its run closes), so a database outage at the run's start does not
// leave a running scan without a recorded start.
func TestScanResult_FailedOpensAreRetriedLater(t *testing.T) {
	tr, st := recordingTracker(t)
	tr.results.timing.retries, tr.results.timing.openRetryEvery = []time.Duration{time.Millisecond}, 20*time.Millisecond
	st.mu.Lock()
	st.failNext = 2 // the first attempt and its retry
	st.mu.Unlock()
	tenant, id := uuid.New(), uuid.New()
	g := tr.Begin(id)
	tr.Attach(tenant, id, g)
	deadline := time.Now().Add(5 * time.Second)
	for st.get(id).openRuns[genString(g)].Start == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the failed open was never written again")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A run that closes while its open is still pending is not opened later.
	st.mu.Lock()
	st.failNext = 2
	st.mu.Unlock()
	g2 := tr.Begin(id)
	tr.Attach(tenant, id, g2)
	tr.Finish(id, g2, nil, "")
	tr.Finish(id, g, nil, "")
	deadline = time.Now().Add(5 * time.Second)
	for {
		tr.results.mu.Lock()
		n := tr.results.deferredN
		tr.results.mu.Unlock()
		if r := st.get(id); n == 0 && len(r.openRuns) == 0 && r.status == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("open runs left: %+v (deferred %d)", st.get(id).openRuns, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Codex R4 High-2: a finishing write that fails through every attempt is
// written again once the database is back, so the newer result replaces
// the older recorded one.
func TestScanResult_FailedCloseIsWrittenLater(t *testing.T) {
	tr, st := recordingTracker(t)
	tr.results.timing.retries, tr.results.timing.openRetryEvery = []time.Duration{time.Millisecond}, 20*time.Millisecond
	tenant, id := uuid.New(), uuid.New()
	g1 := tr.Begin(id)
	tr.Attach(tenant, id, g1)
	tr.Finish(id, g1, nil, "")
	tr.results.waitIdle()
	first := st.get(id)
	g2 := tr.Begin(id)
	tr.Attach(tenant, id, g2)
	st.mu.Lock()
	st.failNext = 2
	st.mu.Unlock()
	tr.Finish(id, g2, []string{"fetch_failed"}, "nvd: scan failed (fetch_failed)")
	deadline := time.Now().Add(5 * time.Second)
	for st.get(id).status != "failed" {
		if time.Now().After(deadline) {
			t.Fatalf("the failed close was never written again: %+v (first %+v)", st.get(id), first)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if r := st.get(id); len(r.openRuns) != 0 {
		t.Fatalf("open runs left: %+v", r.openRuns)
	}
}

// Codex R4 High-1: a scan that begins while the recorded row is read wins
// over the row.
func TestScanResult_AScanBegunDuringTheReadWins(t *testing.T) {
	tr, st := recordingTracker(t)
	tenant, id := uuid.New(), uuid.New()
	g := tr.Begin(id)
	tr.Attach(tenant, id, g)
	tr.Finish(id, g, nil, "")
	tr.results.waitIdle()
	expire(tr, id)
	st.readHook = func() { st.readHook = nil; tr.Begin(id) }
	if d := tr.GetStatusRecorded(context.Background(), tenant, id); d.State != ScanStateRunning || d.Source != ScanStatusSourceLive {
		t.Fatalf("a scan begun during the read: %+v", d)
	}
}

// Codex R3 Medium-1: a re-check dropped at the queue cap ends its chain, so
// a later finish can start a new one.
func TestScanResult_DroppedRecheckEndsTheChain(t *testing.T) {
	r := newScanRecorder(newMemResultStore(), time.Hour)
	id := uuid.New()
	r.mu.Lock()
	r.running = true
	r.rechecking[id] = true
	r.mu.Unlock()
	for i := 0; i < recordQueueCap; i++ {
		r.enqueue(recordOp{kind: recDrop, sbomID: uuid.New()})
	}
	r.enqueue(recordOp{kind: recRecheck, sbomID: id})
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rechecking[id] {
		t.Fatal("the dropped re-check left its chain marked as scheduled")
	}
}

// Codex R3 Medium-2: a chain continues while the status reads running,
// however long; it ends after recordRecheckMaxErrs unreadable re-checks.
func TestScanResult_RecheckChainFollowsRunning(t *testing.T) {
	r := newScanRecorder(newMemResultStore(), time.Millisecond) // staleAfter long past
	r.timing.recheckEvery = time.Hour                           // scheduled, never fired in the test
	id := uuid.New()
	if !r.scheduleRecheck(recordOp{kind: recRecheck, sbomID: id, recheck: 100}, false) {
		t.Fatal("a chain that still reads running must continue")
	}
	if r.scheduleRecheck(recordOp{kind: recRecheck, sbomID: id, recheck: 100, errs: recordRecheckMaxErrs}, true) {
		t.Fatal("a chain that cannot read the status must end")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rechecking[id] {
		t.Fatal("ended chain still marked")
	}
}

// Codex R3 High-2: an open written before the run's Begin reached the shared
// status is marked unacked; one written after it is not.
func TestScanResult_OpenRecordsWhetherTheBeginLanded(t *testing.T) {
	slow := slowStore{memStore: newMemStore(), delay: 300 * time.Millisecond}
	a := trackerOn(slow, time.Hour)
	a.beginWait = time.Millisecond
	st := newMemResultStore()
	a.withResultStore(st)
	tenant, id := uuid.New(), uuid.New()
	g := a.Begin(id) // returns before the slow begin landed
	a.Attach(tenant, id, g)
	if o := st.get(id).openRuns[genString(g)]; o.Start == 0 || !o.Unacked {
		t.Fatalf("open before the Begin landed: %+v", o)
	}
	fast := trackerOn(newMemStore(), time.Hour)
	st2 := newMemResultStore()
	fast.withResultStore(st2)
	g2 := fast.Begin(id)
	fast.Attach(tenant, id, g2)
	if o := st2.get(id).openRuns[genString(g2)]; o.Start == 0 || o.Unacked {
		t.Fatalf("open after the Begin landed: %+v", o)
	}
}

// Codex R5 Medium-3: a re-check deferred behind a failed write ends its
// chain, so the replayed read-back can start a new one.
func TestScanResult_DeferredRecheckEndsTheChain(t *testing.T) {
	r := newScanRecorder(newMemResultStore(), time.Hour)
	id := uuid.New()
	r.mu.Lock()
	r.rechecking[id] = true
	r.mu.Unlock()
	r.deferOp(recordOp{kind: recRecheck, sbomID: id})
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rechecking[id] || r.deferred[id][0].kind != recClose {
		t.Fatalf("chain flag %v, deferred %+v", r.rechecking[id], r.deferred[id])
	}
}

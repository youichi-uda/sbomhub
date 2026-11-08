//go:build integration

// Package scheduler — M58: the full catalogue re-read (cve_reconcile.go).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M58Reconcile' ./internal/scheduler
package scheduler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const m58Layout = "2006-01-02T15:04:05.000"

type m58Record struct {
	id       string
	severity string
	score    float64
	modified time.Time
}

// m58NVD is a fake /cves/2.0 that honours lastModStartDate..lastModEndDate
// (inclusive) and startIndex, the two things the re-read depends on.
type m58NVD struct {
	mu      sync.Mutex
	records []m58Record
	// fail, when set, decides per request whether to answer 500.
	fail     func(start time.Time) bool
	requests []time.Time // window starts, in request order
}

func (f *m58NVD) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		start, err1 := time.Parse(m58Layout, q.Get("lastModStartDate"))
		end, err2 := time.Parse(m58Layout, q.Get("lastModEndDate"))
		if err1 != nil || err2 != nil {
			t.Errorf("m58: bad window %q..%q", q.Get("lastModStartDate"), q.Get("lastModEndDate"))
		}
		if end.Sub(start) > 120*24*time.Hour {
			http.Error(w, "window wider than 120 days", http.StatusNotFound)
			return
		}
		f.mu.Lock()
		f.requests = append(f.requests, start)
		fail := f.fail
		var in []m58Record
		for _, rec := range f.records {
			if !rec.modified.Before(start) && !rec.modified.After(end) {
				in = append(in, rec)
			}
		}
		f.mu.Unlock()
		if fail != nil && fail(start) {
			http.Error(w, "injected", http.StatusInternalServerError)
			return
		}
		idx, _ := strconv.Atoi(q.Get("startIndex"))
		size, _ := strconv.Atoi(q.Get("resultsPerPage"))
		page := []m58Record{}
		if idx < len(in) {
			hi := idx + size
			if hi > len(in) {
				hi = len(in)
			}
			page = in[idx:hi]
		}
		items := make([]string, 0, len(page))
		for _, rec := range page {
			items = append(items, fmt.Sprintf(`{"cve": {"id": %q, "published": "2026-01-01T00:00:00.000",
				"lastModified": %q, "descriptions": [{"lang": "en", "value": "re-read"}],
				"metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": %v, "baseSeverity": %q}}]},
				"configurations": []}}`, rec.id, rec.modified.Format(m58Layout), rec.score, rec.severity))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"resultsPerPage": %d, "startIndex": %d, "totalResults": %d, "vulnerabilities": [%s]}`,
			len(page), idx, len(in), strings.Join(items, ","))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *m58NVD) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// m58Job builds a sync job against the fake with the pass shortened to start
// in 2025 (5 windows to now instead of ~93) and no pacing.
func m58Job(appDB *sql.DB, url string) *CVESyncJob {
	j := NewCVESyncJob(appDB, repository.NewTenantRepository(appDB), "", 24*time.Hour, nil, url, false).
		WithCatalogueReconcile(30 * 24 * time.Hour)
	j.pageDelay = 0
	j.reconcileEpoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	return j
}

func m58State(t *testing.T, migDB *sql.DB) cveReconcileState {
	t.Helper()
	var raw string
	if err := migDB.QueryRow(`SELECT value FROM system_settings WHERE key = $1`, cveReconcileStateKey).Scan(&raw); err != nil {
		t.Fatalf("read reconcile state: %v", err)
	}
	var st cveReconcileState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("decode reconcile state %q: %v", raw, err)
	}
	return st
}

// m58Fresh protects the state row and removes it, so each test starts with
// no pass on record.
func m58Fresh(t *testing.T, migDB *sql.DB) {
	t.Helper()
	m55ProtectSetting(t, migDB, cveReconcileStateKey)
	m55ProtectWatermark(t, migDB)
	if _, err := migDB.Exec(`DELETE FROM system_settings WHERE key = $1`, cveReconcileStateKey); err != nil {
		t.Fatalf("clear reconcile state: %v", err)
	}
}

// TestM58Reconcile_RefreshesARowTheDeltaWindowNeverReaches is the reason the
// re-read exists. A row the catalogue holds, stale and undated (every row from
// before M57 is), whose CVE NVD last modified months ago: the delta sync's
// window does not contain the record, so it stays LOW; the re-read reaches it.
func TestM58Reconcile_RefreshesARowTheDeltaWindowNeverReaches(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	stale := m55CVEID(t)
	m55SeedLegacy(t, migDB, stale, "NVD")
	absent := m55CVEID(t)
	t.Cleanup(func() { _, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, absent) })
	modified := time.Date(2026, 5, 3, 4, 5, 6, 0, time.UTC)
	fake := &m58NVD{records: []m58Record{
		{id: stale, severity: "CRITICAL", score: 9.8, modified: modified},
		{id: absent, severity: "HIGH", score: 7.5, modified: modified},
	}}
	j := m58Job(appDB, fake.server(t).URL)

	// Control: the delta sync, watermark an hour ago, does not reach it.
	m55PinWatermark(t, migDB, time.Now().UTC().Add(-time.Hour))
	if err := j.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := m55Read(t, migDB, stale).severity; got != "LOW" {
		t.Fatalf("control: the delta sync changed the row to %q; the scenario needs it out of reach", got)
	}

	out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("reconcileCatalogue: %v", err)
	}
	if !out.Finished || out.Status != cveReconcileCompleted {
		t.Fatalf("outcome = %+v, want a finished, completed pass", out)
	}
	row := m55Read(t, migDB, stale)
	if row.severity != "CRITICAL" || !row.sourceModAt.Valid || !row.sourceModAt.Time.UTC().Equal(modified) {
		t.Errorf("after the re-read: %s dated %v, want CRITICAL dated %v", row.severity, row.sourceModAt.Time.UTC(), modified)
	}
	if row.epssScore.Float64 != 0.25 || !row.inKEV {
		t.Errorf("the re-read touched columns owned by the EPSS / KEV jobs: epss=%v in_kev=%v", row.epssScore, row.inKEV)
	}
	var n int
	if err := migDB.QueryRow(`SELECT count(*) FROM vulnerabilities WHERE cve_id = $1`, absent).Scan(&n); err != nil {
		t.Fatalf("count absent: %v", err)
	}
	if n != 0 {
		t.Errorf("the re-read inserted %s; it must be update-only, or one pass imports all of NVD", absent)
	}
	st := m58State(t, migDB)
	if st.PassStartedAt != nil || st.LastStatus != cveReconcileCompleted || st.LastWritten != 1 || st.LastRecords != 2 {
		t.Errorf("state after the pass = %+v, want no pass in progress, last_status completed, 2 records, 1 written", st)
	}
}

// TestM58Reconcile_ResumesAtTheWindowItStoppedIn: an interruption must not
// restart the pass from the epoch. The fake fails every window from 2026 on,
// once; the next invocation must not re-request a window before the cursor.
func TestM58Reconcile_ResumesAtTheWindowItStoppedIn(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	early, late := m55CVEID(t), m55CVEID(t)
	m55SeedLegacy(t, migDB, early, "NVD")
	m55SeedLegacy(t, migDB, late, "NVD")
	earlyMod := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	lateMod := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cut := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &m58NVD{records: []m58Record{
		{id: early, severity: "CRITICAL", score: 9.8, modified: earlyMod},
		{id: late, severity: "CRITICAL", score: 9.8, modified: lateMod},
	}}
	fake.fail = func(start time.Time) bool { return !start.Before(cut) }
	j := m58Job(appDB, fake.server(t).URL)

	if _, err := j.reconcileCatalogue(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("a pass whose window could not be read reported success")
	}
	st := m58State(t, migDB)
	if st.PassStartedAt == nil || st.Cursor == nil || st.Cursor.Before(cut.Add(-cveSyncMaxFetchSpan)) {
		t.Fatalf("state after the failure = %+v, want the pass in progress with the cursor at the failed window", st)
	}
	if st.LastStatus != "" {
		t.Errorf("last_status = %q after an incomplete pass, want none recorded", st.LastStatus)
	}
	if got := m55Read(t, migDB, early).severity; got != "CRITICAL" {
		t.Errorf("the window read before the failure was not applied: %q", got)
	}
	cursor := *st.Cursor

	fake.mu.Lock()
	fake.fail = nil
	fake.requests = nil
	fake.mu.Unlock()
	out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC())
	if err != nil || !out.Finished {
		t.Fatalf("resumed pass: outcome %+v, err %v", out, err)
	}
	fake.mu.Lock()
	for _, s := range fake.requests {
		if s.Before(cursor) {
			t.Errorf("the resumed pass re-read the window starting %s, before the stored cursor %s: it restarted "+
				"instead of resuming", s, cursor)
		}
	}
	fake.mu.Unlock()
	if got := m55Read(t, migDB, late).severity; got != "CRITICAL" {
		t.Errorf("the resumed pass did not reach the window that failed: %q", got)
	}
}

// TestM58Reconcile_TheTickBudgetPausesBetweenWindows: one invocation stops
// once its budget is spent, leaving the cursor for the next — which is what
// keeps a slow pass from holding up the next delta read.
func TestM58Reconcile_TheTickBudgetPausesBetweenWindows(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	fake := &m58NVD{}
	j := m58Job(appDB, fake.server(t).URL)
	j.reconcileBudget = time.Nanosecond

	out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC())
	if err != nil || out.Finished {
		t.Fatalf("outcome %+v err %v, want an unfinished pass and no error", out, err)
	}
	if n := fake.requestCount(); n != 1 {
		t.Errorf("requests = %d, want exactly one window before the budget stopped it", n)
	}
	if st := m58State(t, migDB); st.PassStartedAt == nil || st.LastStatus != "" {
		t.Errorf("state = %+v, want the pass still in progress", st)
	}
}

// TestM58Reconcile_DueOnlyAtTheInterval: a finished pass is not repeated until
// the interval has passed, and a zero interval disables the re-read.
func TestM58Reconcile_DueOnlyAtTheInterval(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	fake := &m58NVD{}
	j := m58Job(appDB, fake.server(t).URL)

	disabled := m58Job(appDB, fake.server(t).URL).WithCatalogueReconcile(0)
	if err := disabled.reconcileIfDue(context.Background()); err != nil {
		t.Fatalf("disabled reconcileIfDue: %v", err)
	}
	if n := fake.requestCount(); n != 0 {
		t.Fatalf("a disabled re-read issued %d requests", n)
	}

	if err := j.reconcileIfDue(context.Background()); err != nil {
		t.Fatalf("first reconcileIfDue: %v", err)
	}
	first := fake.requestCount()
	if first == 0 {
		t.Fatal("a never-run re-read was not due")
	}
	if err := j.reconcileIfDue(context.Background()); err != nil {
		t.Fatalf("second reconcileIfDue: %v", err)
	}
	if n := fake.requestCount(); n != first {
		t.Errorf("a re-read finished moments ago ran again (%d more requests)", n-first)
	}

	// Age the finished pass past the interval.
	st := m58State(t, migDB)
	old := time.Now().UTC().Add(-31 * 24 * time.Hour)
	st.LastFinishedAt = &old
	if err := j.saveReconcileState(context.Background(), st); err != nil {
		t.Fatalf("age state: %v", err)
	}
	if err := j.reconcileIfDue(context.Background()); err != nil {
		t.Fatalf("third reconcileIfDue: %v", err)
	}
	if n := fake.requestCount(); n == first {
		t.Error("a re-read older than its interval was not run")
	}
}

// TestM58Reconcile_AWriteFailureIsNotReportedAsCompleted: a row whose refresh
// the database refuses (severity longer than varchar(20) — an upstream
// vocabulary change) must leave the pass marked as having failures, with the
// CVE named, not "completed".
func TestM58Reconcile_AWriteFailureIsNotReportedAsCompleted(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	bad, good := m55CVEID(t), m55CVEID(t)
	m55SeedLegacy(t, migDB, bad, "NVD")
	m55SeedLegacy(t, migDB, good, "NVD")
	mod := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	fake := &m58NVD{records: []m58Record{
		{id: bad, severity: strings.Repeat("X", 30), score: 9.8, modified: mod},
		{id: good, severity: "CRITICAL", score: 9.8, modified: mod},
	}}
	j := m58Job(appDB, fake.server(t).URL)

	out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("reconcileCatalogue: %v", err)
	}
	if out.Status != cveReconcileCompletedWithWriteErrors {
		t.Errorf("status = %q, want %q", out.Status, cveReconcileCompletedWithWriteErrors)
	}
	st := m58State(t, migDB)
	if st.LastWriteFailures != 1 || len(st.LastFailedSample) != 1 || st.LastFailedSample[0] != bad {
		t.Errorf("state = %+v, want one write failure naming %s", st, bad)
	}
	if got := m55Read(t, migDB, good).severity; got != "CRITICAL" {
		t.Errorf("one refused row stopped the others: %s is %q", good, got)
	}
}

// TestM58Reconcile_AnInconsistentStoredPassStartsOver: a stored pass whose
// start is in the future (clock jump, hand edit) would never be finished
// against its own bound; it must be replaced, not obeyed.
func TestM58Reconcile_AnInconsistentStoredPassStartsOver(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	fake := &m58NVD{}
	j := m58Job(appDB, fake.server(t).URL)
	future := time.Now().UTC().Add(400 * 24 * time.Hour)
	if err := j.saveReconcileState(context.Background(), cveReconcileState{PassStartedAt: &future, Cursor: &future}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC())
	if err != nil || !out.Finished {
		t.Fatalf("outcome %+v err %v, want a fresh pass that finishes", out, err)
	}
	if fake.requestCount() == 0 {
		t.Error("no window was read")
	}

	// And an unparseable value.
	if _, err := migDB.Exec(`UPDATE system_settings SET value = 'not json' WHERE key = $1`, cveReconcileStateKey); err != nil {
		t.Fatalf("corrupt state: %v", err)
	}
	if out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC()); err != nil || !out.Finished {
		t.Fatalf("after an unparseable state: outcome %+v err %v", out, err)
	}
}

// TestM58Reconcile_DoesNotJoinACallersTransaction: the catalogue is global; a
// pass handed a tx-bearing context must still write on its own connection.
func TestM58Reconcile_DoesNotJoinACallersTransaction(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	stale := m55CVEID(t)
	m55SeedLegacy(t, migDB, stale, "NVD")
	fake := &m58NVD{records: []m58Record{{id: stale, severity: "CRITICAL", score: 9.8,
		modified: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}}}
	j := m58Job(appDB, fake.server(t).URL)

	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := j.reconcileCatalogue(database.WithTx(context.Background(), tx), time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("reconcileCatalogue: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := m55Read(t, migDB, stale).severity; got != "CRITICAL" {
		t.Errorf("severity = %q after the caller's tx rolled back: the re-read joined it", got)
	}
}

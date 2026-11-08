package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/database"
)

// Codex M62 R1 High-1: a sweep whose ONLY interrupted work was a CPE walk the
// deadline cut short (every item answered, so Unscanned == 0) must still say
// the deadline fired — not merely "truncated".
func TestM62R1_DeadlineInsideTheLastWalkIsReportedAsDeadline(t *testing.T) {
	pager := &cannedNVDPager{total: 7059}
	inner := pager.start(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st, _ := strconv.Atoi(r.URL.Query().Get("startIndex")); st >= 398 {
			<-r.Context().Done() // the third page never answers
			return
		}
		n.Add(1)
		resp, err := http.Get(inner.URL + "?" + r.URL.RawQuery)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer resp.Body.Close()
		buf := make([]byte, 1<<20)
		for {
			k, rerr := resp.Body.Read(buf)
			_, _ = w.Write(buf[:k])
			if rerr != nil {
				break
			}
		}
	}))
	t.Cleanup(srv.Close)

	svc := NewNVDService(nil, nil, "k", srv.URL, false)
	svc.paceInterval = time.Millisecond
	item := m60PlainItem(t)
	items := map[nvdComponentKey]*nvdWorkItem{item.key: &item}
	ctx, cancel := WithScanDeadline(context.Background(), 700*time.Millisecond)
	defer cancel()
	rep := svc.fetchComponents(ctx, items, (&m62Collect{}).on)
	if rep.Processed != 1 || rep.Unscanned != 0 || rep.TruncatedComponents != 1 {
		t.Fatalf("processed=%d unscanned=%d truncated=%d, want 1/0/1", rep.Processed, rep.Unscanned, rep.TruncatedComponents)
	}
	if got := ScanReasons(rep.incompleteErr()); !slices.Equal(got, []string{ScanReasonDeadlineExceeded, ScanReasonTruncated}) {
		t.Errorf("reasons = %v, want [deadline_exceeded truncated]", got)
	}
}

// Codex M62 R1 High-1: a deadline that has fired before the READ phase
// finishes is reported as the deadline, not as a generic scan_error.
func TestM62R1_DeadlineDuringTheReadPhaseIsReportedAsDeadline(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := WithScanDeadline(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	ctx = WithScanScope(ctx, db, uuid.New())

	_, nerr := NewNVDService(nil, nil, "", "http://127.0.0.1:1", false).ScanComponentsWithReport(ctx, uuid.New())
	if !errors.Is(nerr, ErrScanDeadlineExceeded) {
		t.Errorf("NVD read under an expired deadline: %v, want ErrScanDeadlineExceeded", nerr)
	}
	_, jerr := NewJVNService(nil, nil, "http://127.0.0.1:1", false).ScanComponentsReport(ctx, uuid.New())
	if !errors.Is(jerr, ErrScanDeadlineExceeded) {
		t.Errorf("JVN read under an expired deadline: %v, want ErrScanDeadlineExceeded", jerr)
	}
}

// Codex M62 R1 Medium-3: WithScanScope must not hide a transaction the caller
// is holding — the scanner refuses it, and issues no HTTP request.
func TestM62R1_WithScanScopeDoesNotLaunderATransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)

	txCtx := database.WithTx(context.Background(), tx)
	ctx := WithScanScope(txCtx, db, uuid.New())
	if _, err := NewNVDService(nil, nil, "", srv.URL, false).ScanComponentsWithReport(ctx, uuid.New()); !errors.Is(err, ErrScanInTransaction) {
		t.Errorf("NVD: err = %v, want ErrScanInTransaction", err)
	}
	if _, err := NewJVNService(nil, nil, srv.URL, false).ScanComponentsReport(ctx, uuid.New()); !errors.Is(err, ErrScanInTransaction) {
		t.Errorf("JVN: err = %v, want ErrScanInTransaction", err)
	}
	if hits.Load() != 0 {
		t.Errorf("%d HTTP request(s) were issued from inside a transaction", hits.Load())
	}
}

// Codex M62 R1 Low-4: offline mode does not exempt a caller from the scope
// contract.
func TestM62R1_OfflineStillRequiresScope(t *testing.T) {
	if _, err := NewNVDService(nil, nil, "", "", true).ScanComponentsWithReport(context.Background(), uuid.New()); !errors.Is(err, ErrScanNoScope) {
		t.Errorf("NVD offline without scope: %v, want ErrScanNoScope", err)
	}
	if _, err := NewJVNService(nil, nil, "", true).ScanComponentsReport(context.Background(), uuid.New()); !errors.Is(err, ErrScanNoScope) {
		t.Errorf("JVN offline without scope: %v, want ErrScanNoScope", err)
	}
}

// Codex M62 R1 High-2: a scan that is no longer the current one for its SBOM
// cannot overwrite the current one's state.
func TestM62R1_TrackerIgnoresAStaleRunsOutcome(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	a := tr.Begin(id)
	b := tr.Begin(id)
	tr.Finish(id, a, nil, "")
	if st, _ := tr.Get(id); st != ScanStateRunning {
		t.Fatalf("a superseded run's completion changed the state to %s while the current run is still going", st)
	}
	tr.Finish(id, b, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
	st, msg, reasons := tr.GetDetail(id)
	if st != ScanStateFailed || msg != "nvd: scan failed (fetch_failed)" || !slices.Equal(reasons, []string{ScanReasonFetchFailed}) {
		t.Fatalf("current run's outcome not recorded: %s %q %v", st, msg, reasons)
	}
	tr.Finish(id, a, nil, "")
	if st, _ := tr.Get(id); st != ScanStateFailed {
		t.Errorf("a stale completion overwrote the current run's failure (%s)", st)
	}
}

package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

func TestSummariseVulnerabilities(t *testing.T) {
	tests := []struct {
		name string
		in   []model.Vulnerability
		want VulnerabilitySummaryCount
	}{
		{
			name: "empty",
			in:   nil,
			want: VulnerabilitySummaryCount{Total: 0},
		},
		{
			name: "mixed severities",
			in: []model.Vulnerability{
				{Severity: "CRITICAL"},
				{Severity: "critical"},
				{Severity: "High"},
				{Severity: "MEDIUM"},
				{Severity: "low"},
				{Severity: "LOW"},
				{Severity: ""},
				{Severity: "informational"},
			},
			want: VulnerabilitySummaryCount{
				Critical: 2, High: 1, Medium: 1, Low: 2, Unknown: 2, Total: 8,
			},
		},
		{
			// Codex R1 fix: KEV is counted orthogonally to the CVSS bucket
			// (a KEV-listed CVE also lands in CRITICAL/HIGH/etc). The CLI's
			// `--fail-on kev` reads this bucket via scan-status; without it
			// the threshold silently never trips.
			name: "kev orthogonal to severity",
			in: []model.Vulnerability{
				{Severity: "CRITICAL", InKEV: true},
				{Severity: "HIGH", InKEV: true},
				{Severity: "MEDIUM", InKEV: false},
				{Severity: "LOW"},
			},
			want: VulnerabilitySummaryCount{
				Critical: 1, High: 1, Medium: 1, Low: 1, KEV: 2, Total: 4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summariseVulnerabilities(tt.in)
			if got != tt.want {
				t.Errorf("summariseVulnerabilities() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// stubScanner is a componentScanner used in runScan tests. It records every
// call and returns whatever error was configured. ScanComponents is the
// only method on the componentScanner interface, so this stub fully
// satisfies the contract the background scan goroutine consumes.
type stubScanner struct {
	err    error
	called int
	gotID  uuid.UUID
}

func (s *stubScanner) ScanComponents(_ context.Context, sbomID uuid.UUID) error {
	s.called++
	s.gotID = sbomID
	return s.err
}

// TestRunScan_NVDFailureMarksFailed locks in the Codex R15 P2 contract:
// when the NVD scanner returns an error, the background scan must call
// ScanTracker.MarkFailed rather than MarkCompleted. The previous code
// path swallowed the error and reported "completed, 0 vulnerabilities" —
// which made `sbomhub scan --fail-on critical` always exit 0 during NVD
// outages and CI was silently misled.
func TestRunScan_NVDFailureMarksFailed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	nvd := &stubScanner{err: errors.New("nvd timeout")}
	tracker := service.NewScanTracker()

	h := &SbomHandler{
		nvdService:  nvd,
		jvnService:  nil,
		scanTracker: tracker,
		db:          db,
	}

	sbomID := uuid.New()
	tenantID := uuid.New()
	tracker.MarkRunning(sbomID)
	h.runScan(context.Background(), sbomID, tenantID)

	if nvd.called != 1 {
		t.Fatalf("nvd.called = %d, want 1", nvd.called)
	}
	if nvd.gotID != sbomID {
		t.Fatalf("nvd received sbomID = %s, want %s", nvd.gotID, sbomID)
	}

	state, errMsg := tracker.Get(sbomID)
	if state != service.ScanStateFailed {
		t.Fatalf("tracker state = %q, want %q", state, service.ScanStateFailed)
	}
	if errMsg == "" || !contains(errMsg, "nvd timeout") {
		t.Fatalf("tracker errMsg = %q, want it to mention 'nvd timeout'", errMsg)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRunScan_JVNFailureMarksFailed mirrors the NVD test for the JVN
// scanner — same contract, distinct code path inside runScan.
func TestRunScan_JVNFailureMarksFailed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	jvn := &stubScanner{err: errors.New("jvn 503")}
	tracker := service.NewScanTracker()

	h := &SbomHandler{
		nvdService:  nil,
		jvnService:  jvn,
		scanTracker: tracker,
		db:          db,
	}

	sbomID := uuid.New()
	tracker.MarkRunning(sbomID)
	h.runScan(context.Background(), sbomID, uuid.New())

	state, errMsg := tracker.Get(sbomID)
	if state != service.ScanStateFailed {
		t.Fatalf("tracker state = %q, want %q", state, service.ScanStateFailed)
	}
	if !contains(errMsg, "jvn 503") {
		t.Fatalf("tracker errMsg = %q, want it to mention 'jvn 503'", errMsg)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRunScan_BothFailuresAggregated verifies that when both scanners fail
// the tracker error string mentions both — the operator needs to see every
// failure, not just the first, to diagnose a wider outage.
func TestRunScan_BothFailuresAggregated(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	nvd := &stubScanner{err: errors.New("nvd boom")}
	jvn := &stubScanner{err: errors.New("jvn boom")}
	tracker := service.NewScanTracker()

	h := &SbomHandler{
		nvdService:  nvd,
		jvnService:  jvn,
		scanTracker: tracker,
		db:          db,
	}

	sbomID := uuid.New()
	tracker.MarkRunning(sbomID)
	h.runScan(context.Background(), sbomID, uuid.New())

	state, errMsg := tracker.Get(sbomID)
	if state != service.ScanStateFailed {
		t.Fatalf("tracker state = %q, want %q", state, service.ScanStateFailed)
	}
	if !contains(errMsg, "nvd boom") || !contains(errMsg, "jvn boom") {
		t.Fatalf("tracker errMsg = %q, want both 'nvd boom' and 'jvn boom'", errMsg)
	}
}

// TestRunScan_SuccessMarksCompleted is the positive-path counterpart: when
// every configured scanner returns nil and the tx commits, the tracker is
// moved to Completed — that's what the CLI keys `--fail-on` evaluation on.
func TestRunScan_SuccessMarksCompleted(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	nvd := &stubScanner{}
	jvn := &stubScanner{}
	tracker := service.NewScanTracker()

	h := &SbomHandler{
		nvdService:  nvd,
		jvnService:  jvn,
		scanTracker: tracker,
		db:          db,
	}

	sbomID := uuid.New()
	tracker.MarkRunning(sbomID)
	h.runScan(context.Background(), sbomID, uuid.New())

	state, _ := tracker.Get(sbomID)
	if state != service.ScanStateCompleted {
		t.Fatalf("tracker state = %q, want %q", state, service.ScanStateCompleted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRunScan_TxBeginFailureMarksFailed verifies that a tx-level failure
// (begin / set_config / commit) is also surfaced via MarkFailed instead of
// silently leaving the tracker in "running" forever. Without this branch,
// a transient DB hiccup at scan kickoff would block the CLI poller until
// --wait-timeout fired.
func TestRunScan_TxBeginFailureMarksFailed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin().WillReturnError(errors.New("db down"))

	tracker := service.NewScanTracker()
	h := &SbomHandler{
		nvdService:  &stubScanner{},
		jvnService:  &stubScanner{},
		scanTracker: tracker,
		db:          db,
	}

	sbomID := uuid.New()
	tracker.MarkRunning(sbomID)
	h.runScan(context.Background(), sbomID, uuid.New())

	state, errMsg := tracker.Get(sbomID)
	if state != service.ScanStateFailed {
		t.Fatalf("tracker state = %q, want %q", state, service.ScanStateFailed)
	}
	if !contains(errMsg, "tx:") || !contains(errMsg, "db down") {
		t.Fatalf("tracker errMsg = %q, want 'tx:' + 'db down'", errMsg)
	}
}

// contains is a tiny strings.Contains shim kept local to this file to
// avoid importing the stdlib `strings` package just for one helper —
// keeps the test file's import list aligned with what production code in
// sbom.go already pulls in.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

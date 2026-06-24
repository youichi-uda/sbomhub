package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
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

// ----------------------------------------------------------------------------
// F26 regression — GetVulnerabilities must paginate
// ----------------------------------------------------------------------------
//
// Codex M1 round 16 #F26 (high / DoS): the F20 fix exposed
// GET /api/v1/projects/:id/vulnerabilities to read-scoped API keys,
// but the handler returned the entire matched-vulns slice with no
// pagination. The CLI then io.ReadAll'd the entire response — a
// read-only API-key holder targeting a project with thousands of
// matched vulns could repeatedly mount a single-request DoS against
// both server and CLI memory. The handler now clamps `?limit=` /
// `?offset=` (default 100, max 500) and passes them through to
// SbomService.GetVulnerabilitiesPaginated. Response shape is
// preserved (`[]Vulnerability` — no envelope) so the Web UI's fetch
// path is unaffected; the CLI is updated to page through (separate
// sbomhub-cli commit).
//
// The tests below pin:
//   F26.1 (TestSBOMHandler_GetVulnerabilities_DefaultLimit_F26):
//         no `?limit=` → SQL LIMIT 100 OFFSET 0.
//   F26.2 (TestSBOMHandler_GetVulnerabilities_LimitClamp_F26):
//         `?limit=1000` → 400 (rejected, same posture as F24).
//   F26.3 (TestSBOMHandler_GetVulnerabilities_OffsetPagination_F26):
//         `?limit=200&offset=100` → SQL LIMIT 200 OFFSET 100.

// driveGetVulnerabilities wires the handler with a sqlmock-backed
// service, dispatches the request with the supplied query string, and
// returns the recorder. The first sqlmock expectation MUST cover the
// initial SbomRepository.GetLatest call; the second covers the
// paginated vulnerabilities SELECT (or no second expectation when the
// handler short-circuits on the limit clamp).
func driveGetVulnerabilities(t *testing.T, mock sqlmock.Sqlmock, h *SbomHandler, projectID uuid.UUID, query string) *httptest.ResponseRecorder {
	t.Helper()
	_ = mock // sqlmock expectations are set by callers; suppress unused-param

	e := echo.New()
	url := "/api/v1/projects/" + projectID.String() + "/vulnerabilities"
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())

	if err := h.GetVulnerabilities(c); err != nil {
		t.Fatalf("GetVulnerabilities returned unexpected error: %v", err)
	}
	return rec
}

// TestSBOMHandler_GetVulnerabilities_DefaultLimit_F26 pins the default
// pagination contract: no `?limit=` query param → SQL LIMIT 100.
func TestSBOMHandler_GetVulnerabilities_DefaultLimit_F26(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	projectID := uuid.New()
	sbomID := uuid.New()
	now := time.Now()

	// CountVulnerabilities (added by #F28) runs first: GetLatest +
	// COUNT(*) — both required so the handler can emit X-Total-Count.
	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", []byte(`{}`), now))
	mock.ExpectQuery(`SELECT COUNT\(DISTINCT v.id\) FROM vulnerabilities v`).
		WithArgs(sbomID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// GetVulnerabilitiesPaginated repeats GetLatest then runs the
	// page query.
	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", []byte(`{}`), now))

	// The paginated query MUST be invoked with LIMIT=VulnsDefaultLimit
	// (100) OFFSET=0 — the load-bearing assertion is `WithArgs(sbomID,
	// 100, 0)` which would fail if the handler dropped the clamp or
	// silently chose a different default.
	mock.ExpectQuery(`FROM vulnerabilities v.*LIMIT \$2 OFFSET \$3`).
		WithArgs(sbomID, VulnsDefaultLimit, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cve_id", "description", "severity", "cvss_score", "source",
			"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
			"published_at", "updated_at",
		}))

	sbomService := service.NewSbomService(
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewSbomHandler(db, sbomService, nil, nil, nil)

	rec := driveGetVulnerabilities(t, mock, h, projectID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("F26: default limit path must succeed, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestSBOMHandler_GetVulnerabilities_LimitClamp_F26 pins the upper
// bound: `?limit=1000` MUST be rejected with 400 BEFORE the
// repository runs. Same posture as F24's ListDrafts clamp — silent
// truncation would hide DoS probes from telemetry.
func TestSBOMHandler_GetVulnerabilities_LimitClamp_F26(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	projectID := uuid.New()

	// No mock expectations — the handler MUST reject before any SQL
	// runs. If a regression slips and the query fires, sqlmock's
	// "unexpected query" will trip alongside the response-code check.

	sbomService := service.NewSbomService(
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewSbomHandler(db, sbomService, nil, nil, nil)

	rec := driveGetVulnerabilities(t, mock, h, projectID, "limit=1000")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F26: limit=1000 must return 400, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if !contains(rec.Body.String(), "limit exceeds maximum") {
		t.Errorf("F26: expected 'limit exceeds maximum' body, got %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestSBOMHandler_GetVulnerabilities_OffsetPagination_F26 pins the
// happy-path pagination: `?limit=200&offset=100` flows through as SQL
// LIMIT 200 OFFSET 100 (sub-MaxLimit so allowed). Response stays a
// bare JSON array — no envelope — so the Web UI's existing fetch path
// is preserved.
func TestSBOMHandler_GetVulnerabilities_OffsetPagination_F26(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	projectID := uuid.New()
	sbomID := uuid.New()
	now := time.Now()

	// CountVulnerabilities (#F28) runs first: GetLatest + COUNT(*).
	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", []byte(`{}`), now))
	mock.ExpectQuery(`SELECT COUNT\(DISTINCT v.id\) FROM vulnerabilities v`).
		WithArgs(sbomID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(350))

	// GetVulnerabilitiesPaginated repeats GetLatest then runs the page.
	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", []byte(`{}`), now))

	// `WithArgs(sbomID, 200, 100)` is the load-bearing assertion — a
	// regression that dropped the offset (e.g. forgot to parse it) or
	// transposed the args would surface here as a sqlmock mismatch.
	mock.ExpectQuery(`FROM vulnerabilities v.*LIMIT \$2 OFFSET \$3`).
		WithArgs(sbomID, 200, 100).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cve_id", "description", "severity", "cvss_score", "source",
			"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
			"published_at", "updated_at",
		}).AddRow(uuid.New(), "CVE-2024-1", "desc", "HIGH", 7.5, "NVD",
			false, nil, nil, nil, now, now))

	sbomService := service.NewSbomService(
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewSbomHandler(db, sbomService, nil, nil, nil)

	rec := driveGetVulnerabilities(t, mock, h, projectID, "limit=200&offset=100")
	if rec.Code != http.StatusOK {
		t.Fatalf("F26: limit=200 offset=100 must succeed, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	// Response stays a bare JSON array (no envelope) so the Web UI's
	// fetch path is preserved.
	var out []model.Vulnerability
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("F26: response body must be a JSON array, got error %v (body=%s)",
			err, rec.Body.String())
	}
	if len(out) != 1 {
		t.Errorf("F26: expected 1 vuln in response, got %d", len(out))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ----------------------------------------------------------------------------
// F27 regression — GetVulnerabilities must reject offsets above the cap
// ----------------------------------------------------------------------------
//
// Codex M1 round 17 #F27 (high / correctness + DoS): the #F26 fix
// added a limit clamp but left `?offset=` unbounded. A request such
// as `?offset=2147483647` would force the DB to skip billions of
// rows on its way to producing zero output — a cheap DoS primitive
// reachable via the same read-scoped API-key path that motivated
// #F26. The handler now rejects offsets > VulnsMaxOffset (10000) at
// the same boundary as the limit clamp.

// TestSBOMHandler_GetVulnerabilities_OffsetOverflow_F27 pins the
// upper bound: a 32-bit overflow probe must be rejected with 400
// BEFORE any SQL runs. If a regression slips, sqlmock's
// "unexpected query" trip would fire alongside the response-code
// check because no GetLatest / SELECT expectations are registered.
func TestSBOMHandler_GetVulnerabilities_OffsetOverflow_F27(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	projectID := uuid.New()

	sbomService := service.NewSbomService(
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewSbomHandler(db, sbomService, nil, nil, nil)

	rec := driveGetVulnerabilities(t, mock, h, projectID, "offset=2147483647")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F27: offset=2147483647 must return 400, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if !contains(rec.Body.String(), "offset exceeds maximum") {
		t.Errorf("F27: expected 'offset exceeds maximum' body, got %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestSBOMHandler_GetVulnerabilities_OffsetAtCap_F27 pins the
// boundary: an offset exactly at VulnsMaxOffset must succeed (off-
// by-one trap — a `>=` vs `>` typo in the clamp would silently
// reject the boundary value and break legitimate deep-pagination).
func TestSBOMHandler_GetVulnerabilities_OffsetAtCap_F27(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	projectID := uuid.New()
	sbomID := uuid.New()
	now := time.Now()

	// GetLatest is called twice: once by CountVulnerabilities (for
	// the X-Total-Count header) and once by GetVulnerabilitiesPaginated.
	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", []byte(`{}`), now))
	mock.ExpectQuery(`SELECT COUNT\(DISTINCT v.id\) FROM vulnerabilities v`).
		WithArgs(sbomID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", []byte(`{}`), now))
	mock.ExpectQuery(`FROM vulnerabilities v.*LIMIT \$2 OFFSET \$3`).
		WithArgs(sbomID, VulnsDefaultLimit, VulnsMaxOffset).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cve_id", "description", "severity", "cvss_score", "source",
			"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
			"published_at", "updated_at",
		}))

	sbomService := service.NewSbomService(
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewSbomHandler(db, sbomService, nil, nil, nil)

	rec := driveGetVulnerabilities(t, mock, h, projectID, "offset=10000")
	if rec.Code != http.StatusOK {
		t.Fatalf("F27: offset=%d (boundary) must succeed, got %d (body=%s)",
			VulnsMaxOffset, rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ----------------------------------------------------------------------------
// F28 regression — GetVulnerabilities must emit X-Total-Count
// ----------------------------------------------------------------------------
//
// Codex M1 round 17 #F28 (high / data integrity): the Web UI used
// to fetch /api/v1/projects/:id/vulnerabilities without pagination
// and treat the default 100-row response as the complete set —
// tab counts and workflow actions for vulns past row 100 were
// silently truncated. The handler now emits X-Total-Count as a
// response header so the UI can render the authoritative count and
// trip a warning banner when total > visible page. CORS must
// expose this header (see ExposeHeaders in cmd/server/main.go) for
// the cross-origin fetch to pick it up.
func TestSBOMHandler_GetVulnerabilities_TotalCountHeader_F28(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	projectID := uuid.New()
	sbomID := uuid.New()
	now := time.Now()

	// CountVulnerabilities calls GetLatest + COUNT(*).
	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", []byte(`{}`), now))
	mock.ExpectQuery(`SELECT COUNT\(DISTINCT v.id\) FROM vulnerabilities v`).
		WithArgs(sbomID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(742))

	// GetVulnerabilitiesPaginated repeats GetLatest then runs the
	// page query.
	mock.ExpectQuery(`SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "format", "version", "raw_data", "created_at",
		}).AddRow(sbomID, projectID, "cyclonedx", "1.5", []byte(`{}`), now))
	mock.ExpectQuery(`FROM vulnerabilities v.*LIMIT \$2 OFFSET \$3`).
		WithArgs(sbomID, VulnsDefaultLimit, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cve_id", "description", "severity", "cvss_score", "source",
			"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
			"published_at", "updated_at",
		}))

	sbomService := service.NewSbomService(
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewSbomHandler(db, sbomService, nil, nil, nil)

	rec := driveGetVulnerabilities(t, mock, h, projectID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("F28: expected 200, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Total-Count"); got != "742" {
		t.Errorf("F28: expected X-Total-Count=742, got %q", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
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

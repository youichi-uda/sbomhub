package handler

// SBOMHUB_JVN=off (2026-11): the scan routes skip JVN, say so in
// scan-status `skipped_sources`, and do not fail the scan for it. With JVN on
// nothing changes.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	appmw "github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// switchScanner is a componentScanner that can be switched off the way
// service.JVNService is (SBOMHUB_JVN=off).
type switchScanner struct {
	stubScanner
	disabled bool
}

func (s *switchScanner) ScanDisabled() bool { return s.disabled }

func TestJVNSwitch_RunSBOMScanSkipsADisabledSource(t *testing.T) {
	nvd := &stubScanner{}
	jvn := &switchScanner{disabled: true}
	out := runSBOMScan(context.Background(), nil, uuid.New(), uuid.New(), time.Minute, []scanStep{
		{source: "nvd", scanner: nvd},
		{source: "jvn", scanner: jvn},
	})
	if jvn.called != 0 {
		t.Errorf("the disabled scanner was called %d time(s)", jvn.called)
	}
	if nvd.called != 1 {
		t.Errorf("nvd called %d time(s), want 1", nvd.called)
	}
	if out.failed() || len(out.reasons) != 0 {
		t.Errorf("a skipped source failed the scan: %+v", out)
	}
	if !slices.Equal(out.skipped, []string{"jvn"}) {
		t.Errorf("skipped = %v, want [jvn]", out.skipped)
	}
}

// With the switch on, the scanner runs and nothing is reported skipped:
// the default behaviour is unchanged.
func TestJVNSwitch_RunSBOMScanEnabledIsUnchanged(t *testing.T) {
	jvn := &switchScanner{disabled: false}
	out := runSBOMScan(context.Background(), nil, uuid.New(), uuid.New(), time.Minute,
		[]scanStep{{source: "jvn", scanner: jvn}})
	if jvn.called != 1 || len(out.skipped) != 0 || out.failed() {
		t.Errorf("called=%d out=%+v, want the scanner run and nothing skipped", jvn.called, out)
	}
}

// A skipped source does not hide another source's failure.
func TestJVNSwitch_SkipDoesNotMaskAFailure(t *testing.T) {
	nvd := &stubScanner{err: service.ErrScanFetchFailed}
	out := runSBOMScan(context.Background(), nil, uuid.New(), uuid.New(), time.Minute, []scanStep{
		{source: "nvd", scanner: nvd},
		{source: "jvn", scanner: &switchScanner{disabled: true}},
	})
	if !out.failed() || !slices.Equal(out.reasons, []string{service.ScanReasonFetchFailed}) ||
		!slices.Equal(out.skipped, []string{"jvn"}) {
		t.Errorf("out = %+v, want failed (fetch_failed) with jvn skipped", out)
	}
}

func TestJVNSwitch_RecordScanOutcomeCarriesSkipped(t *testing.T) {
	tr := service.NewScanTracker()
	id := uuid.New()
	recordScanOutcome(tr, id, tr.Begin(id), scanOutcome{skipped: []string{"jvn"}})
	if st := tr.GetStatus(id); st.State != service.ScanStateCompleted || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Errorf("status = %+v, want completed with skipped [jvn]", st)
	}
}

// scanStatusBody drives ScanStatus for a tracker in a given state.
func scanStatusBody(t *testing.T, tracker *service.ScanTracker, projectID, sbomID uuid.UUID) map[string]any {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherFunc(func(string, string) error { return nil })))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("in project").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("sbom").WillReturnRows(
		sqlmock.NewRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"}).
			AddRow(sbomID.String(), projectID.String(), "cyclonedx", "1.5", []byte(`{}`), time.Now()))
	mock.ExpectQuery("vulns").WillReturnRows(sqlmock.NewRows([]string{"x"}))

	h := &SbomHandler{
		sbomService: service.NewSbomService(repository.NewSbomRepository(db), repository.NewComponentRepository(db)),
		scanTracker: tracker,
	}
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	c.SetParamNames("id", "sbom_id")
	c.SetParamValues(projectID.String(), sbomID.String())
	c.Set(appmw.ContextKeyTenantID, uuid.New())
	if err := h.ScanStatus(c); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	return body
}

func TestJVNSwitch_ScanStatusReportsSkippedSources(t *testing.T) {
	tracker := service.NewScanTracker()
	projectID, sbomID := uuid.New(), uuid.New()
	tracker.FinishSkipped(sbomID, tracker.Begin(sbomID), nil, "", []string{"jvn"})

	body := scanStatusBody(t, tracker, projectID, sbomID)
	if body["status"] != "completed" {
		t.Fatalf("status = %v, want completed", body["status"])
	}
	got, _ := body["skipped_sources"].([]any)
	if len(got) != 1 || got[0] != "jvn" {
		t.Errorf("skipped_sources = %v, want [jvn]", body["skipped_sources"])
	}
	if _, ok := body["reasons"]; ok {
		t.Errorf("a completed scan carries reasons: %v", body["reasons"])
	}
}

// Nothing skipped: the field is absent, so the response is byte-for-byte
// what it was before SBOMHUB_JVN existed.
func TestJVNSwitch_ScanStatusOmitsSkippedSourcesWhenNoneSkipped(t *testing.T) {
	tracker := service.NewScanTracker()
	projectID, sbomID := uuid.New(), uuid.New()
	tracker.Finish(sbomID, tracker.Begin(sbomID), nil, "")

	body := scanStatusBody(t, tracker, projectID, sbomID)
	if _, ok := body["skipped_sources"]; ok {
		t.Errorf("skipped_sources present with nothing skipped: %v", body)
	}
}

// The manual route with sources=jvn while JVN is off: 202 as usual (the
// GitHub Action requires 202 by number), the scan skips JVN and reads
// completed with skipped_sources [jvn].
func TestJVNSwitch_ManualJVNOnlyScanIsSkippedNotRefused(t *testing.T) {
	jvn := &switchScanner{disabled: true}
	tracker := service.NewScanTracker()
	h := &VulnerabilityHandler{jvnService: jvn, scanTracker: tracker}
	id := uuid.New()
	h.runScanRun(context.Background(), id, uuid.New(), "jvn", tracker.Begin(id))
	if jvn.called != 0 {
		t.Errorf("JVN scanner called %d time(s) while disabled", jvn.called)
	}
	if st := tracker.GetStatus(id); st.State != service.ScanStateCompleted || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Errorf("status = %+v, want completed with skipped [jvn]", st)
	}
}

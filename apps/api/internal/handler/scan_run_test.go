package handler

// scan-status `scan_run` (2026-11, service/scan_run.go): a rescan of the same
// SBOM that starts and finishes between a client's two status reads, leaving
// every other field as it was, must be detectable. Before scan_run the two
// answers were identical.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	appmw "github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/service"
)

func TestScanRun_RescanBetweenReadsWithIdenticalFieldsIsDetectable(t *testing.T) {
	tracker := service.NewScanTracker()
	projectID, sbomID := uuid.New(), uuid.New()
	tracker.Finish(sbomID, tracker.Begin(sbomID), nil, "")
	first := scanStatusBody(t, tracker, projectID, sbomID)

	// A whole rescan between the two reads, with the same outcome.
	tracker.Finish(sbomID, tracker.Begin(sbomID), nil, "")
	second := scanStatusBody(t, tracker, projectID, sbomID)

	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) == string(b) {
		t.Fatalf("a rescan between the reads left the answer unchanged: %s", a)
	}
	r1, _ := first["scan_run"].(string)
	r2, _ := second["scan_run"].(string)
	if r1 == "" || r2 == "" || r1 == r2 {
		t.Fatalf("scan_run %q then %q, want two different non-empty values", r1, r2)
	}
	// Nothing else differs.
	delete(first, "scan_run")
	delete(second, "scan_run")
	a, _ = json.Marshal(first)
	b, _ = json.Marshal(second)
	if string(a) != string(b) {
		t.Fatalf("other fields differ (the test needs identical fields): %s vs %s", a, b)
	}
}

func TestScanRun_StableWithoutActivityAndAcrossAnOverlappingRun(t *testing.T) {
	tracker := service.NewScanTracker()
	projectID, sbomID := uuid.New(), uuid.New()
	g1 := tracker.Begin(sbomID)
	running := scanStatusBody(t, tracker, projectID, sbomID)
	// A run that joins the active group keeps its scan run.
	g2 := tracker.Begin(sbomID)
	tracker.Finish(sbomID, g1, nil, "")
	tracker.Finish(sbomID, g2, nil, "")
	done := scanStatusBody(t, tracker, projectID, sbomID)
	again := scanStatusBody(t, tracker, projectID, sbomID)
	if running["status"] != "running" || done["status"] != "completed" {
		t.Fatalf("states %v, %v", running["status"], done["status"])
	}
	if running["scan_run"] == nil || running["scan_run"] != done["scan_run"] || done["scan_run"] != again["scan_run"] {
		t.Fatalf("scan_run running %v, completed %v, again %v: want one value", running["scan_run"], done["scan_run"], again["scan_run"])
	}
}

// Legacy Mark* writes and an unknown status carry no scan_run (absent =
// unknown).
func TestScanRun_AbsentWhenUnknown(t *testing.T) {
	tracker := service.NewScanTracker()
	projectID, sbomID := uuid.New(), uuid.New()
	if body := scanStatusBody(t, tracker, projectID, sbomID); body["status"] != "unknown" || body["scan_run"] != nil {
		t.Fatalf("no entry: %v", body)
	}
	tracker.Finish(sbomID, tracker.Begin(sbomID), nil, "")
	tracker.MarkCompleted(sbomID)
	if body := scanStatusBody(t, tracker, projectID, sbomID); body["status"] != "completed" || body["scan_run"] != nil {
		t.Fatalf("after a legacy MarkCompleted: %v", body)
	}
}

// The manual scan's 202 names the scan run that scan-status then reports for
// the scan containing this run.
func TestScanRun_ManualScan202CarriesTheScanRun(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tracker := service.NewScanTracker()
	scanner := &m62BlockingScanner{release: make(chan struct{})}
	h := &VulnerabilityHandler{db: db, sbomScope: m62InScope{}, nvdService: scanner}
	h.WithScanTracking(tracker, time.Minute)

	projectID, sbomID := uuid.New(), uuid.New()
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/api/v1/projects/"+projectID.String()+"/scan?sbom_id="+sbomID.String()+"&sources=nvd", nil), rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(appmw.ContextKeyTenantID, uuid.New())
	if err := h.Scan(c); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	run, _ := body["scan_run"].(string)
	if run == "" {
		t.Fatalf("202 without scan_run: %v", body)
	}
	if d := tracker.GetStatus(sbomID); d.State != service.ScanStateRunning || d.Run != run {
		t.Fatalf("status after 202: %+v, want running with scan_run %q", d, run)
	}
	close(scanner.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		d := tracker.GetStatus(sbomID)
		if d.State == service.ScanStateCompleted {
			if d.Run != run {
				t.Fatalf("terminal scan_run %q, want the 202's %q", d.Run, run)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("never completed: %+v", d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

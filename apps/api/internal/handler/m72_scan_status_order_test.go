package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// Codex M72 R12 High-1: scan-status reads the scan state BEFORE the counts.
// A scan publishes its terminal state only after its findings committed, so
// counts read after a terminal state include them. Read the other way round,
// a scan finishing during the count query answered "completed" with the
// pre-commit counts, and `sbomhub scan --fail-on` trusted them.
func TestM72ScanStatus_StateIsReadBeforeTheCounts(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherFunc(func(string, string) error { return nil })))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	projectID, sbomID := uuid.New(), uuid.New()
	// The count query is slow; the scan finishes while it runs.
	mock.ExpectQuery("sbom").WillDelayFor(300 * time.Millisecond).WillReturnRows(
		sqlmock.NewRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"}).
			AddRow(sbomID.String(), projectID.String(), "cyclonedx", "1.5", []byte(`{}`), time.Now()))
	mock.ExpectQuery("vulns").WillReturnRows(sqlmock.NewRows([]string{"x"}))

	tracker := service.NewScanTracker()
	gen := tracker.Begin(sbomID)
	go func() {
		time.Sleep(100 * time.Millisecond)
		tracker.Finish(sbomID, gen, nil, "") // findings committed, then completed
	}()

	h := &SbomHandler{
		sbomService: service.NewSbomService(repository.NewSbomRepository(db), repository.NewComponentRepository(db)),
		scanTracker: tracker,
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "sbom_id")
	c.SetParamValues(projectID.String(), sbomID.String())
	if err := h.ScanStatus(c); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if body["status"] != "running" {
		t.Fatalf("status %v with counts read before the scan's findings: the state must be read first", body["status"])
	}
}

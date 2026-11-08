package handler

import (
	"context"
	"encoding/json"
	"fmt"
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

// M62: the manual scan route reports its outcome — a PARTIAL failure
// included — through the same scan-status tracker as the upload path. Before
// M62 it logged and told no one.

type m62InScope struct{}

func (m62InScope) SbomInProject(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (bool, error) {
	return true, nil
}

// blockingScanner holds the scan until released, so the test can observe
// the "running" state the 202 promises.
type m62BlockingScanner struct {
	release chan struct{}
	err     error
}

func (b *m62BlockingScanner) ScanComponents(ctx context.Context, _ uuid.UUID) error {
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return b.err
}

func TestM62ManualScan_PartialFailureIsReportedLikeTheScheduler(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tracker := service.NewScanTracker()
	scanner := &m62BlockingScanner{
		release: make(chan struct{}),
		// What NVDService returns for 3 of 10 lookups failing since M62.
		err: fmt.Errorf("nvd: 3 of 10 component lookup(s) failed: %w", service.ErrScanFetchFailed),
	}
	h := &VulnerabilityHandler{db: db, sbomScope: m62InScope{}, nvdService: scanner}
	h.WithScanTracking(tracker, time.Minute)

	projectID, sbomID, tenantID := uuid.New(), uuid.New(), uuid.New()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/"+projectID.String()+"/scan?sbom_id="+sbomID.String()+"&sources=nvd", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(appmw.ContextKeyTenantID, tenantID)

	if err := h.Scan(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// Backward compatible: the pre-M62 fields are all still there.
	for _, k := range []string{"message", "project_id", "sbom_id", "sources", "status_url"} {
		if _, ok := body[k]; !ok {
			t.Errorf("202 body lacks %q: %v", k, body)
		}
	}
	if st, _ := tracker.Get(sbomID); st != service.ScanStateRunning {
		t.Errorf("state right after 202 = %s, want running", st)
	}

	close(scanner.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, msg, reasons := tracker.GetDetail(sbomID)
		if st == service.ScanStateFailed {
			if msg != "nvd: scan failed (fetch_failed)" || len(reasons) != 1 || reasons[0] != service.ScanReasonFetchFailed {
				t.Errorf("failed with %q %v, want generic marker + [fetch_failed]", msg, reasons)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("manual scan never reached failed (state %s)", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestM62ManualScan_SuccessIsReportedCompleted(t *testing.T) {
	tracker := service.NewScanTracker()
	h := (&VulnerabilityHandler{nvdService: &stubScanner{}, jvnService: &stubScanner{}}).WithScanTracking(tracker, time.Minute)
	id := uuid.New()
	tracker.MarkRunning(id)
	h.runScan(context.Background(), id, uuid.New(), "nvd,jvn")
	if st, _ := tracker.Get(id); st != service.ScanStateCompleted {
		t.Errorf("state = %s, want completed", st)
	}
}

// The scan-status response carries the reasons (additively).
func TestM62ScanStatusResponse_ReasonsAreAdditive(t *testing.T) {
	b, err := json.Marshal(ScanStatusResponse{Status: "completed"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["reasons"]; ok {
		t.Errorf("a completed status carries `reasons`: %s", b)
	}
	b, _ = json.Marshal(ScanStatusResponse{Status: "failed", Error: "nvd: scan failed (deadline_exceeded)", Reasons: []string{"deadline_exceeded"}})
	_ = json.Unmarshal(b, &m)
	if _, ok := m["reasons"]; !ok {
		t.Errorf("a failed status lacks `reasons`: %s", b)
	}
}

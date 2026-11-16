package handler

// Scan coverage (2026-11): scan-status says, for a terminal scan, which
// sources were actually checked (checked_sources) and which made no request
// (skipped_sources: offline mode, SBOMHUB_JVN=off, a ?sources= subset, no
// scanner), and the 202 of POST .../scan says up front which sources the run
// will skip. A source is never reported checked when its step made no
// request.

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
	"github.com/sbomhub/sbomhub/internal/service"
)

// offlineStub is a scanner in offline mode: like the real services, its sweep
// would "succeed" without a request.
type offlineStub struct {
	stubScanner
	offline bool
}

func (s *offlineStub) ScanOffline() bool { return s.offline }

func allSteps(nvd, jvn, distro componentScanner) []scanStep {
	return []scanStep{
		{source: service.ScanSourceNVD, scanner: nvd},
		{source: service.ScanSourceJVN, scanner: jvn},
		{source: service.ScanSourceDistro, scanner: distro},
	}
}

func TestScanCoverage_OfflineChecksNothing(t *testing.T) {
	nvd, jvn, distro := &offlineStub{offline: true}, &offlineStub{offline: true}, &offlineStub{offline: true}
	out := runSBOMScan(context.Background(), nil, uuid.New(), uuid.New(), time.Minute, allSteps(nvd, jvn, distro))
	if out.failed() {
		t.Fatalf("offline failed the scan: %+v", out)
	}
	if nvd.called+jvn.called+distro.called != 0 {
		t.Errorf("offline scanners were called: %d %d %d", nvd.called, jvn.called, distro.called)
	}
	if len(out.checked) != 0 || out.checked == nil {
		t.Errorf("checked = %#v, want [] (reported, nothing checked)", out.checked)
	}
	if !slices.Equal(out.skipped, []string{"nvd", "jvn", "distro"}) {
		t.Errorf("skipped = %v, want [nvd jvn distro]", out.skipped)
	}
}

func TestScanCoverage_DefaultChecksEverySource(t *testing.T) {
	out := runSBOMScan(context.Background(), nil, uuid.New(), uuid.New(), time.Minute,
		allSteps(&offlineStub{}, &switchScanner{}, &stubScanner{}))
	if out.failed() || len(out.skipped) != 0 || !slices.Equal(out.checked, []string{"nvd", "jvn", "distro"}) {
		t.Errorf("out = %+v, want checked [nvd jvn distro], nothing skipped", out)
	}
}

// A failed source is neither checked nor skipped: it is in the markers.
func TestScanCoverage_FailedSourceIsNeither(t *testing.T) {
	out := runSBOMScan(context.Background(), nil, uuid.New(), uuid.New(), time.Minute,
		allSteps(&stubScanner{}, &stubScanner{err: service.ErrScanSourceUnavailable}, &stubScanner{}))
	if !out.failed() || !slices.Equal(out.checked, []string{"nvd", "distro"}) || len(out.skipped) != 0 {
		t.Errorf("out = %+v, want failed, checked [nvd distro], nothing skipped", out)
	}
}

// No slot: nothing was checked, the skips are still named.
func TestScanCoverage_SlotFailureChecksNothing(t *testing.T) {
	withConcurrency(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := runSBOMScan(ctx, nil, uuid.New(), uuid.New(), time.Minute,
		allSteps(&stubScanner{}, &switchScanner{disabled: true}, &stubScanner{}))
	if !out.failed() || out.checked == nil || len(out.checked) != 0 || !slices.Equal(out.skipped, []string{"jvn"}) {
		t.Errorf("out = %+v, want failed, checked [], skipped [jvn]", out)
	}
}

// The steps' scanners a given handler would build, for the 202 and the run.
func manualHandler(nvd, jvn, distro componentScanner) *VulnerabilityHandler {
	return &VulnerabilityHandler{nvdService: nvd, jvnService: jvn, distroService: distro}
}

func TestScanCoverage_ManualSubsetSkipsTheOthers(t *testing.T) {
	for _, tc := range []struct {
		sources          string
		checked, skipped []string
	}{
		{"nvd", []string{"nvd", "distro"}, []string{"jvn"}},
		{"jvn", []string{"jvn", "distro"}, []string{"nvd"}},
		{"nvd,jvn", []string{"nvd", "jvn", "distro"}, nil},
	} {
		tracker := service.NewScanTracker()
		h := manualHandler(&stubScanner{}, &switchScanner{}, &stubScanner{})
		h.scanTracker = tracker
		id := uuid.New()
		h.runScanRun(context.Background(), id, uuid.New(), tc.sources, tracker.Begin(id))
		st := tracker.GetStatus(id)
		if st.State != service.ScanStateCompleted || !st.CheckedKnown ||
			!slices.Equal(st.Checked, tc.checked) || !slices.Equal(st.Skipped, tc.skipped) {
			t.Errorf("sources=%s: %+v, want checked %v skipped %v", tc.sources, st, tc.checked, tc.skipped)
		}
	}
}

func scanStatusJSON(t *testing.T, tracker *service.ScanTracker, sbomID uuid.UUID) map[string]any {
	t.Helper()
	return scanStatusBody(t, tracker, uuid.New(), sbomID)
}

func TestScanCoverage_ScanStatusPresenceRules(t *testing.T) {
	t.Run("offline: checked_sources is [] and every source skipped", func(t *testing.T) {
		tr := service.NewScanTracker()
		id := uuid.New()
		tr.FinishCoverage(id, tr.Begin(id), nil, "", service.ScanCoverage{Checked: []string{}, Skipped: []string{"distro", "nvd", "jvn"}, Reported: true})
		body := scanStatusJSON(t, tr, id)
		c, ok := body["checked_sources"].([]any)
		if !ok || len(c) != 0 {
			t.Errorf("checked_sources = %#v, want []", body["checked_sources"])
		}
		s, _ := body["skipped_sources"].([]any)
		if len(s) != 3 || s[0] != "nvd" || s[1] != "jvn" || s[2] != "distro" {
			t.Errorf("skipped_sources = %v, want [nvd jvn distro] in that order", body["skipped_sources"])
		}
	})
	t.Run("full: checked_sources lists all, skipped_sources absent", func(t *testing.T) {
		tr := service.NewScanTracker()
		id := uuid.New()
		tr.FinishCoverage(id, tr.Begin(id), nil, "", service.ScanCoverage{Checked: []string{"distro", "jvn", "nvd"}, Reported: true})
		body := scanStatusJSON(t, tr, id)
		c, _ := body["checked_sources"].([]any)
		if len(c) != 3 || c[0] != "nvd" || c[1] != "jvn" || c[2] != "distro" {
			t.Errorf("checked_sources = %v", body["checked_sources"])
		}
		if _, ok := body["skipped_sources"]; ok {
			t.Errorf("skipped_sources present: %v", body)
		}
	})
	t.Run("failed: the failed source is in neither", func(t *testing.T) {
		tr := service.NewScanTracker()
		id := uuid.New()
		tr.FinishCoverage(id, tr.Begin(id), []string{service.ScanReasonFetchFailed}, "jvn: scan failed (fetch_failed)",
			service.ScanCoverage{Checked: []string{"nvd", "distro"}, Reported: true})
		body := scanStatusJSON(t, tr, id)
		c, _ := body["checked_sources"].([]any)
		if body["status"] != "failed" || len(c) != 2 || c[0] != "nvd" || c[1] != "distro" {
			t.Errorf("body = %v", body)
		}
	})
	t.Run("legacy finish: checked_sources absent (unknown, not none)", func(t *testing.T) {
		tr := service.NewScanTracker()
		id := uuid.New()
		tr.Finish(id, tr.Begin(id), nil, "")
		if body := scanStatusJSON(t, tr, id); body["checked_sources"] != nil {
			t.Errorf("checked_sources present for a scan that reported no coverage: %v", body)
		}
		if _, ok := scanStatusJSON(t, tr, id)["checked_sources"]; ok {
			t.Error("checked_sources key present")
		}
	})
	t.Run("running: absent", func(t *testing.T) {
		tr := service.NewScanTracker()
		id := uuid.New()
		tr.Begin(id)
		if _, ok := scanStatusJSON(t, tr, id)["checked_sources"]; ok {
			t.Error("checked_sources on a running scan")
		}
	})
}

// scan202 drives POST .../scan and returns the 202 body.
func scan202(t *testing.T, h *VulnerabilityHandler, sources string) map[string]any {
	t.Helper()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h.db, h.sbomScope = db, m62InScope{}
	if h.scanTracker == nil {
		h.WithScanTracking(service.NewScanTracker(), time.Minute)
	}
	projectID, sbomID := uuid.New(), uuid.New()
	url := "/api/v1/projects/" + projectID.String() + "/scan?sbom_id=" + sbomID.String()
	if sources != "" {
		url += "&sources=" + sources
	}
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, url, nil), rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(appmw.ContextKeyTenantID, uuid.New())
	if err := h.Scan(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// Let the run finish before the db closes.
	waitTerminal(t, h.scanTracker, sbomID)
	return body
}

func waitTerminal(t *testing.T, tr *service.ScanTracker, id uuid.UUID) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := tr.Get(id); st == service.ScanStateCompleted || st == service.ScanStateFailed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("scan did not finish")
}

func skipped202(body map[string]any) []string {
	raw, ok := body["skipped_sources"].([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, v := range raw {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func TestScanCoverage_202NamesTheSkippedSources(t *testing.T) {
	for _, tc := range []struct {
		name    string
		h       *VulnerabilityHandler
		sources string
		want    []string
	}{
		{"default, all on", manualHandler(&stubScanner{}, &switchScanner{}, &stubScanner{}), "", nil},
		{"sources=nvd", manualHandler(&stubScanner{}, &switchScanner{}, &stubScanner{}), "nvd", []string{"jvn"}},
		{"SBOMHUB_JVN=off", manualHandler(&stubScanner{}, &switchScanner{disabled: true}, &stubScanner{}), "", []string{"jvn"}},
		{"offline", manualHandler(&offlineStub{offline: true}, &offlineStub{offline: true}, &offlineStub{offline: true}), "", []string{"nvd", "jvn", "distro"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := scan202(t, tc.h, tc.sources)
			got := skipped202(body)
			if !slices.Equal(got, tc.want) {
				t.Errorf("202 skipped_sources = %v, want %v (body %v)", got, tc.want, body)
			}
			if tc.want == nil {
				if _, ok := body["skipped_sources"]; ok {
					t.Errorf("202 carries skipped_sources with nothing skipped: %v", body)
				}
			}
			// Consistent with what scan-status reports for the run.
			var sbomID uuid.UUID
			if s, _ := body["sbom_id"].(string); s != "" {
				sbomID = uuid.MustParse(s)
			}
			if st := tc.h.scanTracker.GetStatus(sbomID); !slices.Equal(st.Skipped, tc.want) {
				t.Errorf("scan-status skipped = %v, 202 said %v", st.Skipped, tc.want)
			}
		})
	}
}

// Codex coverage R3 Medium: NewSbomHandler with unconfigured (nil) NVD / JVN
// services must not hand typed-nil pointers to the scan, where the coverage
// checks would call methods on them; the sources read as skipped.
func TestScanCoverage_UploadWithNilServicesSkipsThem(t *testing.T) {
	tr := service.NewScanTracker()
	h := NewSbomHandler(nil, nil, nil, nil, tr)
	id := uuid.New()
	h.runScanRun(context.Background(), id, uuid.New(), tr.Begin(id))
	st := tr.GetStatus(id)
	if st.State != service.ScanStateCompleted || !st.CheckedKnown || len(st.Checked) != 0 ||
		!slices.Equal(st.Skipped, []string{"nvd", "jvn", "distro"}) {
		t.Fatalf("status %+v", st)
	}
}

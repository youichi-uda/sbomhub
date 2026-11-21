package handler

// 2026-11 (migration 071): the upload 201 names the scan-status URL and the
// scan run; scan-status says where its answer comes from. The recorded
// (PostgreSQL) answers are tested against a real database in
// scan_result_integration_test.go.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

func TestUploadResponse_KeepsEveryFieldAndAddsStatusURLAndScanRun(t *testing.T) {
	projectID, sbomID, tenantID := uuid.New(), uuid.New(), uuid.New()
	sbom := &model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", Version: "1.5",
		RawData: []byte(`{"secret":1}`), CreatedAt: time.Date(2026, 11, 21, 1, 2, 3, 0, time.UTC)}

	before, _ := json.Marshal(sbom)
	var old map[string]any
	_ = json.Unmarshal(before, &old)

	for _, run := range []string{"", "0123456789abcdef0123456789abcdef"} {
		b, err := json.Marshal(newUploadResponse(sbom, projectID, run))
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		for k, v := range old {
			if got[k] != v {
				t.Fatalf("field %q = %v, want %v (body %s)", k, got[k], v, b)
			}
		}
		if want := "/api/v1/projects/" + projectID.String() + "/sboms/" + sbomID.String() + "/scan-status"; got["status_url"] != want {
			t.Fatalf("status_url = %v, want %s", got["status_url"], want)
		}
		if run == "" {
			if _, ok := got["scan_run"]; ok {
				t.Fatalf("unknown scan_run must be absent: %s", b)
			}
		} else if got["scan_run"] != run {
			t.Fatalf("scan_run = %v, want %s", got["scan_run"], run)
		}
		if _, ok := got["raw_data"]; ok || len(got) != len(old)+map[bool]int{true: 1, false: 2}[run == ""] {
			t.Fatalf("unexpected fields: %s", b)
		}
	}
}

func TestScanStatus_LiveAnswersSaySoAndUnknownHasNoSource(t *testing.T) {
	tracker := service.NewScanTracker()
	projectID, sbomID := uuid.New(), uuid.New()
	if body := scanStatusBody(t, tracker, projectID, sbomID); body["status"] != "unknown" || body["source"] != nil || body["last_scan_at"] != nil {
		t.Fatalf("unknown: %v", body)
	}
	g := tracker.Begin(sbomID)
	if body := scanStatusBody(t, tracker, projectID, sbomID); body["status"] != "running" || body["source"] != "live" || body["last_scan_at"] != nil {
		t.Fatalf("running: %v", body)
	}
	tracker.Finish(sbomID, g, nil, "")
	if body := scanStatusBody(t, tracker, projectID, sbomID); body["status"] != "completed" || body["source"] != "live" || body["last_scan_at"] != nil {
		t.Fatalf("completed: %v", body)
	}
}

// Codex R1 Medium-1: last_scan_at keeps the recorded milliseconds, so two
// recorded results within one second are different answers.
func TestFormatLastScanAt_KeepsMilliseconds(t *testing.T) {
	a := time.Date(2026, 11, 21, 1, 2, 3, 120_000_000, time.FixedZone("JST", 9*3600))
	b := a.Add(5 * time.Millisecond)
	if got := formatLastScanAt(a); got != "2026-11-20T16:02:03.120Z" {
		t.Fatalf("formatLastScanAt = %q", got)
	}
	if formatLastScanAt(a) == formatLastScanAt(b) {
		t.Fatal("results 5ms apart must not format alike")
	}
	if _, err := time.Parse(time.RFC3339, formatLastScanAt(a)); err != nil {
		t.Fatalf("not RFC 3339: %v", err)
	}
}

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service/meti/criteria"
)

// The override note limit is "1-4096 characters" (the 400 says so, and the
// web form caps the note at 2000 characters), but the check counted BYTES:
// a 2000-character Japanese rationale (6000 bytes in UTF-8) was refused with
// "must be 1-4096 characters". The limit is now counted in characters.
func TestMetiHandler_Override_NoteLimitCountsCharactersNotBytes(t *testing.T) {
	cases := []struct {
		name string
		note string
		want int
	}{
		{"2000 Japanese chars (the web form's own cap)", strings.Repeat("理", 2000), http.StatusOK},
		{"4096 Japanese chars", strings.Repeat("理", MaxMetiOverrideNoteLen), http.StatusOK},
		{"4097 Japanese chars", strings.Repeat("理", MaxMetiOverrideNoteLen+1), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newMetiHarness()
			h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
			body, _ := json.Marshal(metiOverrideRequest{
				OverrideStatus: criteria.StatusAchieved,
				OverrideNote:   tc.note,
			})
			req := httptest.NewRequest(http.MethodPut,
				"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
				strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)
			c.SetParamNames("id", "criterion_id")
			c.SetParamValues(h.projectID.String(), realCriterionID)
			h.ctxWithRole(c, model.RoleAdmin)
			if err := h.handler.OverrideAssessment(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// Codex R4: the audit row records the note length so an auditor can spot
// one-character notes; it was in bytes, so the one-character note "理" was
// audited as 3. Both the override and the clear-override audit count
// characters now, like the limit itself.
func TestMetiHandler_NoteLengthAuditedInCharacters(t *testing.T) {
	h := newMetiHarness()
	h.seedRow(realCriterionID, realCriterionPhase, criteria.StatusNeedsReview)
	body, _ := json.Marshal(metiOverrideRequest{OverrideStatus: criteria.StatusAchieved, OverrideNote: " 理 "})
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)
	if err := h.handler.OverrideAssessment(c); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("override: %v %d %s", err, rec.Code, rec.Body.String())
	}

	body, _ = json.Marshal(metiClearOverrideRequest{Note: "誤"})
	req = httptest.NewRequest(http.MethodDelete,
		"/api/v1/projects/"+h.projectID.String()+"/meti/assessment/"+realCriterionID+"/override",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	c = echo.New().NewContext(req, rec)
	c.SetParamNames("id", "criterion_id")
	c.SetParamValues(h.projectID.String(), realCriterionID)
	h.ctxWithRole(c, model.RoleAdmin)
	if err := h.handler.ClearOverride(c); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("clear: %v %d %s", err, rec.Code, rec.Body.String())
	}

	if len(h.audit.entries) != 2 {
		t.Fatalf("audit entries = %d, want 2", len(h.audit.entries))
	}
	// The persisted (and audited) note is the trimmed one: 1 character.
	if got := h.audit.entries[0].Details["override_note_len"]; got != 1 {
		t.Errorf("override_note_len = %v, want 1", got)
	}
	if got := h.audit.entries[1].Details["clear_note_len"]; got != 1 {
		t.Errorf("clear_note_len = %v, want 1", got)
	}
}

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

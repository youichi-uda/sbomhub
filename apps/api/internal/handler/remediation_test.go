package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

// TestGetRemediationByCVE_MalformedCVEIs400 locks the M42 fix: the
// /remediation/:cve_id endpoint validates the CVE ID and returns 400 BEFORE the
// value can reach the external OSV /vulns/<id> request URL. A nil service is
// safe here precisely because validation short-circuits ahead of any service
// call.
func TestGetRemediationByCVE_MalformedCVEIs400(t *testing.T) {
	h := NewRemediationHandler(nil)

	malformed := []string{
		"not-a-cve",
		"CVE-21-1",              // 2-digit year, 1-digit seq
		"CVE-2021-1",            // sequence < 4 digits
		"../../etc/passwd",      // path traversal
		"CVE-2021-44228?key=x",  // query-injection shape
		"CVE-2021-44228/../foo", // slash-bearing
		"",                      // empty
	}
	for _, bad := range malformed {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/remediation/x", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("cve_id")
		c.SetParamValues(bad)

		if err := h.GetRemediationByCVE(c); err != nil {
			t.Fatalf("cve=%q: handler returned error: %v", bad, err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("cve=%q: status=%d, want 400 (malformed must be rejected before the OSV call)", bad, rec.Code)
		}
	}
}

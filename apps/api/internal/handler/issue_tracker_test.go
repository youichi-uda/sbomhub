package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
)

// TestCreateConnection_TrackerTypeValidation pins the handler-side
// tracker_type switch of CreateConnection (F356, M24-1b #125): the raw
// request string is validated against the full wire-value set BEFORE it is
// mapped to a model const, the 400 message enumerates exactly that set (the
// same message TestTrackerTypeRegistryParity_F330 direction 3b pins against
// the const block), and the per-tracker required-field checks fire at the
// handler (email for Jira, default_project_key for GitHub — GitHub's
// connection test is repository-scoped, so a missing "owner/repo" key would
// otherwise only fail later inside the service's connection test).
//
// Every case exercises a validation path that returns before the service is
// touched, so the handler is constructed with a nil service (recording-stub
// spirit of apikey_test.go — no DB, no HTTP).
func TestCreateConnection_TrackerTypeValidation(t *testing.T) {
	h := NewIssueTrackerHandler(nil)

	cases := []struct {
		name        string
		body        string
		wantMessage string
	}{
		{
			name:        "unknown tracker type is rejected with the full wire-value list",
			body:        `{"tracker_type":"linear","name":"n","base_url":"https://example.com","api_token":"t"}`,
			wantMessage: "Invalid tracker_type. Must be 'jira', 'backlog', or 'github'",
		},
		{
			name:        "jira requires email",
			body:        `{"tracker_type":"jira","name":"n","base_url":"https://example.atlassian.net","api_token":"t"}`,
			wantMessage: "email is required for Jira",
		},
		{
			name:        "github requires default_project_key",
			body:        `{"tracker_type":"github","name":"n","base_url":"https://api.github.com","api_token":"t"}`,
			wantMessage: "default_project_key (owner/repo) is required for GitHub",
		},
		{
			name:        "missing required fields fail before the tracker switch",
			body:        `{"tracker_type":"github"}`,
			wantMessage: "tracker_type, name, base_url, and api_token are required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations", strings.NewReader(tc.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set(middleware.ContextKeyTenantID, uuid.New())

			err := h.CreateConnection(c)
			if err == nil {
				t.Fatalf("expected a 400 *echo.HTTPError, got nil (recorded status %d, body %s)",
					rec.Code, rec.Body.String())
			}
			he, ok := err.(*echo.HTTPError)
			if !ok {
				t.Fatalf("expected *echo.HTTPError, got %T: %v", err, err)
			}
			if he.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", he.Code, http.StatusBadRequest)
			}
			msg, _ := he.Message.(string)
			if msg != tc.wantMessage {
				t.Errorf("message = %q, want %q", msg, tc.wantMessage)
			}
		})
	}
}

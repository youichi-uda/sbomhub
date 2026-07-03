package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
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

// recordingIssueTrackerService is a minimal IssueTrackerServiceAPI stub for
// the F370 default-base-URL pin: it records the CreateConnection input the
// handler forwards and returns a canned connection. Every other method
// fails the test — the flows under test must not touch them.
type recordingIssueTrackerService struct {
	t *testing.T

	createConnectionCalls []service.CreateConnectionInput
	connectionToReturn    *model.IssueTrackerConnection
}

func (s *recordingIssueTrackerService) CreateConnection(_ context.Context, _ uuid.UUID, input service.CreateConnectionInput) (*model.IssueTrackerConnection, error) {
	s.createConnectionCalls = append(s.createConnectionCalls, input)
	return s.connectionToReturn, nil
}

func (s *recordingIssueTrackerService) ListConnections(context.Context, uuid.UUID) ([]model.IssueTrackerConnection, error) {
	s.t.Fatal("unexpected ListConnections call")
	return nil, nil
}

func (s *recordingIssueTrackerService) GetConnection(context.Context, uuid.UUID) (*model.IssueTrackerConnection, error) {
	s.t.Fatal("unexpected GetConnection call")
	return nil, nil
}

func (s *recordingIssueTrackerService) DeleteConnection(context.Context, uuid.UUID) error {
	s.t.Fatal("unexpected DeleteConnection call")
	return nil
}

func (s *recordingIssueTrackerService) CreateTicket(context.Context, uuid.UUID, service.CreateTicketInput) (*model.VulnerabilityTicket, error) {
	s.t.Fatal("unexpected CreateTicket call")
	return nil, nil
}

func (s *recordingIssueTrackerService) GetTicketByVulnerability(context.Context, uuid.UUID) ([]model.VulnerabilityTicketWithDetails, error) {
	s.t.Fatal("unexpected GetTicketByVulnerability call")
	return nil, nil
}

func (s *recordingIssueTrackerService) ListTickets(context.Context, uuid.UUID, string, int, int) ([]model.VulnerabilityTicketWithDetails, int, error) {
	s.t.Fatal("unexpected ListTickets call")
	return nil, 0, nil
}

func (s *recordingIssueTrackerService) SyncTicket(context.Context, uuid.UUID) error {
	s.t.Fatal("unexpected SyncTicket call")
	return nil
}

// TestCreateConnection_GitHubBaseURLDefault pins the F370 base-URL UX
// contract end-to-end through the handler:
//
//   - github + empty base_url → 201, and the service receives (and the
//     response echoes) the substituted https://api.github.com default;
//   - github + explicit base_url (GHES) → the operator's URL wins, the
//     default must not clobber it;
//   - jira / backlog + empty base_url → the pre-existing 400 contract is
//     unchanged (their base URL embeds the customer subdomain and cannot
//     be defaulted), with the service never touched.
func TestCreateConnection_GitHubBaseURLDefault(t *testing.T) {
	if githubDefaultBaseURL != "https://api.github.com" {
		t.Fatalf("githubDefaultBaseURL = %q, want the public GitHub API root", githubDefaultBaseURL)
	}

	t.Run("github with empty base_url gets the api.github.com default and a 201", func(t *testing.T) {
		connID := uuid.New()
		stub := &recordingIssueTrackerService{
			t: t,
			connectionToReturn: &model.IssueTrackerConnection{
				ID:                connID,
				TrackerType:       model.TrackerTypeGitHub,
				Name:              "gh",
				BaseURL:           githubDefaultBaseURL,
				DefaultProjectKey: "octocat/hello-world",
			},
		}
		h := NewIssueTrackerHandler(stub)

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations", strings.NewReader(
			`{"tracker_type":"github","name":"gh","api_token":"t","default_project_key":"octocat/hello-world"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set(middleware.ContextKeyTenantID, uuid.New())

		if err := h.CreateConnection(c); err != nil {
			t.Fatalf("CreateConnection returned %v, want a 201 flow", err)
		}
		if rec.Code != http.StatusCreated {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
		}
		if len(stub.createConnectionCalls) != 1 {
			t.Fatalf("service CreateConnection called %d times, want 1", len(stub.createConnectionCalls))
		}
		if got := stub.createConnectionCalls[0].BaseURL; got != githubDefaultBaseURL {
			t.Errorf("service received BaseURL %q, want the substituted default %q", got, githubDefaultBaseURL)
		}
		if !strings.Contains(rec.Body.String(), githubDefaultBaseURL) {
			t.Errorf("201 response %q should echo the defaulted base_url", rec.Body.String())
		}
	})

	t.Run("github with an explicit GHES base_url is not clobbered by the default", func(t *testing.T) {
		stub := &recordingIssueTrackerService{
			t:                  t,
			connectionToReturn: &model.IssueTrackerConnection{ID: uuid.New()},
		}
		h := NewIssueTrackerHandler(stub)

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations", strings.NewReader(
			`{"tracker_type":"github","name":"gh","base_url":"https://ghe.example.com/api/v3","api_token":"t","default_project_key":"octocat/hello-world"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set(middleware.ContextKeyTenantID, uuid.New())

		if err := h.CreateConnection(c); err != nil {
			t.Fatalf("CreateConnection returned %v, want a 201 flow", err)
		}
		if len(stub.createConnectionCalls) != 1 {
			t.Fatalf("service CreateConnection called %d times, want 1", len(stub.createConnectionCalls))
		}
		if got := stub.createConnectionCalls[0].BaseURL; got != "https://ghe.example.com/api/v3" {
			t.Errorf("service received BaseURL %q, want the operator's GHES root", got)
		}
	})

	// The other trackers' contract is unchanged: base_url stays required.
	for _, tc := range []struct {
		name string
		body string
	}{
		{"jira", `{"tracker_type":"jira","name":"n","email":"a@b.c","api_token":"t"}`},
		{"backlog", `{"tracker_type":"backlog","name":"n","api_token":"t"}`},
	} {
		t.Run(tc.name+" with empty base_url still 400s", func(t *testing.T) {
			stub := &recordingIssueTrackerService{t: t}
			h := NewIssueTrackerHandler(stub)

			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations", strings.NewReader(tc.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set(middleware.ContextKeyTenantID, uuid.New())

			err := h.CreateConnection(c)
			he, ok := err.(*echo.HTTPError)
			if !ok {
				t.Fatalf("expected *echo.HTTPError, got %T: %v", err, err)
			}
			if he.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", he.Code, http.StatusBadRequest)
			}
			if msg, _ := he.Message.(string); msg != "tracker_type, name, base_url, and api_token are required" {
				t.Errorf("message = %q, want the unchanged required-field message", msg)
			}
			if len(stub.createConnectionCalls) != 0 {
				t.Errorf("service CreateConnection called %d times, want 0 (400 fires before the service)", len(stub.createConnectionCalls))
			}
		})
	}
}

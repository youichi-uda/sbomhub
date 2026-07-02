package service

// GitHub Issues tracker-arm coverage (F356, M24-1b #125) — the service-level
// counterpart of the Jira/Backlog coverage in issue_tracker_test.go, plus
// full-flow tests for the two switch arms that are new with GitHub:
//
//   - testConnection's repository-scoped connection test (Jira/Backlog test
//     instance-level endpoints; GitHub tests GET /repos/{owner}/{repo}, so an
//     empty DefaultProjectKey must fail loudly instead of probing nothing).
//   - SyncTicket's numeric-issue-key contract (ExternalTicketKey is
//     strconv.Itoa(issue.Number) for GitHub, so a non-numeric key is a data
//     bug that must surface as an explicit error, never a silent skip).
//
// External HTTP is mocked with httptest (same pattern as
// client/github_issues_test.go); the SyncTicket flow mocks the repository
// with sqlmock (same pattern as apikey_test.go).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

func TestIssueTrackerService_TestConnection_GitHub(t *testing.T) {
	svc := NewIssueTrackerService(nil, nil, testEncryptionKey, nil)

	t.Run("success probes the repo-scoped endpoint with Bearer auth", func(t *testing.T) {
		var gotPath, gotAuth string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id": 1, "full_name": "octocat/hello-world"}`))
		}))
		defer ts.Close()

		conn := &model.IssueTrackerConnection{
			TrackerType:       model.TrackerTypeGitHub,
			BaseURL:           ts.URL,
			DefaultProjectKey: "octocat/hello-world",
		}
		if err := svc.testConnection(context.Background(), conn, "test-token"); err != nil {
			t.Fatalf("testConnection failed: %v", err)
		}
		if gotPath != "/repos/octocat/hello-world" {
			t.Errorf("path = %q, want /repos/octocat/hello-world", gotPath)
		}
		if gotAuth != "Bearer test-token" {
			t.Errorf("Authorization = %q, want \"Bearer test-token\"", gotAuth)
		}
	})

	t.Run("empty default project key fails before any HTTP", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("no HTTP request must be made for an empty DefaultProjectKey; got %s %s", r.Method, r.URL.Path)
		}))
		defer ts.Close()

		conn := &model.IssueTrackerConnection{
			TrackerType: model.TrackerTypeGitHub,
			BaseURL:     ts.URL,
		}
		err := svc.testConnection(context.Background(), conn, "test-token")
		if err == nil {
			t.Fatal("expected an error for empty DefaultProjectKey")
		}
		if !strContains(err.Error(), "default project key") {
			t.Errorf("error %q should name the missing default project key", err)
		}
	})

	t.Run("401 surfaces ErrGitHubUnauthorized via errors.Is", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message": "Bad credentials"}`))
		}))
		defer ts.Close()

		conn := &model.IssueTrackerConnection{
			TrackerType:       model.TrackerTypeGitHub,
			BaseURL:           ts.URL,
			DefaultProjectKey: "octocat/hello-world",
		}
		err := svc.testConnection(context.Background(), conn, "revoked-token")
		if !errors.Is(err, client.ErrGitHubUnauthorized) {
			t.Fatalf("err = %v, want errors.Is(err, client.ErrGitHubUnauthorized)", err)
		}
	})
}

func TestIssueTrackerService_CreateGitHubTicket(t *testing.T) {
	svc := NewIssueTrackerService(nil, nil, testEncryptionKey, nil)

	t.Run("maps issue number to ID/Key and html_url to URL", func(t *testing.T) {
		var gotPath string
		var gotBody map[string]interface{}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{
				"number": 42,
				"title": "[HIGH] CVE-2026-0001",
				"state": "open",
				"html_url": "https://github.com/octocat/hello-world/issues/42"
			}`))
		}))
		defer ts.Close()

		conn := &model.IssueTrackerConnection{
			TrackerType: model.TrackerTypeGitHub,
			BaseURL:     ts.URL,
		}
		input := CreateTicketInput{
			Summary:     "[HIGH] CVE-2026-0001",
			Description: "Vulnerability remediation required.",
			Priority:    "High",
			Labels:      []string{"security", "sbomhub"},
		}

		ticket, err := svc.createGitHubTicket(context.Background(), conn, "test-token", "octocat/hello-world", input)
		if err != nil {
			t.Fatalf("createGitHubTicket failed: %v", err)
		}

		if gotPath != "/repos/octocat/hello-world/issues" {
			t.Errorf("path = %q, want /repos/octocat/hello-world/issues", gotPath)
		}
		if gotBody["title"] != "[HIGH] CVE-2026-0001" {
			t.Errorf("posted title = %v, want the input summary", gotBody["title"])
		}
		if labels, ok := gotBody["labels"].([]interface{}); !ok || len(labels) != 2 {
			t.Errorf("posted labels = %v, want the 2 input labels", gotBody["labels"])
		}

		if ticket.ID != "42" || ticket.Key != "42" {
			t.Errorf("ID/Key = %q/%q, want \"42\"/\"42\" (strconv.Itoa(issue.Number))", ticket.ID, ticket.Key)
		}
		if ticket.URL != "https://github.com/octocat/hello-world/issues/42" {
			t.Errorf("URL = %q, want the issue html_url", ticket.URL)
		}
		if ticket.Status != "open" {
			t.Errorf("Status = %q, want \"open\"", ticket.Status)
		}
		// GitHub Issues has no native priority field — the requested
		// priority must NOT be persisted as external state.
		if ticket.Priority != "" {
			t.Errorf("Priority = %q, want empty (GitHub has no priority field)", ticket.Priority)
		}
	})

	t.Run("malformed owner/repo project key is rejected client-side", func(t *testing.T) {
		conn := &model.IssueTrackerConnection{
			TrackerType: model.TrackerTypeGitHub,
			BaseURL:     "https://api.github.invalid",
		}
		_, err := svc.createGitHubTicket(context.Background(), conn, "test-token", "not-a-repo", CreateTicketInput{Summary: "s"})
		if !errors.Is(err, client.ErrGitHubInvalidRepo) {
			t.Fatalf("err = %v, want errors.Is(err, client.ErrGitHubInvalidRepo)", err)
		}
	})
}

// ticket/connection column sets mirror repository.IssueTrackerRepository's
// GetTicket / GetConnection SELECT lists.
var githubSyncTicketCols = []string{
	"id", "tenant_id", "vulnerability_id", "project_id", "connection_id",
	"external_ticket_id", "external_ticket_key", "external_ticket_url",
	"local_status", "external_status", "priority", "assignee", "summary",
	"last_synced_at", "created_at", "updated_at",
}

var githubSyncConnCols = []string{
	"id", "tenant_id", "tracker_type", "name", "base_url", "auth_type", "auth_email",
	"auth_token_encrypted", "default_project_key", "default_issue_type", "is_active",
	"last_sync_at", "created_at", "updated_at",
}

func TestIssueTrackerService_SyncTicket_GitHub_ClosedIssue(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/octocat/hello-world/issues/42" {
			t.Errorf("path = %q, want /repos/octocat/hello-world/issues/42", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"number": 42,
			"title": "[HIGH] CVE-2026-0001",
			"state": "closed",
			"html_url": "https://github.com/octocat/hello-world/issues/42"
		}`))
	}))
	defer ts.Close()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := NewIssueTrackerService(repository.NewIssueTrackerRepository(db), nil, testEncryptionKey, nil)

	encToken, err := svc.encrypt("gh-token")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	ticketID := uuid.New()
	connID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectQuery("FROM vulnerability_tickets").WithArgs(ticketID).WillReturnRows(
		sqlmock.NewRows(githubSyncTicketCols).AddRow(
			ticketID, tenantID, uuid.New(), uuid.New(), connID,
			"42", "42", "https://github.com/octocat/hello-world/issues/42",
			string(model.TicketStatusOpen), "open", "", "", "[HIGH] CVE-2026-0001",
			nil, now, now))

	mock.ExpectQuery("FROM issue_tracker_connections").WithArgs(connID).WillReturnRows(
		sqlmock.NewRows(githubSyncConnCols).AddRow(
			connID, tenantID, string(model.TrackerTypeGitHub), "GitHub prod", ts.URL,
			string(model.AuthTypeAPIToken), "", encToken, "octocat/hello-world", "",
			true, nil, now, now))

	// "closed" must land in the same terminal bucket as Jira "Done" /
	// Backlog "完了": local_status = closed, external_status = raw "closed".
	mock.ExpectExec("UPDATE vulnerability_tickets").WithArgs(
		ticketID, string(model.TicketStatusClosed), "closed", "", "",
		"[HIGH] CVE-2026-0001", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))

	if err := svc.SyncTicket(context.Background(), ticketID); err != nil {
		t.Fatalf("SyncTicket failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestIssueTrackerService_SyncTicket_GitHub_NonNumericKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := NewIssueTrackerService(repository.NewIssueTrackerRepository(db), nil, testEncryptionKey, nil)

	encToken, err := svc.encrypt("gh-token")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	ticketID := uuid.New()
	connID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	mock.ExpectQuery("FROM vulnerability_tickets").WithArgs(ticketID).WillReturnRows(
		sqlmock.NewRows(githubSyncTicketCols).AddRow(
			ticketID, tenantID, uuid.New(), uuid.New(), connID,
			"PROJ-1", "PROJ-1", "https://example.invalid/PROJ-1",
			string(model.TicketStatusOpen), "open", "", "", "s",
			nil, now, now))

	mock.ExpectQuery("FROM issue_tracker_connections").WithArgs(connID).WillReturnRows(
		sqlmock.NewRows(githubSyncConnCols).AddRow(
			connID, tenantID, string(model.TrackerTypeGitHub), "GitHub prod", "https://api.github.invalid",
			string(model.AuthTypeAPIToken), "", encToken, "octocat/hello-world", "",
			true, nil, now, now))

	// No UPDATE expectation: a Jira-shaped key on a GitHub connection is a
	// data bug that must error out loudly, not silently rewrite the ticket.
	err = svc.SyncTicket(context.Background(), ticketID)
	if err == nil {
		t.Fatal("expected an error for a non-numeric GitHub ticket key")
	}
	if !strContains(err.Error(), "non-numeric") {
		t.Errorf("error %q should name the non-numeric external ticket key", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no UPDATE must run for a non-numeric key; got %v", err)
	}
}

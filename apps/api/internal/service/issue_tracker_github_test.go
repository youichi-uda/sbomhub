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
			TrackerType:       model.TrackerTypeGitHub,
			BaseURL:           ts.URL,
			DefaultProjectKey: "octocat/hello-world",
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
		// F366: the creation repository is reported back so CreateTicket
		// persists it on the ticket row (external_project_key).
		if ticket.ProjectKey != "octocat/hello-world" {
			t.Errorf("ProjectKey = %q, want the creation repository \"octocat/hello-world\" (F366)", ticket.ProjectKey)
		}
	})

	t.Run("malformed owner/repo project key is rejected client-side", func(t *testing.T) {
		conn := &model.IssueTrackerConnection{
			TrackerType:       model.TrackerTypeGitHub,
			BaseURL:           "https://api.github.invalid",
			DefaultProjectKey: "octocat/hello-world",
		}
		_, err := svc.createGitHubTicket(context.Background(), conn, "test-token", "not-a-repo", CreateTicketInput{Summary: "s"})
		if !errors.Is(err, client.ErrGitHubInvalidRepo) {
			t.Fatalf("err = %v, want errors.Is(err, client.ErrGitHubInvalidRepo)", err)
		}
	})

	// F366 (replaces the F361 creation-side reject): a per-ticket repository
	// override differing from the connection's default is accepted — the
	// issue is created in the override repository and that repository is
	// reported back for persistence, so SyncTicket can poll it later.
	t.Run("F366: repository override differing from the default is accepted and reported for persistence", func(t *testing.T) {
		var gotPath string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{
				"number": 7,
				"title": "s",
				"state": "open",
				"html_url": "https://github.com/octocat/other-repo/issues/7"
			}`))
		}))
		defer ts.Close()

		conn := &model.IssueTrackerConnection{
			TrackerType:       model.TrackerTypeGitHub,
			BaseURL:           ts.URL,
			DefaultProjectKey: "octocat/hello-world",
		}
		ticket, err := svc.createGitHubTicket(context.Background(), conn, "test-token", "octocat/other-repo", CreateTicketInput{Summary: "s"})
		if err != nil {
			t.Fatalf("createGitHubTicket rejected a per-ticket repository override (F366 unlocked these): %v", err)
		}
		if gotPath != "/repos/octocat/other-repo/issues" {
			t.Errorf("path = %q, want the issue created in the OVERRIDE repository /repos/octocat/other-repo/issues", gotPath)
		}
		if ticket.Key != "7" {
			t.Errorf("Key = %q, want \"7\"", ticket.Key)
		}
		if ticket.ProjectKey != "octocat/other-repo" {
			t.Errorf("ProjectKey = %q, want the override repository \"octocat/other-repo\" reported for persistence", ticket.ProjectKey)
		}
	})
}

// ticket/connection column sets mirror repository.IssueTrackerRepository's
// GetTicket / GetConnection SELECT lists (external_project_key added by
// migration 051 / F366; GetTicket COALESCEs its NULL to "").
var githubSyncTicketCols = []string{
	"id", "tenant_id", "vulnerability_id", "project_id", "connection_id",
	"external_ticket_id", "external_ticket_key", "external_ticket_url",
	"external_project_key",
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
			"octocat/hello-world",
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
			"PROJ-1", "PROJ-1", "https://example.invalid/PROJ-1", "",
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

// githubSyncGuardFixture wires the two GetTicket/GetConnection sqlmock rows
// shared by the GitHub sync-side repo-resolution tests (F361 guard heritage,
// F366 repo persistence): a GitHub ticket (external key "42") with the given
// external URL and persisted external_project_key (empty = legacy pre-051
// row after GetTicket's COALESCE) on a connection whose default repository
// is "octocat/hello-world" and whose base URL is baseURL. Guard tests point
// baseURL at a server that fails the test on ANY request (the guards must
// reject before HTTP); the happy-path tests point it at a normal mock.
func githubSyncGuardFixture(t *testing.T, svc *IssueTrackerService, mock sqlmock.Sqlmock, baseURL, ticketURL, externalProjectKey string) uuid.UUID {
	t.Helper()

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
			"42", "42", ticketURL, externalProjectKey,
			string(model.TicketStatusOpen), "open", "", "", "[HIGH] CVE-2026-0001",
			nil, now, now))

	mock.ExpectQuery("FROM issue_tracker_connections").WithArgs(connID).WillReturnRows(
		sqlmock.NewRows(githubSyncConnCols).AddRow(
			connID, tenantID, string(model.TrackerTypeGitHub), "GitHub prod", baseURL,
			string(model.AuthTypeAPIToken), "", encToken, "octocat/hello-world", "",
			true, nil, now, now))

	return ticketID
}

// TestIssueTrackerService_SyncTicket_GitHub_LegacyNULLRowURLFallback pins the
// F366 legacy path: a pre-051 ticket row persists no external_project_key
// (empty after GetTicket's COALESCE), so sync resolves the repository from
// the persisted issue html_url — even when that repository differs from the
// connection's default (pre-F366 this was the F361 hard-error case; with the
// per-URL resolution the ticket's own repository IS the sync target).
func TestIssueTrackerService_SyncTicket_GitHub_LegacyNULLRowURLFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/other-org/other-repo/issues/42" {
			t.Errorf("path = %q, want the URL-derived repository /repos/other-org/other-repo/issues/42", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"number": 42,
			"title": "[HIGH] CVE-2026-0001",
			"state": "closed",
			"html_url": "https://github.com/other-org/other-repo/issues/42"
		}`))
	}))
	defer ts.Close()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := NewIssueTrackerService(repository.NewIssueTrackerRepository(db), nil, testEncryptionKey, nil)
	ticketID := githubSyncGuardFixture(t, svc, mock, ts.URL,
		"https://github.com/other-org/other-repo/issues/42", "")

	mock.ExpectExec("UPDATE vulnerability_tickets").WithArgs(
		ticketID, string(model.TicketStatusClosed), "closed", "", "",
		"[HIGH] CVE-2026-0001", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))

	if err := svc.SyncTicket(context.Background(), ticketID); err != nil {
		t.Fatalf("SyncTicket failed on a legacy NULL-external_project_key row (URL fallback): %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestIssueTrackerService_SyncTicket_GitHub_PersistedRepoOverride pins the
// F366 sync-side unlock: a ticket whose persisted external_project_key names
// a repository other than the connection's default is polled in ITS OWN
// repository (per-ticket override), not the connection default.
func TestIssueTrackerService_SyncTicket_GitHub_PersistedRepoOverride(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/octocat/other-repo/issues/42" {
			t.Errorf("path = %q, want the persisted repository /repos/octocat/other-repo/issues/42", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"number": 42,
			"title": "[HIGH] CVE-2026-0001",
			"state": "closed",
			"html_url": "https://github.com/octocat/other-repo/issues/42"
		}`))
	}))
	defer ts.Close()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := NewIssueTrackerService(repository.NewIssueTrackerRepository(db), nil, testEncryptionKey, nil)
	ticketID := githubSyncGuardFixture(t, svc, mock, ts.URL,
		"https://github.com/octocat/other-repo/issues/42", "octocat/other-repo")

	mock.ExpectExec("UPDATE vulnerability_tickets").WithArgs(
		ticketID, string(model.TicketStatusClosed), "closed", "", "",
		"[HIGH] CVE-2026-0001", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))

	if err := svc.SyncTicket(context.Background(), ticketID); err != nil {
		t.Fatalf("SyncTicket failed for a persisted per-ticket repository override: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestIssueTrackerService_SyncTicket_GitHub_PersistedRepoURLMismatch pins the
// retained defense-in-depth guard: a persisted external_project_key that
// contradicts the repository named by the persisted html_url is data
// corruption — sync must error out loudly with no HTTP round-trip and no
// UPDATE instead of guessing which of the two repositories is right.
func TestIssueTrackerService_SyncTicket_GitHub_PersistedRepoURLMismatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no HTTP request must be made for a persisted-repo/URL mismatch; got %s %s", r.Method, r.URL.Path)
	}))
	defer ts.Close()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := NewIssueTrackerService(repository.NewIssueTrackerRepository(db), nil, testEncryptionKey, nil)
	ticketID := githubSyncGuardFixture(t, svc, mock, ts.URL,
		"https://github.com/other-org/other-repo/issues/42", "octocat/hello-world")

	err = svc.SyncTicket(context.Background(), ticketID)
	if err == nil {
		t.Fatal("expected an error for a persisted repository contradicting the ticket URL")
	}
	if !strContains(err.Error(), "octocat/hello-world") || !strContains(err.Error(), "other-org/other-repo") {
		t.Errorf("error %q should name both the persisted repository and the URL-derived repository", err)
	}
	// No UPDATE expectation was registered: the guard must fire before any
	// ticket write.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no UPDATE must run for a persisted-repo/URL mismatch; got %v", err)
	}
}

// TestIssueTrackerService_SyncTicket_GitHub_UnparseableURL pins the retained
// defensive-parse arm (F361 posture, kept as defense in depth under F366): a
// stored URL whose repository cannot be established (legacy rows, hand
// edits) is an explicit error — never a silent poll of a repository the
// ticket may not belong to, where the issue number may name an unrelated
// issue.
func TestIssueTrackerService_SyncTicket_GitHub_UnparseableURL(t *testing.T) {
	badURLs := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"relative_no_host", "/octocat/hello-world/issues/42"},
		{"jira_shaped_path", "https://example.invalid/browse/PROJ-1"},
		{"pulls_not_issues", "https://github.com/octocat/hello-world/pull/42"},
		{"non_numeric_issue_segment", "https://github.com/octocat/hello-world/issues/latest"},
	}
	for _, tc := range badURLs {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("no HTTP request must be made for an unparseable ticket URL; got %s %s", r.Method, r.URL.Path)
			}))
			defer ts.Close()

			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			svc := NewIssueTrackerService(repository.NewIssueTrackerRepository(db), nil, testEncryptionKey, nil)
			ticketID := githubSyncGuardFixture(t, svc, mock, ts.URL, tc.url, "")

			err = svc.SyncTicket(context.Background(), ticketID)
			if err == nil {
				t.Fatalf("expected an error for unparseable ticket URL %q", tc.url)
			}
			if !strContains(err.Error(), "refusing to sync") {
				t.Errorf("error %q should state the sync refusal", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("no UPDATE must run for an unparseable ticket URL; got %v", err)
			}
		})
	}
}

// TestIssueTrackerService_SyncTicket_GitHub_CaseVariantRepoURL pins the
// case-insensitivity of the persisted-repo ↔ URL cross-check (F361 heritage,
// F366 shape): GitHub owner/repo names are case-insensitive and html_url
// carries GitHub's canonical casing, which may differ from the casing the
// operator typed into the per-ticket repository at creation. A case-variant
// match is the SAME repository — the mismatch guard must not fire, and sync
// polls the persisted (operator-cased) repository.
func TestIssueTrackerService_SyncTicket_GitHub_CaseVariantRepoURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/octocat/hello-world/issues/42" {
			t.Errorf("path = %q, want /repos/octocat/hello-world/issues/42", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"number": 42,
			"title": "[HIGH] CVE-2026-0001",
			"state": "closed",
			"html_url": "https://github.com/Octocat/Hello-World/issues/42"
		}`))
	}))
	defer ts.Close()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := NewIssueTrackerService(repository.NewIssueTrackerRepository(db), nil, testEncryptionKey, nil)
	ticketID := githubSyncGuardFixture(t, svc, mock, ts.URL,
		"https://github.com/Octocat/Hello-World/issues/42", "octocat/hello-world")

	mock.ExpectExec("UPDATE vulnerability_tickets").WithArgs(
		ticketID, string(model.TicketStatusClosed), "closed", "", "",
		"[HIGH] CVE-2026-0001", sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))

	if err := svc.SyncTicket(context.Background(), ticketID); err != nil {
		t.Fatalf("SyncTicket rejected a case-variant of the default repository: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// TestIssueTrackerService_CreateTicket_GitHub_PersistsExternalProjectKey
// pins the F366 persistence contract end-to-end through CreateTicket: a
// per-ticket repository override is used for the external issue creation AND
// lands in the vulnerability_tickets INSERT's external_project_key argument,
// so SyncTicket can later resolve the ticket's own repository.
func TestIssueTrackerService_CreateTicket_GitHub_PersistsExternalProjectKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/octocat/other-repo/issues" {
			t.Errorf("path = %q, want the override repository /repos/octocat/other-repo/issues", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"number": 43,
			"title": "[HIGH] CVE-2026-0002",
			"state": "open",
			"html_url": "https://github.com/octocat/other-repo/issues/43"
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

	tenantID := uuid.New()
	connID := uuid.New()
	vulnID := uuid.New()
	projectID := uuid.New()
	now := time.Now()

	mock.ExpectQuery("FROM issue_tracker_connections").WithArgs(connID).WillReturnRows(
		sqlmock.NewRows(githubSyncConnCols).AddRow(
			connID, tenantID, string(model.TrackerTypeGitHub), "GitHub prod", ts.URL,
			string(model.AuthTypeAPIToken), "", encToken, "octocat/hello-world", "",
			true, nil, now, now))

	// No pre-existing ticket for (vulnerability, connection).
	mock.ExpectQuery("FROM vulnerability_tickets").WithArgs(vulnID, connID).WillReturnRows(
		sqlmock.NewRows(githubSyncTicketCols))

	// The INSERT must carry the override repository in external_project_key
	// (column 9 of the F366 INSERT list) — this is the row SyncTicket reads
	// back.
	mock.ExpectExec("INSERT INTO vulnerability_tickets").WithArgs(
		sqlmock.AnyArg(), tenantID, vulnID, projectID, connID,
		"43", "43", "https://github.com/octocat/other-repo/issues/43",
		"octocat/other-repo",
		string(model.TicketStatusOpen), "open", "", "", "[HIGH] CVE-2026-0002",
		sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(0, 1))

	ticket, err := svc.CreateTicket(context.Background(), tenantID, CreateTicketInput{
		VulnerabilityID: vulnID,
		ProjectID:       projectID,
		ConnectionID:    connID,
		ProjectKey:      "octocat/other-repo", // per-ticket override (F366)
		Summary:         "[HIGH] CVE-2026-0002",
	})
	if err != nil {
		t.Fatalf("CreateTicket failed: %v", err)
	}
	if ticket.ExternalProjectKey != "octocat/other-repo" {
		t.Errorf("ExternalProjectKey = %q, want the override repository \"octocat/other-repo\"", ticket.ExternalProjectKey)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

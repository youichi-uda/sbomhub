package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/egress"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex round 2 (Low): the validation path trims surrounding whitespace
// (egress.Guard.ValidateURL calls strings.TrimSpace), but the untrimmed string
// was what got persisted and later handed to http.NewRequestWithContext. The
// value that was checked and the value that is used have to be the same string,
// or the check is about something other than what happens.
func TestEgressValidation_AcceptsSurroundingWhitespace(t *testing.T) {
	g := egress.NewSet(egress.Settings{}).IssueTracker
	if err := g.ValidateURL("  https://tracker.example  "); err != nil {
		t.Fatalf("ValidateURL trims, so this passes today: %v", err)
	}
	// And the untrimmed string is genuinely unusable as a request target — that
	// is what made the mismatch a real defect rather than a cosmetic one.
	if _, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"  https://tracker.example  ", nil); err == nil {
		t.Error("expected http.NewRequestWithContext to reject the untrimmed URL")
	}
}

func TestNormaliseEgressURL(t *testing.T) {
	cases := map[string]string{
		"  https://tracker.example  ": "https://tracker.example",
		"https://tracker.example":     "https://tracker.example",
		"\thttps://a.example\n":       "https://a.example",
		"":                            "",
		"   ":                         "",
	}
	for in, want := range cases {
		if got := normaliseEgressURL(in); got != want {
			t.Errorf("normaliseEgressURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCreateConnection_PersistsNormalisedBaseURL drives the real write path and
// asserts on the value that reaches the INSERT.
//
// Codex round 3 (Low) found the first version of this test vacuous: it called
// the normaliser and the validator but never CreateConnection, so reverting the
// persist-the-normalised-value change left it green. This one fails on that
// reversion, because sqlmock matches the exact argument bound to base_url.
func TestCreateConnection_PersistsNormalisedBaseURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1,"full_name":"octocat/hello-world"}`))
	}))
	defer srv.Close()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// The destination is chosen by the test, not by a tenant, so the guard says
	// so explicitly (the test server is on loopback).
	svc := NewIssueTrackerService(repository.NewIssueTrackerRepository(db), nil,
		testEncryptionKey, egress.OperatorControlled())

	rawURL := "  " + srv.URL + "  "
	wantURL := strings.TrimSpace(srv.URL)

	mock.ExpectExec("INSERT INTO issue_tracker_connections").
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // tenant_id
			model.TrackerTypeGitHub,
			"conn",
			wantURL, // base_url — the assertion
			model.AuthTypeAPIToken,
			"",
			sqlmock.AnyArg(), // encrypted token
			"octocat/hello-world",
			"",
			true,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	conn, err := svc.CreateConnection(context.Background(), uuid.New(), CreateConnectionInput{
		TrackerType:       model.TrackerTypeGitHub,
		Name:              "conn",
		BaseURL:           rawURL,
		APIToken:          "gh-token",
		DefaultProjectKey: "octocat/hello-world",
	})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	if conn.BaseURL != wantURL {
		t.Errorf("returned BaseURL = %q, want %q", conn.BaseURL, wantURL)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the INSERT did not bind the normalised base_url: %v", err)
	}
}

// TestUpdateNotificationSettings_PersistsNormalisedWebhookURLs is the same
// assertion for the other write path that takes tenant-supplied URLs.
func TestUpdateNotificationSettings_PersistsNormalisedWebhookURLs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	projectID := uuid.New()
	tenantID := uuid.New()

	svc := NewNotificationService(
		repository.NewNotificationRepository(db),
		repository.NewProjectRepository(db),
		nil,
		egress.NewSet(egress.Settings{}).NotificationWebhook,
	)

	mock.ExpectQuery("FROM projects").
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))

	mock.ExpectExec("INSERT INTO notification_settings").
		WithArgs(
			sqlmock.AnyArg(), // id
			tenantID,
			projectID,
			"https://hooks.slack.example/a",   // slack — the assertion
			"https://discord.example/api/w/b", // discord — the assertion
			sqlmock.AnyArg(),                  // email_addresses
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	settings, err := svc.UpdateSettings(context.Background(), projectID, UpdateNotificationSettingsInput{
		SlackWebhookURL:   "  https://hooks.slack.example/a  ",
		DiscordWebhookURL: "\thttps://discord.example/api/w/b\n",
		NotifyCritical:    true,
	})
	if err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	if settings.SlackWebhookURL != "https://hooks.slack.example/a" {
		t.Errorf("returned SlackWebhookURL = %q", settings.SlackWebhookURL)
	}
	if settings.DiscordWebhookURL != "https://discord.example/api/w/b" {
		t.Errorf("returned DiscordWebhookURL = %q", settings.DiscordWebhookURL)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the UPSERT did not bind the normalised webhook URLs: %v", err)
	}
}

// TestUpdateNotificationSettings_RefusesInternalWebhook is the write-path half
// of the egress check: an internal destination is refused before the row is
// written, as a ValidationError the handler maps to 400.
func TestUpdateNotificationSettings_RefusesInternalWebhook(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	projectID := uuid.New()
	mock.ExpectQuery("FROM projects").
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(uuid.New()))

	svc := NewNotificationService(
		repository.NewNotificationRepository(db),
		repository.NewProjectRepository(db),
		nil,
		nil, // nil guard must resolve to the strict policy
	)

	_, err = svc.UpdateSettings(context.Background(), projectID, UpdateNotificationSettingsInput{
		SlackWebhookURL: "http://169.254.169.254/latest/meta-data/",
	})
	if err == nil {
		t.Fatal("expected the metadata address to be refused before the upsert")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v, want ErrValidation so the handler answers 400", err)
	}
	if !strings.Contains(err.Error(), "slack_webhook_url") {
		t.Errorf("err = %v, want it to name the offending field", err)
	}
	// No INSERT was expected; ExpectationsWereMet confirms none was issued.
	if merr := mock.ExpectationsWereMet(); merr != nil {
		t.Errorf("unexpected database activity: %v", merr)
	}
}

package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestNotificationRepository_UpsertSettings_PassesTenantID asserts that
// the tenant_id column is bound at position 2 of the INSERT statement.
// Pairs with the FORCE RLS WITH CHECK clause on notification_settings
// (migration 023): a missing tenant_id is rejected at INSERT time.
func TestNotificationRepository_UpsertSettings_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewNotificationRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	settingsID := uuid.New()
	now := time.Now()

	mock.ExpectExec("INSERT INTO notification_settings").
		WithArgs(
			settingsID,
			tenantID,
			projectID,
			sql.NullString{String: "https://slack.example/webhook", Valid: true},
			sql.NullString{}, // discord empty
			sql.NullString{}, // email empty
			true,
			true,
			false,
			false,
			now,
			now,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.UpsertSettings(context.Background(), &model.NotificationSettings{
		ID:              settingsID,
		TenantID:        tenantID,
		ProjectID:       projectID,
		SlackWebhookURL: "https://slack.example/webhook",
		NotifyCritical:  true,
		NotifyHigh:      true,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if err != nil {
		t.Fatalf("UpsertSettings returned unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

// TestNotificationRepository_CreateLog_PassesTenantID asserts that
// tenant_id is bound at position 2 of the notification_logs INSERT.
func TestNotificationRepository_CreateLog_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewNotificationRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	logID := uuid.New()
	now := time.Now()

	mock.ExpectExec("INSERT INTO notification_logs").
		WithArgs(
			logID,
			tenantID,
			projectID,
			model.NotificationChannelSlack,
			`{"x":1}`,
			"sent",
			sql.NullString{}, // no error message
			now,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.CreateLog(context.Background(), &model.NotificationLog{
		ID:        logID,
		TenantID:  tenantID,
		ProjectID: projectID,
		Channel:   model.NotificationChannelSlack,
		Payload:   `{"x":1}`,
		Status:    "sent",
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateLog returned unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

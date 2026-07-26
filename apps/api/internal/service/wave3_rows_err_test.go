// Package service — M46 Track A wave 3 rows.Err() regression test for
// ScanSettingsService.GetLogs: a mid-iteration driver failure used to be
// swallowed (`continue` on scan error, no rows.Err() check), so the scan
// history listing silently truncated.
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

var errWave3SvcBoom = errors.New("wave3: connection reset mid-iteration")

func TestWave3ScanSettingsGetLogs_PartialResultsNotReturned(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "tenant_id", "started_at", "completed_at", "status",
		"projects_scanned", "new_vulnerabilities", "error_message", "created_at",
	}).
		AddRow(uuid.New().String(), uuid.New().String(), now, nil, "completed", 1, 2, nil, now).
		AddRow(uuid.New().String(), uuid.New().String(), now, nil, "completed", 3, 4, nil, now).
		RowError(1, errWave3SvcBoom)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	svc := NewScanSettingsService(db)
	logs, err := svc.GetLogs(context.Background(), uuid.New(), 10)
	if err == nil {
		t.Fatalf("GetLogs with a mid-iteration failure returned nil error (partial history presented as complete)")
	}
	if !errors.Is(err, errWave3SvcBoom) {
		t.Errorf("error = %v, want errWave3SvcBoom via rows.Err()", err)
	}
	if len(logs) != 0 {
		t.Errorf("returned %d logs alongside the error, want 0 (no partial results)", len(logs))
	}
}

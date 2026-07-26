// Package scheduler — M46 Track A wave 3 rows.Err() regression test for
// getProjects: a mid-iteration driver failure used to be swallowed
// (`continue` on scan error, no rows.Err() check), so a tenant's scan tick
// silently covered only part of its projects.
package scheduler

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

var errWave3SchedBoom = errors.New("wave3: connection reset mid-iteration")

func TestWave3GetProjects_PartialResultsNotReturned(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	goodID := uuid.New()
	rows := sqlmock.NewRows([]string{"id"}).
		AddRow(goodID.String()).
		AddRow(uuid.New().String()).
		RowError(1, errWave3SchedBoom)
	mock.ExpectQuery("SELECT").WillReturnRows(rows)

	j := &VulnerabilityScanJob{db: db}
	projects, err := j.getProjects(context.Background(), uuid.New())
	if err == nil {
		t.Fatalf("getProjects with a mid-iteration failure returned nil error (partial project list presented as complete)")
	}
	if !errors.Is(err, errWave3SchedBoom) {
		t.Errorf("error = %v, want errWave3SchedBoom via rows.Err()", err)
	}
	if len(projects) != 0 {
		t.Errorf("returned %d projects alongside the error, want 0 (no partial results)", len(projects))
	}
}

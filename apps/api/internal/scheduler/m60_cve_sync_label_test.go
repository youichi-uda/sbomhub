package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// Codex M60 R1 Low: the CVE-sync linker writes cve_sync_keyword, but when the
// link already existed from before migration 067 (match_method NULL) it left
// it NULL forever — "unknown" although this linker just reproduced it. It now
// labels a NULL link (and only a NULL one: cve_sync_keyword is the weakest
// method, so it never touches a labelled link, and the UPDATE locks a row
// only when it changes it).
func TestM60CVESyncLinker_LabelsAPreM60Link(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	compID, vulnID := uuid.New(), uuid.New()
	mock.ExpectQuery(`SELECT DISTINCT c\.id\s+FROM components c`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(compID))
	mock.ExpectExec(`INSERT INTO component_vulnerabilities .*'cve_sync_keyword'.*ON CONFLICT .* DO NOTHING`).
		WithArgs(compID, vulnID).
		WillReturnResult(sqlmock.NewResult(0, 0)) // the link already existed
	mock.ExpectExec(`UPDATE component_vulnerabilities\s+SET match_method = 'cve_sync_keyword'\s+WHERE component_id = \$1\s+AND vulnerability_id = \$2\s+AND match_method IS NULL`).
		WithArgs(compID, vulnID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, "", false)
	linked, err := j.linkCVEToTenantComponents(context.Background(), db, CVEInfo{ID: "CVE-2024-0001", Keywords: []string{"libfoo"}}, vulnID)
	if err != nil || linked != 1 {
		t.Fatalf("linked=%d err=%v", linked, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the pre-M60 link was not labelled: %v", err)
	}
}

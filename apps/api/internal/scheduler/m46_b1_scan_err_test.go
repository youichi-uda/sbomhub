package scheduler

// M46 Codex round B-1 — Medium-3: Scan errors inside cve_sync.go's row
// loops must fail the chunk/transaction, not be silently skipped.
//
// The post-loop rows.Err() check does NOT catch a per-row Scan failure:
// rows.Next() keeps returning true for the remaining rows and rows.Err()
// stays nil at EOF. Pre-fix both loops did `if err := rows.Scan(...);
// err != nil { continue }`, so one undecodable row meant
//
//   - linkCVEToTenantComponents: the component silently lost its
//     component_vulnerabilities link while the surrounding tx COMMITTED —
//     no error, no retry signal, a permanently missing vulnerability match;
//   - listOSVCandidatesChunk: the OSV candidate pair vanished from the
//     fetch set while the candidate tx committed — the CVE's vulnerable
//     symbols were never fetched and never retried.
//
// Post-fix a Scan error aborts the whole call with an explicit error (the
// caller's chunk retry semantics take over). These tests inject an
// undecodable row via sqlmock (NULL into a non-pointer scan target) and
// require the error to surface; pre-fix both returned nil (measured red).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestLinkCVEToTenantComponents_ScanErrorFailsChunk(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	// One good component row, then a row whose id cannot scan into
	// uuid.UUID (a malformed uuid string — note NULL would NOT error
	// here: uuid.UUID.Scan(nil) silently zeroes, the Medium-1 bug
	// class). Pre-fix the bad row was skipped and the INSERT for the
	// good row went ahead inside a tx that went on to COMMIT.
	rows := sqlmock.NewRows([]string{"id"}).
		AddRow(uuid.New()).
		AddRow("not-a-uuid")
	mock.ExpectQuery(`SELECT DISTINCT c\.id\s+FROM components c`).
		WillReturnRows(rows)

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, "", false)
	cve := CVEInfo{ID: "CVE-2024-0001", Keywords: []string{"libfoo"}}

	linked, err := j.linkCVEToTenantComponents(context.Background(), db, cve, uuid.New())
	if err == nil {
		t.Fatalf("linkCVEToTenantComponents returned (linked=%d, nil) on an undecodable component row; want an error that fails the chunk", linked)
	}
	if !strings.Contains(err.Error(), "scan") {
		t.Errorf("error = %v, want a scan-decode error", err)
	}
}

func TestListOSVCandidatesChunk_ScanErrorFailsTx(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec(`set_config\('app\.current_tenant_id'`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// One good (cve, purl) pair, then a NULL pair that cannot scan into
	// the string targets. Pre-fix the bad pair was skipped and the tx
	// committed with the candidate silently missing.
	rows := sqlmock.NewRows([]string{"cve_id", "purl"}).
		AddRow("CVE-2024-0001", "pkg:golang/example.com/mod@v1.0.0").
		AddRow(nil, nil)
	mock.ExpectQuery(`SELECT`).
		WithArgs(tenantID, sqlmock.AnyArg()).
		WillReturnRows(rows)
	mock.ExpectRollback()

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("db.Conn: %v", err)
	}
	defer func() { _ = conn.Close() }()

	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, "", false)
	out, err := j.listOSVCandidatesChunk(ctx, conn, 0, []uuid.UUID{tenantID},
		time.Now().Add(-time.Hour), map[string]osvCVEEcosystems{})
	if err == nil {
		t.Fatalf("listOSVCandidatesChunk returned (%d tenants, nil) on an undecodable candidate row; want an error that fails the tx", len(out))
	}
	if !strings.Contains(err.Error(), "scan") {
		t.Errorf("error = %v, want a scan-decode error", err)
	}
}

//go:build integration

// Migration 072: the JVNDB RSS sync end to end against a real PostgreSQL and a
// local copy of the real feed (testdata/jvndb/recent_trimmed.rdf).
//
//	cd apps/api && DATABASE_URL=... MIGRATE_DATABASE_URL=... \
//	    go test -tags=integration -count=1 -run JVNDBRSSIntegration ./internal/service
package service

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/repository"
)

func TestJVNDBRSSIntegration_SyncIsIdempotent(t *testing.T) {
	appURL, migURL := os.Getenv("DATABASE_URL"), os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("DATABASE_URL / MIGRATE_DATABASE_URL not set")
	}
	appDB, err := sql.Open("postgres", appURL)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = migDB.Close() })
	if err := appDB.Ping(); err != nil {
		t.Skipf("db unreachable: %v", err)
	}

	ids := []string{"JVNDB-2026-000172", "JVNDB-2026-044393", "JVNDB-2026-039068", "JVNDB-2026-042402",
		"JVNDB-2026-000175", "JVNDB-2026-044117", "JVNDB-2025-009576"}
	// The fixture's ids are real; this test owns them in a scratch database
	// only. Refuse to run against one that already holds them from a real sync.
	var pre int
	if err := migDB.QueryRow(`SELECT COUNT(*) FROM jvndb_advisories WHERE jvndb_id = ANY($1)`, pq.Array(ids)).Scan(&pre); err != nil {
		t.Fatal(err)
	}
	if pre != 0 {
		t.Skip("the fixture's advisories already exist in this database; run against a scratch database")
	}
	reset := func() {
		if _, err := migDB.Exec(`DELETE FROM jvndb_advisories WHERE jvndb_id = ANY($1)`, pq.Array(ids)); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		if _, err := migDB.Exec(`DELETE FROM jvndb_feed_state WHERE feed = 'recent'`); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}
	reset()
	t.Cleanup(reset)

	doc, err := os.ReadFile("testdata/jvndb/recent_trimmed.rdf")
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(doc) // no validators: every fetch is a full read
	}))
	defer srv.Close()

	svc := NewJVNDBRSSService(repository.NewJVNDBRepository(appDB), srv.URL, false, time.Hour, 0)
	ctx := context.Background()
	for round := 0; round < 2; round++ {
		res, err := svc.Sync(ctx)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if res.Feeds[0].Status != "success" || res.Feeds[0].Written != 7 {
			t.Fatalf("round %d: %+v", round, res.Feeds)
		}
		var advisories, mappings int
		_ = migDB.QueryRow(`SELECT COUNT(*) FROM jvndb_advisories WHERE jvndb_id = ANY($1)`, pq.Array(ids)).Scan(&advisories)
		_ = migDB.QueryRow(`SELECT COUNT(*) FROM jvndb_advisory_cves WHERE jvndb_id = ANY($1)`, pq.Array(ids)).Scan(&mappings)
		if advisories != 7 || mappings != 11 {
			t.Fatalf("round %d: advisories=%d mappings=%d, want 7 / 11", round, advisories, mappings)
		}
		// Let the next round claim the feed.
		if _, err := migDB.Exec(`UPDATE jvndb_feed_state SET last_attempt_at = NOW() - interval '2 hours' WHERE feed = 'recent'`); err != nil {
			t.Fatal(err)
		}
	}
	if hits != 2 {
		t.Fatalf("hits = %d", hits)
	}
	var status string
	var seen, written int
	if err := migDB.QueryRow(`SELECT last_status, items_seen, items_written FROM jvndb_feed_state WHERE feed = 'recent'`).Scan(&status, &seen, &written); err != nil {
		t.Fatal(err)
	}
	if status != "success" || seen != 7 || written != 7 {
		t.Fatalf("feed state = %s %d %d", status, seen, written)
	}
}

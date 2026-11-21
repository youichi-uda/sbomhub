//go:build integration

// Migration 072: JVNDB RSS storage against a real PostgreSQL, as the runtime
// app role (sbomhub_app, NOBYPASSRLS).
//
//	cd apps/api && DATABASE_URL=... MIGRATE_DATABASE_URL=... \
//	    go test -tags=integration -count=1 -run JVNDBIntegration ./internal/repository
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// jvndbTestIDs returns unique JVNDB / CVE ids for this run (the tables are a
// shared global catalogue) and reaps them afterwards.
func jvndbTestIDs(t *testing.T, migDB *sql.DB, n int) (ids, cves []string) {
	t.Helper()
	base := uuid.New().ID() % 900000
	for i := 0; i < n; i++ {
		ids = append(ids, fmt.Sprintf("JVNDB-2099-%06d%03d", base, i))
		cves = append(cves, fmt.Sprintf("CVE-2099-%07d%03d", base, i))
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM jvndb_advisories WHERE jvndb_id = ANY($1)`, pq.Array(ids)); err != nil {
			t.Errorf("cleanup advisories: %v", err)
		}
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`, pq.Array(cves)); err != nil {
			t.Errorf("cleanup vulnerabilities: %v", err)
		}
	})
	return ids, cves
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestJVNDBIntegration_UpsertGuardAndCVESet(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	migDB := openOrSkip(t, migURL)
	appDB := openOrSkip(t, appURL)
	ids, cves := jvndbTestIDs(t, migDB, 3)
	repo := NewJVNDBRepository(appDB)
	ctx := context.Background()

	t1 := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)
	n, err := repo.UpsertAdvisories(ctx, []JVNDBAdvisoryRecord{
		{ID: ids[0], Title: "v1", CVEs: []string{cves[0], cves[1]}, Published: ptrTime(t1), Modified: ptrTime(t1)},
	})
	if err != nil || n != 1 {
		t.Fatalf("insert: n=%d err=%v", n, err)
	}
	// Newer item replaces title and the CVE set.
	n, err = repo.UpsertAdvisories(ctx, []JVNDBAdvisoryRecord{
		{ID: ids[0], Title: "v2", CVEs: []string{cves[1], cves[2]}, Published: ptrTime(t1), Modified: ptrTime(t2)},
	})
	if err != nil || n != 1 {
		t.Fatalf("update: n=%d err=%v", n, err)
	}
	// An older item (a stale year feed) is ignored.
	n, err = repo.UpsertAdvisories(ctx, []JVNDBAdvisoryRecord{
		{ID: ids[0], Title: "stale", CVEs: []string{cves[0]}, Published: ptrTime(t1), Modified: ptrTime(t1)},
	})
	if err != nil || n != 0 {
		t.Fatalf("stale: n=%d err=%v, want 0 written", n, err)
	}
	// So is an item without a modified time over a dated row.
	n, err = repo.UpsertAdvisories(ctx, []JVNDBAdvisoryRecord{{ID: ids[0], Title: "undated", CVEs: nil}})
	if err != nil || n != 0 {
		t.Fatalf("undated: n=%d err=%v, want 0 written", n, err)
	}
	var title string
	if err := appDB.QueryRow(`SELECT title FROM jvndb_advisories WHERE jvndb_id = $1`, ids[0]).Scan(&title); err != nil || title != "v2" {
		t.Fatalf("title = %q err=%v, want v2", title, err)
	}
	rows, err := appDB.Query(`SELECT cve_id FROM jvndb_advisory_cves WHERE jvndb_id = $1 ORDER BY cve_id`, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		got = append(got, c)
	}
	_ = rows.Close()
	want := []string{cves[1], cves[2]}
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("cve set = %v, want %v (replaced, not merged)", got, want)
	}

	// The CHECK constraints refuse what the parser would never hand over.
	if _, err := repo.UpsertAdvisories(ctx, []JVNDBAdvisoryRecord{{ID: "JVNDB-x", Title: "t"}}); err == nil {
		t.Error("a malformed JVNDB id must be refused by the table")
	}
	if _, err := repo.UpsertAdvisories(ctx, []JVNDBAdvisoryRecord{{ID: ids[1], Title: "t", CVEs: []string{"cve-1"}}}); err == nil {
		t.Error("a malformed CVE id must be refused by the table")
	}
	var leaked int
	_ = appDB.QueryRow(`SELECT COUNT(*) FROM jvndb_advisories WHERE jvndb_id = $1`, ids[1]).Scan(&leaked)
	if leaked != 0 {
		t.Error("a failed batch must roll back as a whole")
	}
}

func TestJVNDBIntegration_ClaimIsExclusiveAcrossReplicas(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	migDB := openOrSkip(t, migURL)
	appDB := openOrSkip(t, appURL)
	feed := fmt.Sprintf("year:%04d", 1000+uuid.New().ID()%8999)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM jvndb_feed_state WHERE feed = $1`, feed); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	repo := NewJVNDBRepository(appDB)
	ctx := context.Background()

	const replicas = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	var winner *JVNDBFeedState
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, ok, err := repo.ClaimFeed(ctx, feed, time.Hour)
			if err != nil {
				t.Errorf("claim: %v", err)
				return
			}
			if ok {
				mu.Lock()
				wins++
				winner = st
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d replicas claimed the feed in the same interval, want exactly 1", wins)
	}

	// Finish with validators; a later claim (gap elapsed) returns them.
	if err := repo.FinishFeed(ctx, feed, winner.Attempt, JVNDBFeedResult{Status: JVNDBFeedStatusSuccess, SourceURL: "https://m.example/rss/years/jvndb_x.rdf", ETag: `"e1"`, LastModified: "Sun, 15 Nov 2026 00:02:09 GMT", ItemsSeen: 3, ItemsWritten: 3, Completed: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := migDB.Exec(`UPDATE jvndb_feed_state SET last_attempt_at = NOW() - interval '2 hours' WHERE feed = $1`, feed); err != nil {
		t.Fatal(err)
	}
	prev, ok, err := repo.ClaimFeed(ctx, feed, time.Hour)
	if err != nil || !ok {
		t.Fatalf("claim after the gap: ok=%v err=%v", ok, err)
	}
	if prev.ETag != `"e1"` || prev.SourceURL != "https://m.example/rss/years/jvndb_x.rdf" || !prev.Completed || prev.LastSuccessAt == nil || prev.LastStatus != "success" {
		t.Fatalf("previous state = %+v", prev)
	}
	// A failed attempt keeps the validators and the completion.
	if err := repo.FinishFeed(ctx, feed, prev.Attempt, JVNDBFeedResult{Status: JVNDBFeedStatusFailed, ErrorMessage: "JVNDB RSS fetch failed", ETag: `"ignored"`}); err != nil {
		t.Fatal(err)
	}
	states, err := repo.FeedStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st := states[feed]; st.ETag != `"e1"` || !st.Completed || st.LastStatus != "failed" {
		t.Fatalf("after failure = %+v", st)
	}
}

// End-to-end through the list read, as the app role inside a tenant
// transaction (the shape TenantTx gives the handler).
func TestJVNDBIntegration_ProjectListCarriesAdvisory(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	migDB := openOrSkip(t, migURL)
	appDB := openOrSkip(t, appURL)
	ids, cves := jvndbTestIDs(t, migDB, 2)
	tenantID, componentID := m54SeedComponentForLink(t, migDB)

	vulnID := uuid.New()
	if _, err := migDB.Exec(`INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source) VALUES ($1, $2, 'nvd', 'HIGH', 7.5, 'NVD')`, vulnID, cves[0]); err != nil {
		t.Fatal(err)
	}
	var sbomID uuid.UUID
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1, $2)`, componentID, vulnID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT sbom_id FROM components WHERE id = $1`, componentID).Scan(&sbomID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	pub := time.Date(2026, 11, 19, 7, 12, 0, 0, time.UTC)
	if _, err := NewJVNDBRepository(appDB).UpsertAdvisories(context.Background(), []JVNDBAdvisoryRecord{
		{ID: ids[0], Title: "テスト用の脆弱性", CVEs: []string{cves[0]}, Published: &pub, Modified: &pub},
		{ID: ids[1], Title: "無関係", CVEs: []string{cves[1]}, Published: &pub, Modified: &pub},
	}); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := appDB.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE cve_id = ANY($1)`, pq.Array(cves)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("vulnerabilities rows = %d err=%v: storing advisories must never create a finding", count, err)
	}

	err = database.WithTxFunc(context.Background(), appDB, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
			return err
		}
		ctx = database.WithTx(ctx, tx)
		vulns, err := NewComponentRepository(appDB).WithJVNDBEnrichment().GetVulnerabilitiesPaginated(ctx, sbomID, 100, 0, "cvss")
		if err != nil {
			return err
		}
		if len(vulns) != 1 {
			return fmt.Errorf("rows = %d, want 1", len(vulns))
		}
		j := vulns[0].JVNDB
		if len(j) != 1 || j[0].ID != ids[0] || j[0].Title != "テスト用の脆弱性" || j[0].Published == nil || !j[0].Published.Equal(pub) {
			return fmt.Errorf("jvndb = %+v", j)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Codex R1 (Low): the per-CVE cap is applied in SQL; newest first.
func TestJVNDBIntegration_PerCVECap(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	migDB := openOrSkip(t, migURL)
	appDB := openOrSkip(t, appURL)
	ids, cves := jvndbTestIDs(t, migDB, 8)
	var recs []JVNDBAdvisoryRecord
	for i, id := range ids {
		p := time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC)
		recs = append(recs, JVNDBAdvisoryRecord{ID: id, Title: "t", CVEs: []string{cves[0]}, Published: &p, Modified: &p})
	}
	if _, err := NewJVNDBRepository(appDB).UpsertAdvisories(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	vulns := []model.Vulnerability{{CVEID: cves[0]}}
	if err := AttachJVNDB(context.Background(), appDB, vulns); err != nil {
		t.Fatal(err)
	}
	if len(vulns[0].JVNDB) != maxJVNDBPerCVE || vulns[0].JVNDB[0].ID != ids[7] {
		t.Fatalf("got %d advisories, first %s; want %d, newest (%s) first", len(vulns[0].JVNDB), vulns[0].JVNDB[0].ID, maxJVNDBPerCVE, ids[7])
	}
}

func TestJVNDBIntegration_GapUntilOnlyMovesForward(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	migDB := openOrSkip(t, migURL)
	appDB := openOrSkip(t, appURL)
	feed := fmt.Sprintf("year:%04d", 1000+uuid.New().ID()%8999)
	t.Cleanup(func() { _, _ = migDB.Exec(`DELETE FROM jvndb_feed_state WHERE feed = $1`, feed) })
	repo := NewJVNDBRepository(appDB)
	ctx := context.Background()
	claim, _, err := repo.ClaimFeed(ctx, feed, 0)
	if err != nil {
		t.Fatal(err)
	}
	late := time.Date(2026, 11, 18, 8, 24, 0, 0, time.UTC)
	early := late.Add(-72 * time.Hour)
	cm := time.Date(2026, 11, 15, 0, 2, 9, 0, time.UTC)
	for _, g := range []*time.Time{&late, &early, nil} {
		if err := repo.FinishFeed(ctx, feed, claim.Attempt, JVNDBFeedResult{Status: JVNDBFeedStatusSuccess, GapUntil: g, ContentModifiedAt: &cm}); err != nil {
			t.Fatal(err)
		}
	}
	// A failed attempt changes neither.
	if err := repo.FinishFeed(ctx, feed, claim.Attempt, JVNDBFeedResult{Status: JVNDBFeedStatusFailed, GapUntil: &early}); err != nil {
		t.Fatal(err)
	}
	states, err := repo.FeedStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st := states[feed]
	if st.GapUntil == nil || !st.GapUntil.Equal(late) || st.ContentModifiedAt == nil || !st.ContentModifiedAt.Equal(cm) {
		t.Fatalf("state = %+v", st)
	}
}

// Codex R2 (Medium): an attempt can only finish the claim it holds; a stale
// attempt cannot overwrite the state a newer attempt wrote.
func TestJVNDBIntegration_FinishIsFencedToTheClaim(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	migDB := openOrSkip(t, migURL)
	appDB := openOrSkip(t, appURL)
	feed := fmt.Sprintf("year:%04d", 1000+uuid.New().ID()%8999)
	t.Cleanup(func() { _, _ = migDB.Exec(`DELETE FROM jvndb_feed_state WHERE feed = $1`, feed) })
	repo := NewJVNDBRepository(appDB)
	ctx := context.Background()
	old, ok, err := repo.ClaimFeed(ctx, feed, time.Hour)
	if err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if _, err := migDB.Exec(`UPDATE jvndb_feed_state SET last_attempt_at = NOW() - interval '2 hours' WHERE feed = $1`, feed); err != nil {
		t.Fatal(err)
	}
	cur, ok, err := repo.ClaimFeed(ctx, feed, time.Hour)
	if err != nil || !ok || cur.Attempt == old.Attempt {
		t.Fatalf("second claim: %v %v %+v", ok, err, cur)
	}
	if err := repo.FinishFeed(ctx, feed, cur.Attempt, JVNDBFeedResult{Status: JVNDBFeedStatusSuccess, ETag: `"new"`, Completed: true}); err != nil {
		t.Fatal(err)
	}
	if err := repo.FinishFeed(ctx, feed, old.Attempt, JVNDBFeedResult{Status: JVNDBFeedStatusFailed, ETag: `"old"`}); !errors.Is(err, ErrJVNDBClaimLost) {
		t.Fatalf("stale finish: err = %v, want ErrJVNDBClaimLost", err)
	}
	states, _ := repo.FeedStates(ctx)
	if st := states[feed]; st.LastStatus != "success" || st.ETag != `"new"` {
		t.Fatalf("state overwritten by a stale attempt: %+v", st)
	}
}

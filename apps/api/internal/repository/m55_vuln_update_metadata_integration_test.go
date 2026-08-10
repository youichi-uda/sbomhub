//go:build integration

// Package repository — M55: UpdateMetadata is the CVE catalogue's missing
// update path, and its refusal rules are the whole point of it.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M55UpdateMetadata' ./internal/repository
//
// Before M55 this repository could Create a catalogue row and could move the
// EPSS columns, and that was all: nothing could refresh a CVE's description,
// severity, CVSS score or published date once the row existed. The only write
// that reached those columns was Create's ON CONFLICT clause, which a caller
// only reaches when it believes the row is ABSENT — so in the ordinary case
// (row present) a CVE re-scored LOW -> CRITICAL upstream stayed LOW here.
//
// The scheduler's daily job is the caller and the owner; these tests pin the
// contract it depends on, at the level where the SQL lives.
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	_ "github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

func m55MetaCVEID() string {
	return fmt.Sprintf("CVE-2092-%07d", uuid.New().ID()%10000000)
}

// m55SeedCatalogueRow writes one catalogue row and returns its cve_id. EPSS
// and KEV columns are populated so the "other owners' columns are untouched"
// assertions have something to observe. sourceModifiedAt nil stores SQL NULL,
// which is the legacy state every pre-066 row is in.
func m55SeedCatalogueRow(t *testing.T, migDB *sql.DB, source string, sourceModifiedAt *time.Time) string {
	t.Helper()
	cveID := m55MetaCVEID()
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("cleanup: delete %s: %v", cveID, err)
		}
	})
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source,
			published_at, updated_at, source_modified_at,
			epss_score, epss_percentile, epss_updated_at, epss_checked_at,
			in_kev, kev_date_added, kev_due_date, kev_ransomware_use)
		VALUES ($1, $2, 'stored description', 'LOW', 2.0, $3,
			'2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', $4,
			0.25, 0.9, NOW(), NOW(),
			true, '2025-02-02', '2025-03-03', true)`,
		uuid.New(), cveID, source, sourceModifiedAt); err != nil {
		t.Fatalf("seed %s: %v", cveID, err)
	}
	return cveID
}

func m55Meta(cveID string, severity string, score float64, description string, sourceModifiedAt *time.Time) VulnerabilityMetadata {
	return VulnerabilityMetadata{
		CVEID:            cveID,
		Description:      description,
		Severity:         severity,
		CVSSScore:        &score,
		Source:           "NVD",
		SourceModifiedAt: sourceModifiedAt,
	}
}

// TestM55UpdateMetadata_RowAbsentIsNotAnInsert: the method must never grow the
// catalogue. Its caller replays NVD's whole modification window, so an upsert
// here would import every CVE NVD has touched, matched or not.
func TestM55UpdateMetadata_RowAbsentIsNotAnInsert(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	cveID := m55MetaCVEID()
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("cleanup: delete %s: %v", cveID, err)
		}
	})

	mod := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	outcome, err := NewVulnerabilityRepository(appDB).
		UpdateMetadata(context.Background(), m55Meta(cveID, "CRITICAL", 9.8, "should not be inserted", &mod))
	if err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if outcome != MetadataRowAbsent {
		t.Errorf("outcome = %v, want %v", outcome, MetadataRowAbsent)
	}

	var n int
	if err := migDB.QueryRow(`SELECT count(*) FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("rows for an absent CVE = %d, want 0 — UpdateMetadata must never insert", n)
	}
}

// TestM55UpdateMetadata_LegacyNULLTimestampIsWritable: a stored NULL means
// "unknown", not "newer than everything". Every row written before migration
// 066 and every row the per-component scanners create has one, and those are
// exactly the frozen rows this method exists to unfreeze.
func TestM55UpdateMetadata_LegacyNULLTimestampIsWritable(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	cveID := m55SeedCatalogueRow(t, migDB, "NVD", nil)
	mod := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	outcome, err := NewVulnerabilityRepository(appDB).
		UpdateMetadata(context.Background(), m55Meta(cveID, "CRITICAL", 9.8, "refreshed", &mod))
	if err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if outcome != MetadataWritten {
		t.Fatalf("outcome = %v, want %v — a legacy row with no recorded upstream timestamp must be writable", outcome, MetadataWritten)
	}

	var severity string
	var stored sql.NullTime
	if err := migDB.QueryRow(`SELECT severity, source_modified_at FROM vulnerabilities WHERE cve_id = $1`, cveID).
		Scan(&severity, &stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", severity)
	}
	if !stored.Valid || !stored.Time.UTC().Equal(mod) {
		t.Errorf("source_modified_at = %v (valid=%v), want %v — the write must record what it was arbitrated on, "+
			"or the row stays unarbitrable forever", stored.Time.UTC(), stored.Valid, mod)
	}
}

// TestM55UpdateMetadata_OlderRecordIsRefused is the guard itself.
func TestM55UpdateMetadata_OlderRecordIsRefused(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	stored := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	cveID := m55SeedCatalogueRow(t, migDB, "NVD", &stored)
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	outcome, err := NewVulnerabilityRepository(appDB).
		UpdateMetadata(context.Background(), m55Meta(cveID, "CRITICAL", 9.8, "from an older upstream record", &older))
	if err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if outcome != MetadataRefusedStale {
		t.Fatalf("outcome = %v, want %v", outcome, MetadataRefusedStale)
	}

	var description string
	var mod sql.NullTime
	if err := migDB.QueryRow(`SELECT description, source_modified_at FROM vulnerabilities WHERE cve_id = $1`, cveID).
		Scan(&description, &mod); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if description != "stored description" {
		t.Errorf("description = %q, want the stored one — a refused write must change nothing", description)
	}
	if !mod.Valid || !mod.Time.UTC().Equal(stored) {
		t.Errorf("source_modified_at = %v, want %v — a refused write must not move the arbiter backwards either", mod.Time.UTC(), stored)
	}
}

// TestM55UpdateMetadata_EqualTimestampDoesNotOverwrite pins `<`, not `<=`
// (Codex M55 S2, High).
//
// Two DIFFERENT bodies can carry the SAME upstream lastModified: baseURL is
// overridable to a mirror for air-gapped installs, and a cached or
// partially-populated mirror page is exactly a stale body under an unchanged
// timestamp. Under `<=` the second one wins, which is a silent downgrade
// reachable by replay alone. Under `<` the first body stands.
//
// The earlier justification for `<=` — "repair a row left half-written by a
// failed run" — was false: UpdateMetadata is one atomic statement, so a
// failure leaves every owned field unchanged, never some of them.
func TestM55UpdateMetadata_EqualTimestampDoesNotOverwrite(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	stored := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	// Seeded strictly OLDER than T so the first body at T legitimately lands.
	seeded := stored.Add(-time.Hour)
	cveID := m55SeedCatalogueRow(t, migDB, "NVD", &seeded)
	repo := NewVulnerabilityRepository(appDB)

	// First body at T wins.
	if outcome, err := repo.UpdateMetadata(context.Background(),
		m55Meta(cveID, "CRITICAL", 9.8, "first body at T", &stored)); err != nil {
		t.Fatalf("UpdateMetadata (first): %v", err)
	} else if outcome != MetadataWritten {
		t.Fatalf("first write outcome = %v, want %v", outcome, MetadataWritten)
	}

	// A different body at the SAME T must not replace it.
	outcome, err := repo.UpdateMetadata(context.Background(),
		m55Meta(cveID, "LOW", 2.0, "stale mirror body at the same T", &stored))
	if err != nil {
		t.Fatalf("UpdateMetadata (second): %v", err)
	}
	if outcome != MetadataRefusedStale {
		t.Errorf("outcome = %v, want %v", outcome, MetadataRefusedStale)
	}
	var severity, description string
	if err := migDB.QueryRow(`SELECT severity, description FROM vulnerabilities WHERE cve_id = $1`, cveID).
		Scan(&severity, &description); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if severity != "CRITICAL" || description != "first body at T" {
		t.Errorf("row = %s / %q, want CRITICAL / \"first body at T\": a second body carrying the same upstream "+
			"timestamp downgraded the row, which a replay against a mirror can do at will", severity, description)
	}

	// A strictly newer record still gets through — the guard must not have
	// become a first-write-wins latch.
	newer := stored.Add(time.Hour)
	if outcome, err := repo.UpdateMetadata(context.Background(),
		m55Meta(cveID, "MEDIUM", 5.0, "genuinely newer record", &newer)); err != nil {
		t.Fatalf("UpdateMetadata (newer): %v", err)
	} else if outcome != MetadataWritten {
		t.Errorf("outcome for a strictly newer record = %v, want %v", outcome, MetadataWritten)
	}
}

// TestM55UpdateMetadata_UnknownAgeIsRefusedAgainstAKnownRecord: a record whose
// upstream timestamp we could not read is not evidence of anything. Letting it
// overwrite a row we know is fresh reopens the downgrade the guard closes.
func TestM55UpdateMetadata_UnknownAgeIsRefusedAgainstAKnownRecord(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	stored := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	cveID := m55SeedCatalogueRow(t, migDB, "NVD", &stored)

	repo := NewVulnerabilityRepository(appDB)
	outcome, err := repo.UpdateMetadata(context.Background(), m55Meta(cveID, "LOW", 1.0, "no upstream timestamp", nil))
	if err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if outcome != MetadataRefusedStale {
		t.Errorf("outcome = %v, want %v", outcome, MetadataRefusedStale)
	}

	// And the refusal is not permanent: the next record that carries a
	// timestamp is arbitrated normally.
	newer := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	outcome, err = repo.UpdateMetadata(context.Background(), m55Meta(cveID, "CRITICAL", 9.8, "later record", &newer))
	if err != nil {
		t.Fatalf("UpdateMetadata (later): %v", err)
	}
	if outcome != MetadataWritten {
		t.Errorf("outcome = %v, want %v — refusing an unknown-age record must not block later ones", outcome, MetadataWritten)
	}
}

// TestM55UpdateMetadata_LeavesOtherOwnersColumnsAlone. The EPSS columns belong
// to UpdateEPSSScores / MarkEPSSChecked, which maintain an invariant across all
// four of them (migration 059); the KEV columns belong to the KEV sync. A
// catalogue refresh that touched either would break a contract from outside.
// `id` is referenced by component_vulnerabilities and must never move.
func TestM55UpdateMetadata_LeavesOtherOwnersColumnsAlone(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	cveID := m55SeedCatalogueRow(t, migDB, "NVD", nil)

	var beforeID uuid.UUID
	if err := migDB.QueryRow(`SELECT id FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&beforeID); err != nil {
		t.Fatalf("read id: %v", err)
	}

	mod := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if _, err := NewVulnerabilityRepository(appDB).
		UpdateMetadata(context.Background(), m55Meta(cveID, "CRITICAL", 9.8, "refreshed", &mod)); err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}

	var afterID uuid.UUID
	var epssScore, epssPercentile sql.NullFloat64
	var epssUpdated, epssChecked sql.NullTime
	var inKEV, kevRansom sql.NullBool
	var kevAdded, kevDue sql.NullTime
	var storedCVEID string
	if err := migDB.QueryRow(`
		SELECT id, cve_id, epss_score, epss_percentile, epss_updated_at, epss_checked_at,
		       in_kev, kev_date_added, kev_due_date, kev_ransomware_use
		FROM vulnerabilities WHERE cve_id = $1`, cveID).
		Scan(&afterID, &storedCVEID, &epssScore, &epssPercentile, &epssUpdated, &epssChecked,
			&inKEV, &kevAdded, &kevDue, &kevRansom); err != nil {
		t.Fatalf("read back: %v", err)
	}

	if afterID != beforeID {
		t.Errorf("id moved %s -> %s; component_vulnerabilities references it", beforeID, afterID)
	}
	if storedCVEID != cveID {
		t.Errorf("cve_id = %q, want %q", storedCVEID, cveID)
	}
	if !epssScore.Valid || epssScore.Float64 != 0.25 || !epssPercentile.Valid || epssPercentile.Float64 != 0.9 {
		t.Errorf("EPSS score/percentile = %v/%v, want 0.25/0.9 untouched", epssScore, epssPercentile)
	}
	if !epssUpdated.Valid || !epssChecked.Valid {
		t.Errorf("EPSS timestamps cleared (updated valid=%v checked valid=%v); migration 059's invariant is the EPSS sync's to maintain",
			epssUpdated.Valid, epssChecked.Valid)
	}
	if !inKEV.Valid || !inKEV.Bool || !kevAdded.Valid || !kevDue.Valid || !kevRansom.Valid || !kevRansom.Bool {
		t.Errorf("KEV columns changed (in_kev=%v added=%v due=%v ransomware=%v), want the KEV sync's values untouched",
			inKEV, kevAdded.Valid, kevDue.Valid, kevRansom)
	}
}

// TestM55UpdateMetadata_PublishedAtIsNotClearedByAnAbsentValue: an absent
// upstream date means the feed did not give us one, not that the CVE was never
// published. Clearing the stored value on every record that lacks it would let
// one malformed page blank the date on a global, cross-tenant row — the blast
// radius MarkEPSSChecked exists to avoid on the EPSS side.
func TestM55UpdateMetadata_PublishedAtIsNotClearedByAnAbsentValue(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	cveID := m55SeedCatalogueRow(t, migDB, "NVD", nil)
	mod := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	m := m55Meta(cveID, "HIGH", 7.5, "refreshed without a published date", &mod)
	m.PublishedAt = nil
	if _, err := NewVulnerabilityRepository(appDB).UpdateMetadata(context.Background(), m); err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}

	var published sql.NullTime
	if err := migDB.QueryRow(`SELECT published_at FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&published); err != nil {
		t.Fatalf("read back: %v", err)
	}
	want := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if !published.Valid || !published.Time.UTC().Equal(want) {
		t.Errorf("published_at = %v (valid=%v), want the stored %v preserved", published.Time.UTC(), published.Valid, want)
	}
}

// TestM55UpdateMetadata_NilCVSSScoreClearsTheScore: "NVD withdrew the metrics"
// has to be representable. nil writes SQL NULL — un-scored — and NOT 0.0,
// which is a real CVSS score ("None") that reads downstream as a harmless
// finding.
func TestM55UpdateMetadata_NilCVSSScoreClearsTheScore(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	cveID := m55SeedCatalogueRow(t, migDB, "NVD", nil)
	mod := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	if _, err := NewVulnerabilityRepository(appDB).UpdateMetadata(context.Background(), VulnerabilityMetadata{
		CVEID:            cveID,
		Description:      "metrics withdrawn upstream",
		Severity:         "UNKNOWN",
		CVSSScore:        nil,
		Source:           "NVD",
		SourceModifiedAt: &mod,
	}); err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}

	var score sql.NullFloat64
	if err := migDB.QueryRow(`SELECT cvss_score FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&score); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if score.Valid {
		t.Errorf("cvss_score = %v, want NULL — 0.0 is a real score and must not be used as the 'no score' sentinel", score.Float64)
	}
}

// m55AwaitLockWaiter blocks until some backend is WAITING on a lock on
// `vulnerabilities`, i.e. until the racing UpdateMetadata has demonstrably
// reached the held row lock.
//
// The race tests used a fixed sleep, which proves nothing: a goroutine
// scheduled after the holder commits reads post-commit state and passes even
// against the unlocked implementation (Codex M55 R2, Low — a false-negative
// generator, exactly the shape M54 rejected elsewhere). pg_locks is readable
// by any role and shows ungranted entries, so the wait is observable rather
// than assumed.
func m55AwaitLockWaiter(t *testing.T, db *sql.DB, holderXID int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		// A ROW-level wait does not appear as an ungranted lock on the
		// relation: the waiter blocks on the HOLDING TRANSACTION'S XID (and,
		// transiently, on a tuple lock). The XID is what makes this specific —
		// polling for "any ungranted lock in the cluster" would be satisfied
		// by an unrelated waiter and let the test pass without the race ever
		// happening (Codex M55 R3, Low). The bigint->text->xid cast is how a
		// 64-bit txid_current() value is compared with pg_locks' 32-bit xid.
		if err := db.QueryRow(`
			SELECT count(*) FROM pg_locks
			WHERE NOT granted AND locktype = 'transactionid' AND transactionid = $1::text::xid`,
			holderXID).Scan(&waiting); err != nil {
			t.Fatalf("poll pg_locks: %v", err)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no backend ever blocked on the holder's transaction: the racing write never reached the contended row, " +
		"so this test would pass against an implementation with no lock at all")
}

// m55HoldRowLock opens a transaction, applies `stmt` to the row (taking its
// lock), and returns a func that commits. The caller races UpdateMetadata
// against the held lock.
func m55HoldRowLock(t *testing.T, db *sql.DB, stmt, cveID string) (xid int64, commit func()) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin lock holder: %v", err)
	}
	if _, err := tx.Exec(stmt, cveID); err != nil {
		_ = tx.Rollback()
		t.Fatalf("lock holder statement: %v", err)
	}
	if err := tx.QueryRow(`SELECT txid_current()`).Scan(&xid); err != nil {
		_ = tx.Rollback()
		t.Fatalf("read holder xid: %v", err)
	}
	committed := false
	t.Cleanup(func() {
		if !committed {
			_ = tx.Rollback()
		}
	})
	return xid, func() {
		if err := tx.Commit(); err != nil {
			t.Errorf("lock holder commit: %v", err)
		}
		committed = true
	}
}

// TestM55UpdateMetadata_StaleWaiterLosesToACommittedNewerWrite is the
// concurrency half of the staleness guard, and it is the half a single-
// connection test cannot see (Codex M55 R1, High).
//
// The guard reads source_modified_at and then updates the row. Under READ
// COMMITTED those are two different views of the row unless the read TAKES THE
// LOCK: a writer that arrives second reads the pre-image, blocks on the row
// lock held by a fresher writer, and — when it unblocks — applies a decision
// made against a value that is no longer there. Measured against the
// unlocked CTE: an NVD record modified 2026-02 overwrote one modified 2026-07
// that had committed while it waited.
//
// This is not exotic for this job. The catalogue is global: the scanner's
// Create races cve_sync, and two overlapping ticks race each other.
func TestM55UpdateMetadata_StaleWaiterLosesToACommittedNewerWrite(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cveID := m55SeedCatalogueRow(t, migDB, "NVD", &old)

	// A fresher record lands and holds its lock.
	holderXID, commit := m55HoldRowLock(t, migDB, `
		UPDATE vulnerabilities
		SET severity = 'CRITICAL', description = 'fresher record',
		    source_modified_at = '2026-07-01T00:00:00Z'
		WHERE cve_id = $1`, cveID)

	// A staler record arrives while that lock is held.
	february := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	type result struct {
		outcome MetadataWriteOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		o, err := NewVulnerabilityRepository(appDB).
			UpdateMetadata(context.Background(), m55Meta(cveID, "MEDIUM", 5.0, "staler record", &february))
		done <- result{o, err}
	}()

	// Wait until the racing write is demonstrably blocked on the row lock,
	// then let the fresher write win.
	m55AwaitLockWaiter(t, migDB, holderXID)
	commit()

	got := <-done
	if got.err != nil {
		t.Fatalf("UpdateMetadata: %v", got.err)
	}
	if got.outcome != MetadataRefusedStale {
		t.Errorf("outcome = %v, want %v", got.outcome, MetadataRefusedStale)
	}

	var severity, description string
	var mod sql.NullTime
	if err := migDB.QueryRow(`SELECT severity, description, source_modified_at FROM vulnerabilities WHERE cve_id = $1`, cveID).
		Scan(&severity, &description, &mod); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if severity != "CRITICAL" || description != "fresher record" {
		t.Errorf("row = %s / %q, want CRITICAL / \"fresher record\": the guard compared against the pre-image it "+
			"read before waiting for the lock, so a stale record overwrote a newer one that committed in between",
			severity, description)
	}
	if !mod.Valid || !mod.Time.UTC().Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("source_modified_at = %v, want 2026-07-01", mod.Time.UTC())
	}
}

// TestM55UpdateMetadata_ConcurrentDeleteReportsRowAbsent: "the row was there
// when I looked and gone when I wrote" must not be reported as a refused stale
// write. The caller acts on the difference — a stale refusal is a no-op it
// ignores, an absent row means the id it is about to link against is gone.
func TestM55UpdateMetadata_ConcurrentDeleteReportsRowAbsent(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cveID := m55SeedCatalogueRow(t, migDB, "NVD", &old)

	holderXID, commit := m55HoldRowLock(t, migDB, `DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID)

	july := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	type result struct {
		outcome MetadataWriteOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		o, err := NewVulnerabilityRepository(appDB).
			UpdateMetadata(context.Background(), m55Meta(cveID, "CRITICAL", 9.8, "after the delete", &july))
		done <- result{o, err}
	}()

	m55AwaitLockWaiter(t, migDB, holderXID)
	commit()

	got := <-done
	if got.err != nil {
		t.Fatalf("UpdateMetadata: %v", got.err)
	}
	if got.outcome != MetadataRowAbsent {
		t.Errorf("outcome = %v, want %v — a row deleted under the write is absent, not stale", got.outcome, MetadataRowAbsent)
	}
}

// TestM55UpdateMetadata_UnknownAgeIsRefusedAgainstALegacyNULLRow closes the
// other half of the unknown-age rule (Codex M55 R1, High). The legacy-NULL
// exception exists so a row with no recorded upstream time can be refreshed
// ONCE and then arbitrated normally — it is not a licence for an undateable
// record to write. A record we cannot date is not evidence about anything, and
// accepting it here would let a malformed feed page downgrade legacy rows
// repeatedly while never establishing an arbiter that would stop it.
func TestM55UpdateMetadata_UnknownAgeIsRefusedAgainstALegacyNULLRow(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	cveID := m55SeedCatalogueRow(t, migDB, "NVD", nil)

	outcome, err := NewVulnerabilityRepository(appDB).
		UpdateMetadata(context.Background(), m55Meta(cveID, "LOW", 1.0, "undateable record", nil))
	if err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if outcome != MetadataRefusedStale {
		t.Errorf("outcome = %v, want %v", outcome, MetadataRefusedStale)
	}
	var severity string
	if err := migDB.QueryRow(`SELECT severity FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&severity); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if severity != "LOW" {
		t.Errorf("severity = %q; the seeded row is LOW, so this assertion is only meaningful with a differing value", severity)
	}
	var description string
	if err := migDB.QueryRow(`SELECT description FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&description); err != nil {
		t.Fatalf("read back description: %v", err)
	}
	if description != "stored description" {
		t.Errorf("description = %q, want the stored one — an undateable record must change nothing", description)
	}
}

// TestM55Create_ConflictDoesNotRewriteMetadata pins the other half of the
// ownership decision (Codex M55 R1, High). Create is the SCANNER's entry
// point, and the scanner is a pure linker: its conflict branch must adopt the
// stored id (the M54 post-condition) WITHOUT rewriting metadata the catalogue
// owner wrote. Before this, a scan racing cve_sync could put its own — older,
// or JVN-sourced — description and severity onto a row that had just been
// refreshed, and because Create does not touch source_modified_at the
// staleness guard would then defend the corrupted values as fresh.
func TestM55Create_ConflictDoesNotRewriteMetadata(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	july := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	cveID := m55SeedCatalogueRow(t, migDB, "NVD", &july)
	var storedID uuid.UUID
	if err := migDB.QueryRow(`SELECT id FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&storedID); err != nil {
		t.Fatalf("read stored id: %v", err)
	}
	// Make the owner-written row unmistakable.
	if _, err := migDB.Exec(`UPDATE vulnerabilities SET severity='CRITICAL', cvss_score=9.8, description='owner wrote this' WHERE cve_id=$1`, cveID); err != nil {
		t.Fatalf("arrange: %v", err)
	}

	scannerScore := 1.0
	pub := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()
	v := &model.Vulnerability{
		ID: uuid.New(), CVEID: cveID, Description: "scanner wrote this",
		Severity: "LOW", CVSSScore: &scannerScore, Source: "JVN",
		PublishedAt: &pub, UpdatedAt: &now,
	}
	if err := NewVulnerabilityRepository(appDB).Create(context.Background(), v); err != nil {
		t.Fatalf("Create on an existing cve_id must still succeed: %v", err)
	}
	// M54 post-condition survives.
	if v.ID != storedID {
		t.Errorf("after Create, v.ID = %s, want the stored id %s", v.ID, storedID)
	}

	var severity, description, source string
	var score sql.NullFloat64
	if err := migDB.QueryRow(`SELECT severity, description, source, cvss_score FROM vulnerabilities WHERE cve_id = $1`, cveID).
		Scan(&severity, &description, &source, &score); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if severity != "CRITICAL" || description != "owner wrote this" || source != "NVD" || !score.Valid || score.Float64 != 9.8 {
		t.Errorf("row after a racing Create = %s / %q / %s / %v, want the owner's CRITICAL / \"owner wrote this\" / NVD / 9.8: "+
			"the scanner is a linker and must not rewrite catalogue metadata", severity, description, source, score.Float64)
	}
}

// TestM55Create_ConflictTakesNoRowLock pins the other half of the pure-linker
// boundary (Codex M55 R4, Medium).
//
// The scanners call Create inside a TENANT transaction that lives for the
// whole sweep. A conflict branch that WRITES — even a self-assignment like
// `SET updated_at = updated_at` — takes the row's lock and holds it until that
// transaction commits, on a GLOBAL row shared with every other tenant. The
// catalogue owner's UpdateMetadata locks the same row FOR UPDATE, so it would
// queue behind an unrelated tenant's scan for as long as that scan runs.
//
// The test holds an open transaction across a conflicting Create and then
// requires UpdateMetadata, on a different connection, to complete anyway.
func TestM55Create_ConflictTakesNoRowLock(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	july := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	cveID := m55SeedCatalogueRow(t, migDB, "NVD", &july)

	// A scanner's tenant transaction, still open.
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin scanner tx: %v", err)
	}
	committed := false
	t.Cleanup(func() {
		if !committed {
			_ = tx.Rollback()
		}
	})
	txCtx := database.WithTx(context.Background(), tx)

	score := 1.0
	pub := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()
	if err := NewVulnerabilityRepository(appDB).Create(txCtx, &model.Vulnerability{
		ID: uuid.New(), CVEID: cveID, Description: "scanner", Severity: "LOW",
		CVSSScore: &score, Source: "JVN", PublishedAt: &pub, UpdatedAt: &now,
	}); err != nil {
		t.Fatalf("Create inside the scanner tx: %v", err)
	}

	// The catalogue owner, on its own connection, must not be blocked.
	august := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	done := make(chan error, 1)
	go func() {
		_, uerr := NewVulnerabilityRepository(appDB).
			UpdateMetadata(context.Background(), m55Meta(cveID, "CRITICAL", 9.8, "owner refresh", &august))
		done <- uerr
	}()

	select {
	case uerr := <-done:
		if uerr != nil {
			t.Fatalf("UpdateMetadata: %v", uerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateMetadata blocked behind an open scanner transaction: Create's conflict branch is taking the " +
			"row lock on a GLOBAL row and holding it for the length of one tenant's sweep")
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit scanner tx: %v", err)
	}
	committed = true

	var severity string
	if err := migDB.QueryRow(`SELECT severity FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&severity); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if severity != "CRITICAL" {
		t.Errorf("severity = %q, want the owner's CRITICAL", severity)
	}
}

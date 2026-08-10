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

// TestM55UpdateMetadata_EqualTimestampIsApplied: `<=`, not `<`. Re-applying a
// record with the same upstream timestamp has to work, or a row left
// half-written by a failed run can only be repaired by waiting for upstream to
// touch the CVE again.
func TestM55UpdateMetadata_EqualTimestampIsApplied(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	stored := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	cveID := m55SeedCatalogueRow(t, migDB, "NVD", &stored)

	outcome, err := NewVulnerabilityRepository(appDB).
		UpdateMetadata(context.Background(), m55Meta(cveID, "HIGH", 7.5, "re-applied", &stored))
	if err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if outcome != MetadataWritten {
		t.Fatalf("outcome = %v, want %v", outcome, MetadataWritten)
	}
	var description string
	if err := migDB.QueryRow(`SELECT description FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&description); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if description != "re-applied" {
		t.Errorf("description = %q, want the re-applied text", description)
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

//go:build integration

// Package scheduler — M67: one CVSS selection rule for every catalogue writer,
// and how rows stored under the old rule converge.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M67' ./internal/scheduler
package scheduler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// m67Record is the recorded live NVD record of CVE-2026-34479 (fixture
// p01_cpename_log4j, 2026-11-08): v3.1 Primary 7.5 HIGH beside a v4.0
// Secondary 6.9 MEDIUM. It is re-keyed to id and re-dated to modified so that
// each test owns its row.
func m67Record(t *testing.T, id string, modified time.Time) json.RawMessage {
	t.Helper()
	var page struct {
		Vulnerabilities []map[string]json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(m67Fixture(t, "p01_cpename_log4j"), &page); err != nil {
		t.Fatal(err)
	}
	for _, v := range page.Vulnerabilities {
		var cve map[string]json.RawMessage
		if err := json.Unmarshal(v["cve"], &cve); err != nil {
			t.Fatal(err)
		}
		var gotID string
		_ = json.Unmarshal(cve["id"], &gotID)
		if gotID != "CVE-2026-34479" {
			continue
		}
		cve["id"], _ = json.Marshal(id)
		cve["lastModified"], _ = json.Marshal(modified.UTC().Format(m58Layout))
		b, err := json.Marshal(cve)
		if err != nil {
			t.Fatal(err)
		}
		return json.RawMessage(`{"cve":` + string(b) + `}`)
	}
	t.Fatal("CVE-2026-34479 is not in the fixture")
	return nil
}

func m67Page(recs ...json.RawMessage) string {
	items := make([]string, len(recs))
	for i, r := range recs {
		items[i] = string(r)
	}
	return fmt.Sprintf(`{"resultsPerPage": %d, "startIndex": 0, "totalResults": %d, "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-11-08T07:11:41.000", "vulnerabilities": [%s]}`,
		len(items), len(items), strings.Join(items, ","))
}

type m67Row struct {
	severity    string
	score       sql.NullFloat64
	version     sql.NullString
	sourceModAt sql.NullTime
}

func m67Read(t *testing.T, db *sql.DB, cveID string) m67Row {
	t.Helper()
	var r m67Row
	if err := db.QueryRow(`SELECT COALESCE(severity, ''), cvss_score, cvss_version, source_modified_at
		FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&r.severity, &r.score, &r.version, &r.sourceModAt); err != nil {
		t.Fatalf("read %s: %v", cveID, err)
	}
	return r
}

func m67Cleanup(t *testing.T, migDB *sql.DB, cveID string) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("cleanup %s: %v", cveID, err)
		}
	})
}

// isV31Primary reports whether the row holds the fixture's v3.1 Primary
// assessment: HIGH / 7.5 / "3.1".
func (r m67Row) isV31Primary() bool {
	return r.severity == "HIGH" && r.score.Valid && r.score.Float64 == 7.5 && r.version.Valid && r.version.String == "3.1"
}

func (r m67Row) String() string {
	return fmt.Sprintf("%s/%v(valid=%v)/v%q(valid=%v)", r.severity, r.score.Float64, r.score.Valid, r.version.String, r.version.Valid)
}

// TestM67_WritePathsStoreTheSameCVSS drives the two writers that create
// catalogue rows from NVD — the CVE sync's INSERT and the scanner's Create
// (via NVDService.SearchByCVEID + SaveVulnerability, the same Create the
// per-component scan uses) — over the same recorded record, and requires the
// same stored severity / score / version from both. Before M67 the sync
// stored MEDIUM / 6.9 and the scanner HIGH / 7.5.
func TestM67_WritePathsStoreTheSameCVSS(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m55ProtectWatermark(t, migDB)

	cveID := m55CVEID(t)
	m67Cleanup(t, migDB, cveID)
	modified := time.Date(2026, 8, 11, 19, 33, 44, 513000000, time.UTC)
	rec := m67Record(t, cveID, modified)

	// 1. The sync inserts it (the record carries CPE keywords, so this is the
	// upsertVulnerability INSERT, not the update-only refresh).
	m55Sync(t, appDB, m67Page(rec))
	synced := m67Read(t, migDB, cveID)
	if !synced.isV31Primary() {
		t.Errorf("sync stored %s, want HIGH/7.5/v3.1 (NVD's v3.1 Primary; the v4.0 Secondary 6.9 MEDIUM must not win)", synced)
	}
	if !synced.sourceModAt.Valid || !synced.sourceModAt.Time.Equal(modified) {
		t.Errorf("sync source_modified_at = %v, want %v", synced.sourceModAt.Time, modified)
	}
	if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
		t.Fatal(err)
	}

	// 2. The scanner creates it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(m67Page(rec)))
	}))
	defer srv.Close()
	nvd := service.NewNVDService(repository.NewVulnerabilityRepository(appDB), nil, "", srv.URL, false)
	v, err := nvd.SearchByCVEID(context.Background(), cveID)
	if err != nil || v == nil {
		t.Fatalf("SearchByCVEID: %v, %v", v, err)
	}
	if err := nvd.SaveVulnerability(context.Background(), v); err != nil {
		t.Fatalf("SaveVulnerability: %v", err)
	}
	scanned := m67Read(t, migDB, cveID)
	if scanned.severity != synced.severity || scanned.score != synced.score || scanned.version != synced.version {
		t.Errorf("scanner stored %s, sync stored %s: the two write paths disagree", scanned, synced)
	}
	if scanned.sourceModAt.Valid {
		t.Errorf("scanner dated its row (%v); it must leave source_modified_at NULL so the sync owns it", scanned.sourceModAt.Time)
	}

	// 3. The sync's refresh over the scanner's row keeps the values and dates it.
	m55Sync(t, appDB, m67Page(rec))
	refreshed := m67Read(t, migDB, cveID)
	if !refreshed.isV31Primary() || !refreshed.sourceModAt.Valid {
		t.Errorf("after the sync refresh: %s (dated=%v), want HIGH/7.5/v3.1, dated", refreshed, refreshed.sourceModAt.Valid)
	}
}

// m67NVD is a fake /cves/2.0 honouring lastModStartDate..lastModEndDate and
// startIndex (what the M58 re-read depends on) over raw records.
type m67NVD struct {
	mu   sync.Mutex
	recs []struct {
		raw      json.RawMessage
		modified time.Time
	}
}

func (f *m67NVD) set(raw json.RawMessage, modified time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs = f.recs[:0]
	f.recs = append(f.recs, struct {
		raw      json.RawMessage
		modified time.Time
	}{raw, modified})
}

func (f *m67NVD) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		start, err1 := time.Parse(m58Layout, q.Get("lastModStartDate"))
		end, err2 := time.Parse(m58Layout, q.Get("lastModEndDate"))
		if err1 != nil || err2 != nil {
			t.Errorf("m67: bad window %q..%q", q.Get("lastModStartDate"), q.Get("lastModEndDate"))
		}
		idx, _ := strconv.Atoi(q.Get("startIndex"))
		f.mu.Lock()
		var in []json.RawMessage
		for _, rec := range f.recs {
			if !rec.modified.Before(start) && !rec.modified.After(end) {
				in = append(in, rec.raw)
			}
		}
		f.mu.Unlock()
		if idx > len(in) {
			idx = len(in)
		}
		page := in[idx:]
		items := make([]string, len(page))
		for i, p := range page {
			items[i] = string(p)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"resultsPerPage": %d, "startIndex": %d, "totalResults": %d, "vulnerabilities": [%s]}`,
			len(page), idx, len(in), strings.Join(items, ","))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestM67_ReconcileConvergesARowTheOldSyncDated is the convergence claim for
// existing rows. A row as the pre-M67 sync left it — v4.0 6.9 MEDIUM, dated
// with NVD's lastModified, cvss_version NULL (written before 069) — is offered
// again by the M58 monthly re-read at the SAME lastModified, because NVD has
// not touched the CVE. The strict freshness guard alone refused that, so the
// row would have kept the old rule until NVD next modified the CVE. It must
// now be re-derived exactly once, and only once.
func TestM67_ReconcileConvergesARowTheOldSyncDated(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	cveID := m55CVEID(t)
	m67Cleanup(t, migDB, cveID)
	modified := time.Date(2026, 5, 3, 4, 5, 6, 0, time.UTC)
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at,
			source_modified_at, updated_at)
		VALUES ($1, $2, 'old sync', 'MEDIUM', 6.9, 'NVD', '2026-04-01T00:00:00Z', $3, NOW())`,
		uuid.New(), cveID, modified); err != nil {
		t.Fatalf("seed: %v", err)
	}

	fake := &m67NVD{}
	fake.set(m67Record(t, cveID, modified), modified)
	j := m58Job(appDB, fake.server(t).URL)
	j.canonicalNVD = true // stands in for services.nvd.nist.gov
	m55PinWatermark(t, migDB, time.Now().UTC().Add(-time.Hour))

	out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC())
	if err != nil || !out.Finished {
		t.Fatalf("reconcileCatalogue = %+v, %v", out, err)
	}
	got := m67Read(t, migDB, cveID)
	if !got.isV31Primary() {
		t.Fatalf("after the re-read: %s, want HIGH/7.5/v3.1 — a row the old sync dated did not converge "+
			"because the record's lastModified equals the stored one", got)
	}
	if !got.sourceModAt.Valid || !got.sourceModAt.Time.Equal(modified) {
		t.Errorf("source_modified_at = %v, want unchanged %v", got.sourceModAt.Time, modified)
	}

	// Once re-derived, an equal-timestamp record is refused again: the
	// exception is one-shot, not last-write-wins. A different body under the
	// same lastModified (the mirror case UpdateMetadata guards against) must
	// not move the row.
	other := json.RawMessage(strings.Replace(string(m67Record(t, cveID, modified)), `"baseScore":7.5`, `"baseScore":3.1`, 1))
	if string(other) == string(m67Record(t, cveID, modified)) {
		t.Fatal("test setup: could not alter the v3.1 score")
	}
	fake.set(other, modified)
	m58Fresh(t, migDB)
	if out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC()); err != nil || !out.Finished {
		t.Fatalf("second reconcileCatalogue = %+v, %v", out, err)
	}
	if again := m67Read(t, migDB, cveID); !again.isV31Primary() {
		t.Errorf("a second equal-timestamp record rewrote the re-derived row to %s; the exception must fire once", again)
	}
}

// TestM67_EqualTimestampDoesNotRewriteAnUnscoredOrPost069Row pins the edges of
// the exception directly on UpdateMetadata.
func TestM67_EqualTimestampDoesNotRewriteAnUnscoredOrPost069Row(t *testing.T) {
	_, migURL := schedIntEnv(t)
	migDB := schedOpenOrSkip(t, migURL)
	repo := repository.NewVulnerabilityRepository(migDB)
	modified := time.Date(2026, 5, 3, 4, 5, 6, 0, time.UTC)
	ver := "3.1"
	score := 9.8
	offer := func(id string, version *string) repository.MetadataWriteOutcome {
		t.Helper()
		out, err := repo.UpdateMetadata(context.Background(), repository.VulnerabilityMetadata{
			CVEID: id, Description: "x", Severity: "CRITICAL", CVSSScore: &score, CVSSVersion: version,
			Source: "NVD", SourceModifiedAt: &modified, CanonicalNVD: true,
		})
		if err != nil {
			t.Fatalf("UpdateMetadata: %v", err)
		}
		return out
	}
	seed := func(score any, version any) string {
		id := m55CVEID(t)
		m67Cleanup(t, migDB, id)
		if _, err := migDB.Exec(`INSERT INTO vulnerabilities (id, cve_id, severity, cvss_score, cvss_version, source, source_modified_at)
			VALUES ($1, $2, 'LOW', $3, $4, 'NVD', $5)`, uuid.New(), id, score, version, modified); err != nil {
			t.Fatalf("seed: %v", err)
		}
		return id
	}

	if out := offer(seed(nil, nil), nil); out != repository.MetadataRefusedStale {
		t.Errorf("unscored row offered unscored: %s, want refused_stale (nothing to re-derive)", out)
	}
	// Codex M67 R6, Low: an unscored / severity-only pre-069 row is re-derived
	// too when the offer records a version (e.g. a v2 rating-only CVE the old
	// rule stored UNKNOWN; the new one reads NVD's metric-level rating).
	if out := offer(seed(nil, nil), &ver); out != repository.MetadataWritten {
		t.Errorf("unscored pre-069 row offered a versioned assessment: %s, want written", out)
	}
	if out := offer(seed(2.0, "3.1"), &ver); out != repository.MetadataRefusedStale {
		t.Errorf("post-069 row: %s, want refused_stale (strict `<` applies once a version is recorded)", out)
	}
	if out := offer(seed(2.0, nil), nil); out != repository.MetadataRefusedStale {
		t.Errorf("re-derivation recording no version: %s, want refused_stale (it would not end the exception)", out)
	}
	if out := offer(seed(2.0, nil), &ver); out != repository.MetadataWritten {
		t.Errorf("scored pre-069 row: %s, want written", out)
	}
	// The strictly-older case is untouched by the exception.
	older := modified.Add(-time.Hour)
	id := seed(2.0, nil)
	out, err := repo.UpdateMetadata(context.Background(), repository.VulnerabilityMetadata{
		CVEID: id, Severity: "CRITICAL", CVSSScore: &score, CVSSVersion: &ver, Source: "NVD", SourceModifiedAt: &older,
	})
	if err != nil || out != repository.MetadataRefusedStale {
		t.Errorf("older record over a pre-069 row: %s, %v, want refused_stale", out, err)
	}
}

// TestM67_CVSSVersionCheckConstraint: 069's CHECK admits the four versions and
// NULL, and nothing else.
func TestM67_CVSSVersionCheckConstraint(t *testing.T) {
	_, migURL := schedIntEnv(t)
	migDB := schedOpenOrSkip(t, migURL)
	for _, v := range []any{"2.0", "3.0", "3.1", "4.0", nil} {
		id := m55CVEID(t)
		m67Cleanup(t, migDB, id)
		if _, err := migDB.Exec(`INSERT INTO vulnerabilities (id, cve_id, cvss_version) VALUES ($1, $2, $3)`, uuid.New(), id, v); err != nil {
			t.Errorf("cvss_version %v refused: %v", v, err)
		}
	}
	id := m55CVEID(t)
	m67Cleanup(t, migDB, id)
	if _, err := migDB.Exec(`INSERT INTO vulnerabilities (id, cve_id, cvss_version) VALUES ($1, $2, '9.9')`, uuid.New(), id); err == nil {
		t.Error("cvss_version '9.9' was accepted")
	}
}

// TestM67_MixedVersionWindowAndItsRecovery (Codex M67 R1, High). A pre-069
// binary still running against the 069 schema (a rolling deploy, or a second
// replica upgraded later) refreshes cvss_score / severity under its OWN rule
// and does not know cvss_version exists, so the marker a new binary recorded
// survives beside a score it no longer describes. At the same lastModified the
// new binary then refuses the record: the strict guard applies, because the
// marker says the row is already re-derived.
//
// That is the accepted, documented limit (UPGRADE: stop pre-069 processes
// before or while 069 is applied). This test pins both halves: the stuck row,
// and the one-statement recovery — clearing the marker returns every scored
// row to the re-derivable state, and the next offer re-derives it from the
// genuine record.
// m67MixedBinaryRecovery is the statement migration 069's header documents.
const m67MixedBinaryRecovery = `UPDATE vulnerabilities SET cvss_version = NULL WHERE cvss_version IS NOT NULL AND source = 'NVD'`

func TestM67_MixedVersionWindowAndItsRecovery(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	cveID := m55CVEID(t)
	m67Cleanup(t, migDB, cveID)
	t1 := time.Date(2026, 5, 3, 4, 5, 6, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)
	// The new binary stored the v3.1 Primary at t1.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, cvss_version, source,
			source_modified_at, updated_at)
		VALUES ($1, $2, 'new binary', 'HIGH', 7.5, '3.1', 'NVD', $3, NOW())`, uuid.New(), cveID, t1); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// NVD modified the CVE (t2); the OLD binary's sync wrote it first, with its
	// v4.0-first rule and its column list (no cvss_version).
	if _, err := migDB.Exec(`UPDATE vulnerabilities SET severity = 'MEDIUM', cvss_score = 6.9,
		source_modified_at = $2, updated_at = NOW() WHERE cve_id = $1`, cveID, t2); err != nil {
		t.Fatalf("old-binary write: %v", err)
	}

	fake := &m67NVD{}
	fake.set(m67Record(t, cveID, t2), t2)
	j := m58Job(appDB, fake.server(t).URL)
	j.canonicalNVD = true
	m55PinWatermark(t, migDB, time.Now().UTC().Add(-time.Hour))
	if out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC()); err != nil || !out.Finished {
		t.Fatalf("reconcileCatalogue = %+v, %v", out, err)
	}
	if got := m67Read(t, migDB, cveID); got.severity != "MEDIUM" {
		t.Fatalf("control: expected the documented stuck state (MEDIUM under a stale 3.1 marker), got %s", got)
	}

	// A JVN-only row (JVNDB id, which NVD can never re-read) must survive the
	// recovery with its version (Codex M67 R2, Low): an old binary cannot have
	// corrupted it — every NVD refresh writes source = 'NVD'.
	jvnID := "JVNDB-2091-" + fmt.Sprintf("%06d", uuid.New().ID()%1000000)
	m67Cleanup(t, migDB, jvnID)
	if _, err := migDB.Exec(`INSERT INTO vulnerabilities (id, cve_id, severity, cvss_score, cvss_version, source)
		VALUES ($1, $2, 'HIGH', 7.5, '3.0', 'JVN')`, uuid.New(), jvnID); err != nil {
		t.Fatalf("seed JVN row: %v", err)
	}

	// The documented recovery, verbatim, run once after the last pre-069
	// process stopped.
	if _, err := migDB.Exec(m67MixedBinaryRecovery); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if got := m67Read(t, migDB, jvnID); !got.version.Valid || got.version.String != "3.0" {
		t.Errorf("the recovery cleared a JVN row's version (%s); NVD cannot re-derive a JVNDB id, so it is lost", got)
	}
	m58Fresh(t, migDB)
	if out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC()); err != nil || !out.Finished {
		t.Fatalf("reconcileCatalogue after recovery = %+v, %v", out, err)
	}
	if got := m67Read(t, migDB, cveID); !got.isV31Primary() {
		t.Errorf("after the recovery and one re-read: %s, want HIGH/7.5/v3.1", got)
	}
}

// TestM67_MirrorCannotUseTheEqualTimestampException (Codex M67 R6, High). The
// one-shot re-derivation at an EQUAL lastModified trusts that the same
// timestamp means the same record. That holds for services.nvd.nist.gov; a
// configured mirror (SBOMHUB_NVD_URL, air-gapped installs) can serve a stale
// or partial body under an unchanged timestamp, and the exception would let it
// replace a pre-M67 CRITICAL with LOW once and then defend it. Against a
// mirror the strict guard applies (the operator reset in the 069 header
// covers convergence there).
func TestM67_MirrorCannotUseTheEqualTimestampException(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m58Fresh(t, migDB)

	cveID := m55CVEID(t)
	m67Cleanup(t, migDB, cveID)
	modified := time.Date(2026, 5, 3, 4, 5, 6, 0, time.UTC)
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, source_modified_at, updated_at)
		VALUES ($1, $2, 'pre-M67', 'CRITICAL', 9.8, 'NVD', $3, NOW())`, uuid.New(), cveID, modified); err != nil {
		t.Fatalf("seed: %v", err)
	}
	stale := json.RawMessage(strings.Replace(string(m67Record(t, cveID, modified)), `"baseScore":7.5`, `"baseScore":2.0`, 1))
	fake := &m67NVD{}
	fake.set(stale, modified)
	j := m58Job(appDB, fake.server(t).URL) // a mirror: not services.nvd.nist.gov
	m55PinWatermark(t, migDB, time.Now().UTC().Add(-time.Hour))
	if out, err := j.reconcileCatalogue(context.Background(), time.Now().UTC()); err != nil || !out.Finished {
		t.Fatalf("reconcileCatalogue = %+v, %v", out, err)
	}
	got := m67Read(t, migDB, cveID)
	if got.severity != "CRITICAL" || got.version.Valid {
		t.Errorf("a mirror's equal-timestamp body rewrote a pre-M67 row to %s; want CRITICAL/9.8 unversioned", got)
	}
}

// TestM67_CanonicalNVDURLIsRecognised pins which base URLs count as canonical.
func TestM67_CanonicalNVDURLIsRecognised(t *testing.T) {
	for url, want := range map[string]bool{
		"": true,
		"https://services.nvd.nist.gov/rest/json/cves/2.0":      true,
		"https://services.nvd.nist.gov/rest/json/cves/2.0/":     true,
		"http://services.nvd.nist.gov/rest/json/cves/2.0":       false,
		"https://nvd-mirror.example/rest/json/cves/2.0":         false,
		"https://services.nvd.nist.gov.evil/rest/json/cves/2.0": false,
	} {
		if got := NewCVESyncJob(nil, nil, "", time.Hour, nil, url, false).canonicalNVD; got != want {
			t.Errorf("canonicalNVD(%q) = %v, want %v", url, got, want)
		}
	}
}

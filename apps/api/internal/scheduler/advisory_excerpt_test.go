// Package scheduler — advisory_excerpt_test.go
//
// M32 Wave A (P1): unit coverage for wiring the NVD advisory-excerpt
// extraction into the production CVE→tenant link flow (cve_sync.go
// upsertNVDAdvisoryExcerpt, called from matchTenantsChunk when a CVE links
// to at least one of a tenant's components).
//
// These tests are hermetic: the CVE→component link wire AND the M32
// SAVEPOINT / RELEASE / ROLLBACK TO statements are driven against a sqlmock
// DB (they run on the chunk tx = database.Querier(ctx, db)), while the
// advisory_excerpts Upsert itself is intercepted by a fake so no real
// advisory_excerpts table / RLS context is needed.
//
// IMPORTANT (RLS caveat): a fake-based unit test proves the excerpt row is
// built and Upserted with the right fields AND that a failure is fenced by a
// savepoint — it does NOT prove the advisory_excerpts RLS WITH CHECK passes
// under the tenant GUC. That is a real-PG assertion left to an integration
// smoke.
package scheduler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// fakeAdvisoryExcerptUpserter records Upsert calls without a DB so the M32
// excerpt-grounding wiring can be unit-tested hermetically. `err` fails
// every call; `failCVE` overrides per CVEID — both prove an excerpt failure
// never aborts the CVE link (it is fenced by a SAVEPOINT).
type fakeAdvisoryExcerptUpserter struct {
	mu      sync.Mutex
	calls   []repository.AdvisoryExcerpt
	err     error
	failCVE map[string]error
}

func (f *fakeAdvisoryExcerptUpserter) Upsert(_ context.Context, e *repository.AdvisoryExcerpt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Value copy: snapshot the struct at call time (the caller reuses the
	// pointer's backing fields across iterations in the real loop).
	f.calls = append(f.calls, *e)
	if f.failCVE != nil {
		if err, ok := f.failCVE[e.CVEID]; ok {
			return err
		}
	}
	return f.err
}

func (f *fakeAdvisoryExcerptUpserter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// excerptOutcome selects which M32 savepoint statements a linked CVE is
// expected to issue against the sqlmock DB.
type excerptOutcome int

const (
	excerptNone     excerptOutcome = iota // grounding skipped: no savepoint at all
	excerptRelease                        // Upsert ok: SAVEPOINT ... RELEASE
	excerptRollback                       // Upsert failed: SAVEPOINT ... ROLLBACK TO
)

// expectTenantSetLocal adds the per-tenant GUC bind expectation.
func expectTenantSetLocal(mock sqlmock.Sqlmock, tenantID uuid.UUID) {
	mock.ExpectExec(`SELECT set_config\('app\.current_tenant_id'`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

// expectOneCVELink adds the sqlmock expectations for ONE CVE inside an
// already-begun, tenant-GUC-bound chunk tx: the components SELECT (1 row, so
// the CVE links), the component_vulnerabilities INSERT, and the M32
// savepoint statements per `out`. The excerpt Upsert itself is intercepted
// by the fake, NOT sqlmock, so it is not expected here.
//
// The savepoint regexes are anchored so `SAVEPOINT` does not also match the
// `RELEASE SAVEPOINT` / `ROLLBACK TO SAVEPOINT` strings.
func expectOneCVELink(mock sqlmock.Sqlmock, out excerptOutcome) {
	mock.ExpectQuery(`SELECT DISTINCT c\.id\s+FROM components`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New().String()))
	mock.ExpectExec(`INSERT INTO component_vulnerabilities`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	switch out {
	case excerptRelease:
		mock.ExpectExec(`^SAVEPOINT sh_advisory_excerpt$`).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`^RELEASE SAVEPOINT sh_advisory_excerpt$`).
			WillReturnResult(sqlmock.NewResult(0, 0))
	case excerptRollback:
		mock.ExpectExec(`^SAVEPOINT sh_advisory_excerpt$`).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`^ROLLBACK TO SAVEPOINT sh_advisory_excerpt$`).
			WillReturnResult(sqlmock.NewResult(0, 0))
	case excerptNone:
		// grounding skipped before any DB work — no savepoint statements.
	}
}

// driveSingleCVEMatch runs matchTenantsChunked for exactly one tenant and
// one CVE. `out` describes the expected M32 savepoint behaviour for that
// CVE. It asserts matchTenantsChunked returns no error and that every
// sqlmock expectation (crucially ExpectCommit) was met — i.e. the enclosing
// chunk tx committed and the CVE link is durable. Returns the matched count.
func driveSingleCVEMatch(t *testing.T, fake advisoryExcerptUpserter, tenantID, vulnID uuid.UUID, cve CVEInfo, out excerptOutcome) (matched int) {
	t.Helper()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	expectTenantSetLocal(mock, tenantID)
	expectOneCVELink(mock, out)
	mock.ExpectCommit()

	j := NewCVESyncJob(db, repository.NewTenantRepository(db), "", 24*time.Hour, fake)

	matched, _, err = j.matchTenantsChunked(
		context.Background(),
		[]uuid.UUID{tenantID},
		[]CVEInfo{cve},
		map[string]cveVulnEntry{cve.ID: {id: vulnID, isNew: true}},
	)
	if err != nil {
		t.Fatalf("matchTenantsChunked returned error (excerpt path must never abort the CVE link): %v", err)
	}
	if e := mock.ExpectationsWereMet(); e != nil {
		t.Errorf("unmet sqlmock expectations (link tx did not complete as expected): %v", e)
	}
	return matched
}

// TestUpsertNVDAdvisoryExcerpt_HappyPath asserts that a linked CVE with a
// non-empty NVD description produces exactly one Upsert with source "nvd",
// the right CVE/tenant, and a non-empty RawExcerpt, fenced by
// SAVEPOINT ... RELEASE.
//
// Because driveSingleCVEMatch runs the real production path, this exercises
// the typed *NVDCVEPayload → NVDParser.Parse route (a plain string would
// route to decodeNVDBytes and error): the RawExcerpt equality assertion
// below only holds if Parse actually produced the excerpt from the payload.
func TestUpsertNVDAdvisoryExcerpt_HappyPath(t *testing.T) {
	fake := &fakeAdvisoryExcerptUpserter{}
	tenantID := uuid.New()
	vulnID := uuid.New()
	cve := CVEInfo{
		ID:          "CVE-2024-12345",
		Description: "A heap buffer overflow in the parse() function of libfoo allows remote attackers to execute arbitrary code via a crafted packet.",
		Keywords:    []string{"libfoo"},
	}

	matched := driveSingleCVEMatch(t, fake, tenantID, vulnID, cve, excerptRelease)
	if matched != 1 {
		t.Fatalf("matched=%d, want 1 (CVE should link to the single mocked component)", matched)
	}

	if got := fake.callCount(); got != 1 {
		t.Fatalf("advisory excerpt Upsert calls=%d, want exactly 1", got)
	}
	got := fake.calls[0]
	if got.Source != "nvd" {
		t.Errorf("Source=%q, want %q", got.Source, "nvd")
	}
	if got.CVEID != cve.ID {
		t.Errorf("CVEID=%q, want %q", got.CVEID, cve.ID)
	}
	if got.TenantID != tenantID {
		t.Errorf("TenantID=%v, want %v (must use the tenant whose GUC is bound in the chunk loop)", got.TenantID, tenantID)
	}
	if strings.TrimSpace(got.RawExcerpt) == "" {
		t.Errorf("RawExcerpt is empty, want the advisory description as grounding text")
	}
	// Proves the parser actually ran on our typed payload: NVDParser sets
	// RawExcerpt to the (trimmed) English description.
	if got.RawExcerpt != strings.TrimSpace(cve.Description) {
		t.Errorf("RawExcerpt=%q, want the parsed NVD description %q", got.RawExcerpt, strings.TrimSpace(cve.Description))
	}
	if got.FetchedAt == nil {
		t.Errorf("FetchedAt is nil, want it stamped at write time")
	}
}

// TestUpsertNVDAdvisoryExcerpt_EmptyDescription asserts that a linked CVE
// with no advisory text produces NO Upsert and NO savepoint (guards against
// empty/garbage rows) while the CVE link itself still happens.
func TestUpsertNVDAdvisoryExcerpt_EmptyDescription(t *testing.T) {
	// Both truly empty and whitespace-only must be skipped by the
	// TrimSpace guard in upsertNVDAdvisoryExcerpt (before any savepoint).
	for _, desc := range []string{"", "   \n\t  "} {
		fake := &fakeAdvisoryExcerptUpserter{}
		cve := CVEInfo{
			ID:          "CVE-2024-99999",
			Description: desc,
			Keywords:    []string{"libbar"},
		}

		matched := driveSingleCVEMatch(t, fake, uuid.New(), uuid.New(), cve, excerptNone)
		if matched != 1 {
			t.Fatalf("matched=%d, want 1 (link must happen even with no advisory text)", matched)
		}
		if got := fake.callCount(); got != 0 {
			t.Fatalf("advisory excerpt Upsert calls=%d for description %q, want 0", got, desc)
		}
	}
}

// TestUpsertNVDAdvisoryExcerpt_UpsertErrorRollsBackSavepoint asserts that
// when the excerpt Upsert fails, it is fenced by SAVEPOINT ... ROLLBACK TO,
// the CVE link is preserved, matchTenantsChunked returns no error, and the
// chunk tx still commits (driveSingleCVEMatch checks ExpectCommit was met).
func TestUpsertNVDAdvisoryExcerpt_UpsertErrorRollsBackSavepoint(t *testing.T) {
	fake := &fakeAdvisoryExcerptUpserter{err: errors.New("simulated advisory_excerpts upsert failure")}
	cve := CVEInfo{
		ID:          "CVE-2024-55555",
		Description: "Improper input validation in libbaz permits path traversal via the ../ sequence in the name parameter.",
		Keywords:    []string{"libbaz"},
	}

	matched := driveSingleCVEMatch(t, fake, uuid.New(), uuid.New(), cve, excerptRollback)
	if matched != 1 {
		t.Fatalf("matched=%d, want 1 (excerpt Upsert error must not abort the CVE link)", matched)
	}
	if got := fake.callCount(); got != 1 {
		t.Fatalf("advisory excerpt Upsert calls=%d, want 1 (the failing call should still have been attempted)", got)
	}
}

// TestUpsertNVDAdvisoryExcerpt_UpsertErrorDoesNotPoisonChunk is the core
// regression pin for the M32 savepoint fix. It drives ONE tenant with TWO
// CVEs in the same chunk tx: the FIRST CVE's excerpt Upsert fails (fenced by
// ROLLBACK TO), and it asserts the SECOND CVE still links (its
// component_vulnerabilities INSERT still executes on the same tx) and the
// chunk still COMMITS. Without the savepoint, the first excerpt error would
// abort the tx and the second link + the COMMIT would fail with
// "current transaction is aborted" — regressing core CVE sync.
func TestUpsertNVDAdvisoryExcerpt_UpsertErrorDoesNotPoisonChunk(t *testing.T) {
	cveA := CVEInfo{
		ID:          "CVE-2024-00001",
		Description: "First advisory: use-after-free in liba during cleanup.",
		Keywords:    []string{"liba"},
	}
	cveB := CVEInfo{
		ID:          "CVE-2024-00002",
		Description: "Second advisory: integer overflow in libb size computation.",
		Keywords:    []string{"libb"},
	}
	// Only cveA's excerpt fails; cveB's succeeds — proving the tx survived
	// the first rollback and remained usable.
	fake := &fakeAdvisoryExcerptUpserter{
		failCVE: map[string]error{cveA.ID: errors.New("simulated RLS WITH CHECK failure on excerpt A")},
	}
	tenantID := uuid.New()
	vulnA, vulnB := uuid.New(), uuid.New()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// Single tenant, single chunk. cves iterate in slice order: A then B.
	mock.ExpectBegin()
	expectTenantSetLocal(mock, tenantID)
	expectOneCVELink(mock, excerptRollback) // cveA: excerpt fails -> ROLLBACK TO
	expectOneCVELink(mock, excerptRelease)  // cveB: still links + excerpt ok -> RELEASE
	mock.ExpectCommit()

	j := NewCVESyncJob(db, repository.NewTenantRepository(db), "", 24*time.Hour, fake)

	matched, _, err := j.matchTenantsChunked(
		context.Background(),
		[]uuid.UUID{tenantID},
		[]CVEInfo{cveA, cveB},
		map[string]cveVulnEntry{
			cveA.ID: {id: vulnA, isNew: true},
			cveB.ID: {id: vulnB, isNew: true},
		},
	)
	if err != nil {
		t.Fatalf("matchTenantsChunked returned error (savepoint must keep the chunk tx usable): %v", err)
	}
	if e := mock.ExpectationsWereMet(); e != nil {
		// A failure here (e.g. the cveB INSERT or the COMMIT unmet) is
		// exactly the poisoning regression this test guards against.
		t.Errorf("unmet sqlmock expectations (tx poisoned by excerpt A failure?): %v", e)
	}
	if matched != 2 {
		t.Fatalf("matched=%d, want 2 (both CVEs must link; excerpt A's failure must not poison the chunk)", matched)
	}
	if got := fake.callCount(); got != 2 {
		t.Fatalf("advisory excerpt Upsert calls=%d, want 2 (both CVEs attempt an excerpt)", got)
	}
}

// TestUpsertNVDAdvisoryExcerpt_NilUpserterIsSafe asserts the nil-safe DI
// path: when no upserter is wired (prod DI not yet passing it, existing
// tests), the CVE sync runs unchanged, issues no savepoint, and never panics.
func TestUpsertNVDAdvisoryExcerpt_NilUpserterIsSafe(t *testing.T) {
	cve := CVEInfo{
		ID:          "CVE-2024-77777",
		Description: "Some advisory text that would be persisted if an upserter were wired.",
		Keywords:    []string{"libqux"},
	}

	// A typed nil interface: NewCVESyncJob stores it and the guard in
	// upsertNVDAdvisoryExcerpt short-circuits before any parse/savepoint.
	matched := driveSingleCVEMatch(t, nil, uuid.New(), uuid.New(), cve, excerptNone)
	if matched != 1 {
		t.Fatalf("matched=%d, want 1 (nil upserter must not disturb the CVE link)", matched)
	}
}

// (compile-time) *repository.AdvisoryExcerptsRepository must satisfy the
// scheduler's narrow upserter interface so the main.go DI wiring type-checks.
var _ advisoryExcerptUpserter = (*repository.AdvisoryExcerptsRepository)(nil)

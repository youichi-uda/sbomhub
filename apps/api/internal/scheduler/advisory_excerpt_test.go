// Package scheduler — advisory_excerpt_test.go
//
// M32 Wave A (P1): unit coverage for wiring the NVD advisory-excerpt
// extraction into the production CVE→tenant link flow. Excerpts are
// collected during matchTenantsChunk's link loop and persisted in ONE
// batched savepoint per chunk (writeChunkAdvisoryExcerpts) — one subxid per
// chunk regardless of CVE count (subxid-cache overflow avoidance), while
// keeping best-effort isolation (core links precede the savepoint).
//
// These tests are hermetic: the CVE→component link wire AND the M32
// SAVEPOINT / SET LOCAL re-assert / RELEASE / ROLLBACK TO statements are
// driven against a sqlmock DB (they run on the chunk tx), while the
// advisory_excerpts Upsert itself is intercepted by a fake so no real
// advisory_excerpts table / RLS context is needed.
//
// IMPORTANT (RLS caveat): a fake-based unit test proves the excerpt rows are
// built and Upserted with the right fields, that exactly ONE savepoint is
// opened per chunk, and that a failure is fenced by that savepoint — it does
// NOT prove the advisory_excerpts RLS WITH CHECK passes under the tenant GUC,
// nor the (tenant,cve,source) ON CONFLICT idempotency (a repository/real-PG
// property; the compile-time assertion at the bottom pins that the real repo
// satisfies the upserter interface). Those are real-PG integration smokes.
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
// is fenced by the chunk savepoint and never aborts the core CVE links.
type fakeAdvisoryExcerptUpserter struct {
	mu      sync.Mutex
	calls   []repository.AdvisoryExcerpt
	err     error
	failCVE map[string]error
}

func (f *fakeAdvisoryExcerptUpserter) Upsert(_ context.Context, e *repository.AdvisoryExcerpt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Value copy: snapshot the struct at call time.
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

// --- sqlmock expectation helpers (all regex-matched; savepoint statements
// are anchored with ^...$ so SAVEPOINT does not also match RELEASE/ROLLBACK
// TO). ---

func expectSetLocal(mock sqlmock.Sqlmock, tenantID uuid.UUID) {
	mock.ExpectExec(`SELECT set_config\('app\.current_tenant_id'`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

// expectLinkOneCVE mocks one CVE's link: components SELECT (1 row → links) +
// the component_vulnerabilities INSERT.
func expectLinkOneCVE(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT DISTINCT c\.id\s+FROM components`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New().String()))
	mock.ExpectExec(`INSERT INTO component_vulnerabilities`).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectSavepoint(mock sqlmock.Sqlmock) {
	mock.ExpectExec(`^SAVEPOINT sh_advisory_excerpt$`).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func expectRelease(mock sqlmock.Sqlmock) {
	mock.ExpectExec(`^RELEASE SAVEPOINT sh_advisory_excerpt$`).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func expectRollbackTo(mock sqlmock.Sqlmock) {
	mock.ExpectExec(`^ROLLBACK TO SAVEPOINT sh_advisory_excerpt$`).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

// runChunkMatch builds a sqlmock DB, lets `setup` declare the expected wire,
// runs one chunk's matchTenantsChunked, and asserts no error + all
// expectations met (crucially ExpectCommit — the chunk committed). Returns
// the matched count.
func runChunkMatch(
	t *testing.T,
	fake advisoryExcerptUpserter,
	tenantIDs []uuid.UUID,
	cves []CVEInfo,
	vulnIndex map[string]cveVulnEntry,
	setup func(sqlmock.Sqlmock),
) (matched int) {
	t.Helper()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	setup(mock)

	j := NewCVESyncJob(db, repository.NewTenantRepository(db), "", 24*time.Hour, fake)
	matched, _, err = j.matchTenantsChunked(context.Background(), tenantIDs, cves, vulnIndex)
	if err != nil {
		t.Fatalf("matchTenantsChunked returned error (excerpt path must never abort the chunk): %v", err)
	}
	if e := mock.ExpectationsWereMet(); e != nil {
		t.Errorf("unmet sqlmock expectations (chunk tx did not complete as expected): %v", e)
	}
	return matched
}

// TestUpsertNVDAdvisoryExcerpt_HappyPathFields drives one tenant + one linked
// CVE and asserts the excerpt row is built with source "nvd", the right
// CVE/tenant, RawExcerpt == the parsed description, FetchedAt set — fenced by
// exactly one SAVEPOINT ... RELEASE.
//
// Because runChunkMatch runs the real production path, this exercises the
// typed *NVDCVEPayload → NVDParser.Parse route (a plain string would route to
// decodeNVDBytes and error): the RawExcerpt equality assertion only holds if
// Parse actually produced the excerpt from the payload.
func TestUpsertNVDAdvisoryExcerpt_HappyPathFields(t *testing.T) {
	fake := &fakeAdvisoryExcerptUpserter{}
	tenantID := uuid.New()
	vulnID := uuid.New()
	cve := CVEInfo{
		ID:          "CVE-2024-12345",
		Description: "A heap buffer overflow in the parse() function of libfoo allows remote attackers to execute arbitrary code via a crafted packet.",
		Keywords:    []string{"libfoo"},
	}

	matched := runChunkMatch(t, fake,
		[]uuid.UUID{tenantID},
		[]CVEInfo{cve},
		map[string]cveVulnEntry{cve.ID: {id: vulnID, isNew: true}},
		func(mock sqlmock.Sqlmock) {
			mock.ExpectBegin()
			expectSetLocal(mock, tenantID) // link loop
			expectLinkOneCVE(mock)
			expectSavepoint(mock)          // one savepoint for the batch
			expectSetLocal(mock, tenantID) // batch re-assert tenant GUC
			expectRelease(mock)
			mock.ExpectCommit()
		},
	)

	if matched != 1 {
		t.Fatalf("matched=%d, want 1", matched)
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
		t.Errorf("TenantID=%v, want %v", got.TenantID, tenantID)
	}
	// Proves the parser ran on our typed payload: NVDParser sets RawExcerpt
	// to the trimmed English description.
	if got.RawExcerpt != strings.TrimSpace(cve.Description) {
		t.Errorf("RawExcerpt=%q, want parsed NVD description %q", got.RawExcerpt, strings.TrimSpace(cve.Description))
	}
	if got.FetchedAt == nil {
		t.Errorf("FetchedAt is nil, want it stamped at write time")
	}
}

// TestUpsertNVDAdvisoryExcerpt_OneSavepointPerChunk is the regression pin for
// the subxid-cache fix. It drives ONE chunk covering TWO tenants (each links
// the same CVE) and asserts that despite TWO excerpt writes, exactly ONE
// SAVEPOINT (and ONE RELEASE) is issued for the whole chunk, with the tenant
// GUC re-asserted per tenant inside the batch. A per-CVE-savepoint regression
// would issue a second SAVEPOINT with no matching expectation and fail here.
func TestUpsertNVDAdvisoryExcerpt_OneSavepointPerChunk(t *testing.T) {
	fake := &fakeAdvisoryExcerptUpserter{}
	tenantA, tenantB := uuid.New(), uuid.New()
	vulnID := uuid.New()
	cve := CVEInfo{
		ID:          "CVE-2024-22222",
		Description: "Server-side request forgery in libnet allows internal endpoint access via a crafted host header.",
		Keywords:    []string{"libnet"},
	}

	matched := runChunkMatch(t, fake,
		[]uuid.UUID{tenantA, tenantB},
		[]CVEInfo{cve},
		map[string]cveVulnEntry{cve.ID: {id: vulnID, isNew: true}},
		func(mock sqlmock.Sqlmock) {
			mock.ExpectBegin()
			// Link loop: per tenant SET LOCAL + one CVE link each.
			expectSetLocal(mock, tenantA)
			expectLinkOneCVE(mock)
			expectSetLocal(mock, tenantB)
			expectLinkOneCVE(mock)
			// Batch: exactly ONE savepoint, then per-tenant GUC re-assert
			// (candidates are contiguous per tenant: A then B), then ONE
			// release.
			expectSavepoint(mock)
			expectSetLocal(mock, tenantA)
			expectSetLocal(mock, tenantB)
			expectRelease(mock)
			mock.ExpectCommit()
		},
	)

	if matched != 2 {
		t.Fatalf("matched=%d, want 2 (CVE links for both tenants)", matched)
	}
	if got := fake.callCount(); got != 2 {
		t.Fatalf("advisory excerpt Upsert calls=%d, want 2 (one per tenant)", got)
	}
	// Candidates are collected tenant-by-tenant, so call[0]=A, call[1]=B.
	if fake.calls[0].TenantID != tenantA || fake.calls[1].TenantID != tenantB {
		t.Errorf("excerpt tenant order = [%v, %v], want [%v, %v]",
			fake.calls[0].TenantID, fake.calls[1].TenantID, tenantA, tenantB)
	}
	for i, c := range fake.calls {
		if c.Source != "nvd" {
			t.Errorf("calls[%d].Source=%q, want nvd", i, c.Source)
		}
		if c.CVEID != cve.ID {
			t.Errorf("calls[%d].CVEID=%q, want %q", i, c.CVEID, cve.ID)
		}
		if strings.TrimSpace(c.RawExcerpt) == "" {
			t.Errorf("calls[%d].RawExcerpt empty, want grounding text", i)
		}
	}
}

// TestUpsertNVDAdvisoryExcerpt_UpsertErrorDoesNotPoisonChunk is the core
// non-poisoning pin under the batched design. ONE tenant, TWO CVEs: the FIRST
// excerpt Upsert fails, and it asserts exactly ONE SAVEPOINT then ROLLBACK TO
// SAVEPOINT (not per-CVE), the batch is abandoned, yet BOTH core CVE links
// survive (they precede the savepoint) and the chunk still COMMITs.
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
	// Only cveA (the first candidate) fails — proving the whole batch is
	// abandoned on first error but the core links (and COMMIT) survive.
	fake := &fakeAdvisoryExcerptUpserter{
		failCVE: map[string]error{cveA.ID: errors.New("simulated RLS WITH CHECK failure on excerpt A")},
	}
	tenantID := uuid.New()
	vulnA, vulnB := uuid.New(), uuid.New()

	matched := runChunkMatch(t, fake,
		[]uuid.UUID{tenantID},
		[]CVEInfo{cveA, cveB},
		map[string]cveVulnEntry{
			cveA.ID: {id: vulnA, isNew: true},
			cveB.ID: {id: vulnB, isNew: true},
		},
		func(mock sqlmock.Sqlmock) {
			mock.ExpectBegin()
			expectSetLocal(mock, tenantID) // link loop
			expectLinkOneCVE(mock)         // cveA link (survives)
			expectLinkOneCVE(mock)         // cveB link (survives)
			// Batch: ONE savepoint, GUC re-assert once (same tenant), then
			// cveA's Upsert fails -> ROLLBACK TO -> batch abandoned.
			expectSavepoint(mock)
			expectSetLocal(mock, tenantID)
			expectRollbackTo(mock)
			mock.ExpectCommit()
		},
	)

	if matched != 2 {
		t.Fatalf("matched=%d, want 2 (both CVEs must link; excerpt A's failure must not poison the chunk)", matched)
	}
	// cveA attempted (and failed) -> batch abandoned before cveB's excerpt.
	if got := fake.callCount(); got != 1 {
		t.Fatalf("advisory excerpt Upsert calls=%d, want 1 (batch abandoned after first failure)", got)
	}
	if fake.calls[0].CVEID != cveA.ID {
		t.Errorf("failed call CVEID=%q, want %q", fake.calls[0].CVEID, cveA.ID)
	}
}

// TestUpsertNVDAdvisoryExcerpt_EmptyDescription asserts a linked CVE with no
// advisory text produces NO Upsert AND NO savepoint (nothing collected → the
// batch is empty), while the CVE link itself still happens.
func TestUpsertNVDAdvisoryExcerpt_EmptyDescription(t *testing.T) {
	for _, desc := range []string{"", "   \n\t  "} {
		fake := &fakeAdvisoryExcerptUpserter{}
		tenantID := uuid.New()
		cve := CVEInfo{
			ID:          "CVE-2024-99999",
			Description: desc,
			Keywords:    []string{"libbar"},
		}

		matched := runChunkMatch(t, fake,
			[]uuid.UUID{tenantID},
			[]CVEInfo{cve},
			map[string]cveVulnEntry{cve.ID: {id: uuid.New(), isNew: true}},
			func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				expectSetLocal(mock, tenantID)
				expectLinkOneCVE(mock)
				// No savepoint: empty description → no candidate collected.
				mock.ExpectCommit()
			},
		)

		if matched != 1 {
			t.Fatalf("matched=%d, want 1 (link happens even with no advisory text)", matched)
		}
		if got := fake.callCount(); got != 0 {
			t.Fatalf("advisory excerpt Upsert calls=%d for description %q, want 0", got, desc)
		}
	}
}

// TestUpsertNVDAdvisoryExcerpt_NilUpserterIsSafe asserts the nil-safe DI path:
// no upserter wired → no candidate collected, no savepoint, no panic, link
// unchanged.
func TestUpsertNVDAdvisoryExcerpt_NilUpserterIsSafe(t *testing.T) {
	tenantID := uuid.New()
	cve := CVEInfo{
		ID:          "CVE-2024-77777",
		Description: "Some advisory text that would be persisted if an upserter were wired.",
		Keywords:    []string{"libqux"},
	}

	matched := runChunkMatch(t, nil,
		[]uuid.UUID{tenantID},
		[]CVEInfo{cve},
		map[string]cveVulnEntry{cve.ID: {id: uuid.New(), isNew: true}},
		func(mock sqlmock.Sqlmock) {
			mock.ExpectBegin()
			expectSetLocal(mock, tenantID)
			expectLinkOneCVE(mock)
			// No savepoint: nil upserter disables grounding entirely.
			mock.ExpectCommit()
		},
	)

	if matched != 1 {
		t.Fatalf("matched=%d, want 1 (nil upserter must not disturb the CVE link)", matched)
	}
}

// (compile-time) *repository.AdvisoryExcerptsRepository must satisfy the
// scheduler's narrow upserter interface so the main.go DI wiring type-checks.
// This is also the unit-level pin that the persisted excerpts are idempotent
// on (tenant_id, cve_id, source): that ON CONFLICT upsert lives in the real
// repository behind this interface (not the fake).
var _ advisoryExcerptUpserter = (*repository.AdvisoryExcerptsRepository)(nil)

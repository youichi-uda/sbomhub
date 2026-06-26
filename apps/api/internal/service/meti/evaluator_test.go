package meti

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/meti/criteria"
)

// fakeDeps mirrors the per-criterion fake used in criteria_test.go
// but is duplicated here to keep the meti package's tests independent
// (the criteria fake is intentionally unexported as it's a test-only
// helper). The set of fields is the union of everything the registry
// touches.
type fakeDeps struct {
	latestSbom  *model.Sbom
	sbomList    []model.Sbom
	components  map[uuid.UUID][]model.Component
	vulns       []model.Vulnerability
	vexDrafts   []repository.VEXDraft
	craReports  []repository.CRAReport
	publicLinks []model.PublicLink
	policies    []model.LicensePolicy
	eolSummary  *model.EOLSummary
	kevSettings *model.KEVSyncSettings
	auditLogsN  int

	failOn string // criterion id to fail on -- used by error-propagation test
}

func (f *fakeDeps) GetLatestSbom(_ context.Context, _ uuid.UUID) (*model.Sbom, error) {
	if f.failOn == "GetLatestSbom" {
		return nil, errors.New("boom: GetLatestSbom")
	}
	return f.latestSbom, nil
}
func (f *fakeDeps) ListSbomsByProject(_ context.Context, _ uuid.UUID) ([]model.Sbom, error) {
	if f.failOn == "ListSbomsByProject" {
		return nil, errors.New("boom: ListSbomsByProject")
	}
	return f.sbomList, nil
}
func (f *fakeDeps) ListComponentsBySbom(_ context.Context, sbomID uuid.UUID) ([]model.Component, error) {
	if f.components == nil {
		return nil, nil
	}
	return f.components[sbomID], nil
}
func (f *fakeDeps) ListVulnerabilitiesByProject(_ context.Context, _ uuid.UUID) ([]model.Vulnerability, error) {
	return f.vulns, nil
}
func (f *fakeDeps) ListVEXDraftsByProject(_ context.Context, _, _ uuid.UUID) ([]repository.VEXDraft, error) {
	return f.vexDrafts, nil
}
func (f *fakeDeps) ListCRAReportsByProject(_ context.Context, _, _ uuid.UUID) ([]repository.CRAReport, error) {
	return f.craReports, nil
}
func (f *fakeDeps) ListPublicLinksByProject(_ context.Context, _, _ uuid.UUID) ([]model.PublicLink, error) {
	return f.publicLinks, nil
}
func (f *fakeDeps) ListLicensePoliciesByProject(_ context.Context, _ uuid.UUID) ([]model.LicensePolicy, error) {
	return f.policies, nil
}
func (f *fakeDeps) GetEOLSummary(_ context.Context, _ uuid.UUID) (*model.EOLSummary, error) {
	return f.eolSummary, nil
}
func (f *fakeDeps) GetKEVSyncSettings(_ context.Context) (*model.KEVSyncSettings, error) {
	return f.kevSettings, nil
}
func (f *fakeDeps) CountAuditLogsForTenant(_ context.Context, _ uuid.UUID) (int, error) {
	return f.auditLogsN, nil
}

// TestEvaluator_Evaluate_CoversEveryCatalogCriterion is the M3-2
// acceptance test: a fresh Evaluator must return one CriterionResult
// for every catalog entry, every result must carry a non-empty
// status / phase / evaluator_version, and the slice must be in
// (phase ASC, id ASC) order so the M3-4 handler can stream it into
// meti_assessments without a re-sort. Mirrors the M3-3 catalog test
// CountByPhase: the evaluator should never silently drop a criterion.
func TestEvaluator_Evaluate_CoversEveryCatalogCriterion(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err)

	ev, err := NewEvaluatorWithDeps(&fakeDeps{})
	require.NoError(t, err)
	tenant, project := uuid.New(), uuid.New()

	results, err := ev.Evaluate(context.Background(), tenant, project)
	require.NoError(t, err)
	require.Equal(t, len(items), len(results), "evaluate must return one result per catalog criterion")

	// Index by criterion_id so the assertion messages name the
	// offending id directly.
	gotIDs := make(map[string]CriterionResult, len(results))
	for _, r := range results {
		gotIDs[r.CriterionID] = r
		assert.NotEmpty(t, r.CriterionID)
		assert.NotEmpty(t, r.Phase)
		assert.NotEmpty(t, r.Status)
		assert.Equal(t, EvaluatorVersion, r.EvaluatorVersion)
		assert.False(t, r.EvaluatedAt.IsZero(), "EvaluatedAt must be set for %s", r.CriterionID)
		// Evidence must always be a JSON array (matches the
		// meti_assessments CHECK constraint).
		var arr []json.RawMessage
		assert.NoError(t, json.Unmarshal(r.Evidence, &arr), "evidence for %s must be a JSON array", r.CriterionID)
	}
	for _, item := range items {
		_, ok := gotIDs[item.ID]
		assert.True(t, ok, "evaluator must emit a result for catalog id %s", item.ID)
	}

	// Order: (phase ASC, id ASC). Mirrors the handler's expectations.
	for i := 1; i < len(results); i++ {
		prev, cur := results[i-1], results[i]
		if prev.Phase != cur.Phase {
			assert.LessOrEqual(t, prev.Phase, cur.Phase, "phase order regressed between %s and %s", prev.CriterionID, cur.CriterionID)
		} else {
			assert.Less(t, prev.CriterionID, cur.CriterionID, "id order regressed inside phase %s", cur.Phase)
		}
	}
}

// TestRegistry_CoversCatalog is the build-time regression guard: every
// catalog id must have a matching entry in criteria.Registry. Mirror
// also asserts that the registry does not carry any orphan id that
// isn't in the catalog (would point to a deleted criterion).
func TestRegistry_CoversCatalog(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err)
	catalogIDs := make(map[string]struct{}, len(items))
	for _, it := range items {
		catalogIDs[it.ID] = struct{}{}
		_, ok := criteria.Lookup(it.ID)
		assert.True(t, ok, "criteria.Registry missing evaluator for catalog id %s", it.ID)
	}
	for id := range criteria.Registry {
		_, ok := catalogIDs[id]
		assert.True(t, ok, "criteria.Registry has orphan id %s not in catalog", id)
	}
}

// TestEvaluator_Evaluate_RejectsZeroIDs exercises the nil-uuid guards
// at the orchestration boundary. The M3-4 handler is expected to
// validate upstream but the evaluator must not silently run with a
// zero tenant/project (the per-criterion functions assume both are
// real).
func TestEvaluator_Evaluate_RejectsZeroIDs(t *testing.T) {
	ev, err := NewEvaluatorWithDeps(&fakeDeps{})
	require.NoError(t, err)
	project := uuid.New()
	if _, err := ev.Evaluate(context.Background(), uuid.Nil, project); err == nil {
		t.Fatal("expected error on zero tenant")
	}
	if _, err := ev.Evaluate(context.Background(), uuid.New(), uuid.Nil); err == nil {
		t.Fatal("expected error on zero project")
	}
}

// TestEvaluator_EvaluateOne_UnknownReturnsTypedError asserts the
// handler-friendly error mapping for the re-evaluate-one path. The
// M3-4 handler relies on errors.Is to map this to HTTP 404.
func TestEvaluator_EvaluateOne_UnknownReturnsTypedError(t *testing.T) {
	ev, err := NewEvaluatorWithDeps(&fakeDeps{})
	require.NoError(t, err)
	_, err = ev.EvaluateOne(context.Background(), uuid.New(), uuid.New(), "meti.does.not.exist")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnknownCriterion), "expected ErrUnknownCriterion, got %v", err)
}

// TestEvaluator_EvaluateOne_KnownReturnsResult round-trips a known id
// (env_setup.07 — the simplest fully-auto one) through EvaluateOne
// to assert the single-criterion path returns the same shape as the
// full Evaluate slice does.
func TestEvaluator_EvaluateOne_KnownReturnsResult(t *testing.T) {
	deps := &fakeDeps{sbomList: []model.Sbom{
		{ID: uuid.New(), Format: "CycloneDX", CreatedAt: time.Now()},
	}}
	ev, err := NewEvaluatorWithDeps(deps)
	require.NoError(t, err)
	got, err := ev.EvaluateOne(context.Background(), uuid.New(), uuid.New(), "meti.env_setup.07")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "meti.env_setup.07", got.CriterionID)
	assert.Equal(t, "env_setup", got.Phase)
	assert.Equal(t, criteria.StatusAchieved, got.Status)
	assert.Equal(t, EvaluatorVersion, got.EvaluatorVersion)
}

// TestEvaluator_Evaluate_PropagatesDepsErrors asserts the
// "fail-fast on storage error" contract documented on Evaluate. We
// inject a failure into ListSbomsByProject (touched by 6 criteria so
// it's reliably hit early) and assert Evaluate aborts with the
// underlying error wrapped.
func TestEvaluator_Evaluate_PropagatesDepsErrors(t *testing.T) {
	ev, err := NewEvaluatorWithDeps(&fakeDeps{failOn: "ListSbomsByProject"})
	require.NoError(t, err)
	_, err = ev.Evaluate(context.Background(), uuid.New(), uuid.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ListSbomsByProject")
}

// TestEvaluator_PinnedNow ensures the evaluator stamps EvaluatedAt
// from a single point-in-time per Evaluate call, so every criterion
// in a single run shares a timestamp (the M3-4 handler relies on
// this to bucket the run as a single "evaluation event" in audit
// logs).
func TestEvaluator_PinnedNow(t *testing.T) {
	pinned := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	ev := &Evaluator{deps: &fakeDeps{}, now: func() time.Time { return pinned }}
	results, err := ev.Evaluate(context.Background(), uuid.New(), uuid.New())
	require.NoError(t, err)
	for _, r := range results {
		assert.Equal(t, pinned, r.EvaluatedAt, "criterion %s should share the pinned evaluation timestamp", r.CriterionID)
	}
}

// TestEvaluatorVersion_StableFormat keeps the version string in a
// known shape. The M3-4 handler greps for the "meti-" prefix when
// deciding whether to upsert across an evaluator-version boundary,
// so a typo here would silently break re-evaluation.
func TestEvaluatorVersion_StableFormat(t *testing.T) {
	assert.True(t, len(EvaluatorVersion) >= len("meti-evaluator-v1"))
	assert.Equal(t, "meti-", EvaluatorVersion[:5])
}

// TestNewEvaluator_RejectsNilRepo guards the production constructor
// against silent nil deps. Pick the first parameter as the canary;
// the constructor returns at the first nil so a fully-nil list would
// share the same error path.
func TestNewEvaluator_RejectsNilRepo(t *testing.T) {
	_, err := NewEvaluator(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil dependency rejected")
}

// helper: prove evaluator results are JSON-marshallable (the M3-4
// handler will marshal them to the wire shape).
func TestCriterionResult_JSONShape(t *testing.T) {
	ev, err := NewEvaluatorWithDeps(&fakeDeps{})
	require.NoError(t, err)
	results, err := ev.Evaluate(context.Background(), uuid.New(), uuid.New())
	require.NoError(t, err)
	for _, r := range results {
		b, err := json.Marshal(r)
		require.NoError(t, err, "criterion %s must marshal", r.CriterionID)
		// Sanity: criterion_id is in the wire shape.
		assert.Contains(t, string(b), fmt.Sprintf(`"criterion_id":%q`, r.CriterionID))
	}
}

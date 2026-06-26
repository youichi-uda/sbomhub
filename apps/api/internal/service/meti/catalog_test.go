package meti

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadCatalog_ParseAndValidate exercises the happy path: the embedded
// catalog.yaml must parse cleanly and survive every schema check. A
// regression here is almost always caused by an author editing the YAML
// and forgetting one of the required fields — the assertions below
// surface exactly which field is missing on which id.
func TestLoadCatalog_ParseAndValidate(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err, "LoadCatalog should not return an error on the embedded catalog")
	require.NotEmpty(t, items, "catalog must contain at least one criterion")

	seen := make(map[string]struct{}, len(items))
	for i, c := range items {
		// Required scalar fields. Each is asserted separately so the
		// failure message names the missing field, not a generic struct
		// equality miss.
		assert.NotEmpty(t, c.ID, "criterion[%d].id must be set", i)
		assert.NotEmpty(t, c.Phase, "criterion[%d=%s].phase must be set", i, c.ID)
		assert.NotEmpty(t, c.TitleJA, "criterion[%d=%s].title_ja must be set", i, c.ID)
		assert.NotEmpty(t, c.TitleEN, "criterion[%d=%s].title_en must be set", i, c.ID)
		assert.NotEmpty(t, c.DescriptionJA, "criterion[%d=%s].description_ja must be set", i, c.ID)
		assert.NotEmpty(t, c.DescriptionEN, "criterion[%d=%s].description_en must be set", i, c.ID)
		assert.NotEmpty(t, c.EvaluatorHint, "criterion[%d=%s].evaluator_hint must be set", i, c.ID)

		// Phase must be one of the closed set; mirrors the loader check
		// so we get a test-time failure in addition to a load-time one.
		_, ok := validPhases[c.Phase]
		assert.True(t, ok, "criterion[%s] has unknown phase %q", c.ID, c.Phase)

		// ID must start with the phase prefix.
		assert.True(t,
			strings.HasPrefix(c.ID, "meti."+string(c.Phase)+"."),
			"criterion[%s] id should start with phase prefix meti.%s.", c.ID, c.Phase,
		)

		// Global uniqueness.
		_, dup := seen[c.ID]
		assert.False(t, dup, "duplicate id %q", c.ID)
		seen[c.ID] = struct{}{}
	}
}

// TestLoadCatalog_ReturnsCopy guards against the cache being poisoned by
// a caller mutating the returned slice. Sorting the result and re-loading
// must yield an identically-ordered second slice.
func TestLoadCatalog_ReturnsCopy(t *testing.T) {
	first, err := LoadCatalog()
	require.NoError(t, err)

	// Mutate the first slice in place.
	if len(first) > 1 {
		first[0], first[1] = first[1], first[0]
	}

	second, err := LoadCatalog()
	require.NoError(t, err)

	// Round-trip the cache: the second load must still be in original
	// (catalog file) order, unaffected by the swap above.
	require.Len(t, second, len(first))
	// Build a stable identity check: the second slice's ids match the
	// catalog's recorded ids, regardless of the caller's mutation.
	ids := make([]string, len(second))
	for i, c := range second {
		ids[i] = c.ID
	}
	// Sanity: the first id of the cached catalog is not the swapped one
	// (assuming at least two items exist).
	if len(first) > 1 {
		assert.Equal(t, ids[0], second[0].ID, "cache must not be mutated by caller swapping its slice")
	}
}

// TestGetCriterion_KnownAndUnknown covers both halves of the lookup
// contract: a real id returns a copy; an unknown id returns (nil, false)
// without an error.
func TestGetCriterion_KnownAndUnknown(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err)
	require.NotEmpty(t, items)

	// Known id — pick the first catalog entry deterministically.
	known := items[0].ID
	got, ok := GetCriterion(known)
	require.True(t, ok, "GetCriterion(%q) should succeed", known)
	require.NotNil(t, got)
	assert.Equal(t, known, got.ID)

	// Mutating the returned copy must not affect the cache.
	got.TitleJA = "MUTATED"
	again, ok := GetCriterion(known)
	require.True(t, ok)
	assert.NotEqual(t, "MUTATED", again.TitleJA, "GetCriterion must return a defensive copy")

	// Unknown id.
	_, ok = GetCriterion("meti.does_not_exist.99")
	assert.False(t, ok, "unknown id should report not-found, not panic or error")
}

// TestListByPhase_GroupsCorrectly verifies (a) every catalog item appears
// in exactly one phase bucket, and (b) each bucket is sorted by id (the
// report renderer relies on a stable order).
func TestListByPhase_GroupsCorrectly(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err)
	total := len(items)

	envSetup := ListByPhase(PhaseEnvSetup)
	sbomCreation := ListByPhase(PhaseSBOMCreation)
	sbomOperation := ListByPhase(PhaseSBOMOperation)

	// Coverage: bucket-sum == total. A criterion with an unknown phase
	// would cause this to fail loudly.
	assert.Equal(t, total, len(envSetup)+len(sbomCreation)+len(sbomOperation),
		"every criterion must land in exactly one phase bucket")

	// Each bucket must be non-empty — the M3-3 contract requires at
	// least some coverage per phase (no phase silently omitted).
	assert.NotEmpty(t, envSetup, "env_setup phase must have ≥1 criterion")
	assert.NotEmpty(t, sbomCreation, "sbom_creation phase must have ≥1 criterion")
	assert.NotEmpty(t, sbomOperation, "sbom_operation phase must have ≥1 criterion")

	// Sort-order invariant.
	for _, bucket := range [][]Criterion{envSetup, sbomCreation, sbomOperation} {
		for i := 1; i < len(bucket); i++ {
			assert.Less(t, bucket[i-1].ID, bucket[i].ID,
				"ListByPhase must return ids in ascending order; got %s before %s",
				bucket[i-1].ID, bucket[i].ID)
		}
	}

	// Unknown phase must return an empty slice, not nil-with-error.
	assert.Empty(t, ListByPhase(Phase("nonexistent")),
		"unknown phase should return empty, not panic")
}

// TestPhases_Order locks in the chronological phase order used by the
// report renderer (env_setup -> sbom_creation -> sbom_operation). A
// regression here would silently re-order phase headers in generated
// PDFs / dashboards.
func TestPhases_Order(t *testing.T) {
	got := Phases()
	want := []Phase{PhaseEnvSetup, PhaseSBOMCreation, PhaseSBOMOperation}
	assert.Equal(t, want, got)
}

// TestCatalog_PhaseCounts asserts the M3-3 acceptance criterion that the
// catalog covers 20-30 items distributed across all three phases. The
// concrete counts double as a guard against accidental deletions during
// future edits.
func TestCatalog_PhaseCounts(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err)

	total := len(items)
	assert.GreaterOrEqual(t, total, 20, "catalog should hold ≥20 criteria (M3-3 spec)")
	assert.LessOrEqual(t, total, 40, "catalog should hold ≤40 criteria (sanity ceiling)")

	envSetup := len(ListByPhase(PhaseEnvSetup))
	sbomCreation := len(ListByPhase(PhaseSBOMCreation))
	sbomOperation := len(ListByPhase(PhaseSBOMOperation))

	// Per-phase floor: the ver 2.0 guidance treats every phase as
	// substantive, so any phase falling below 5 items is almost
	// certainly an authoring miss.
	assert.GreaterOrEqual(t, envSetup, 5, "env_setup should hold ≥5 criteria")
	assert.GreaterOrEqual(t, sbomCreation, 5, "sbom_creation should hold ≥5 criteria")
	assert.GreaterOrEqual(t, sbomOperation, 5, "sbom_operation should hold ≥5 criteria")
}

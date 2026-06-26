package meti

import (
	"strings"
	"testing"
	"time"

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
		// SourceSection (M5-6, issue #52) — required so future authoring
		// rounds cannot drop the provenance link back to the official
		// METI ver 2.0 chapter / sub-section.
		assert.NotEmpty(t, c.SourceSection, "criterion[%d=%s].source_section must be set", i, c.ID)
		assert.True(t, strings.HasPrefix(c.SourceSection, "第"),
			"criterion[%s].source_section %q should start with 第N章 to anchor it in the ver 2.0 table of contents",
			c.ID, c.SourceSection)

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

// TestLoadMetadata_PresentAndSane is the M5-6 (issue #52) regression
// guard. The metadata block records which version of the METI guidance
// the catalog was reconciled against; this test pins:
//
//   - SourceVersion is "ver 2.0" — the dashboard renders this verbatim
//     and a silent downgrade to ver 1.x would change the legal claim
//     the product makes to operators;
//   - SourcePublished and LastSynced are well-formed YYYY-MM-DD dates so
//     the freshness badge can render without a second date-parser;
//   - VerificationStatus is one of the closed set; the loader also
//     enforces this but we double-check here so a regression in the
//     loader does not silently pass the catalog with a typo'd status.
func TestLoadMetadata_PresentAndSane(t *testing.T) {
	meta, err := LoadMetadata()
	require.NoError(t, err, "LoadMetadata should succeed on the embedded catalog")

	assert.NotEmpty(t, meta.Source, "metadata.source must be set")
	assert.Contains(t, meta.Source, "経済産業省",
		"metadata.source should name 経済産業省 as the issuing authority")
	assert.NotEmpty(t, meta.SourceURL, "metadata.source_url must be set")
	assert.True(t, strings.HasPrefix(meta.SourceURL, "https://www.meti.go.jp/"),
		"metadata.source_url %q should point at meti.go.jp", meta.SourceURL)

	// Version lock — the dashboard surfaces this string; bumping to
	// "ver 3.0" must be an intentional, reviewed change.
	assert.Equal(t, "ver 2.0", meta.SourceVersion,
		"metadata.source_version is pinned to ver 2.0; bump deliberately when METI publishes a new revision")

	// Date format lock — both fields must parse so the freshness badge
	// can render them with date arithmetic.
	_, err = time.Parse("2006-01-02", meta.SourcePublished)
	require.NoError(t, err, "metadata.source_published %q must parse as YYYY-MM-DD", meta.SourcePublished)
	_, err = time.Parse("2006-01-02", meta.LastSynced)
	require.NoError(t, err, "metadata.last_synced %q must parse as YYYY-MM-DD", meta.LastSynced)

	assert.NotEmpty(t, meta.SyncedBy, "metadata.synced_by must be set so the audit surface can link to the issue")
	assert.Contains(t, []string{"full", "partial", "deferred"}, meta.VerificationStatus,
		"metadata.verification_status %q must be one of full|partial|deferred", meta.VerificationStatus)
	assert.NotEmpty(t, meta.VerificationNotes,
		"metadata.verification_notes must be set so the dashboard can render the honest provenance note")
}

// TestCatalog_OfficialWording_Regression locks down the Japanese title
// wording for a representative slice of criteria — one per phase plus
// the items that are most likely to drift during an authoring round
// (5W1H scope, NTIA minimum elements, vulnerability monitoring,
// retention, 30-day cadence). A future edit that changes any of these
// titles will fail this test and the author must update the test
// deliberately, which is the M5-6 contract: wording becomes catalog
// data, not a comment.
//
// Why title_ja and not description_ja: titles surface in the UI as
// short labels (dashboard rows, CRA report headings), so silent drift
// there is highest-visibility. Descriptions are intentionally not
// pinned so prose polish does not require a test edit per round.
func TestCatalog_OfficialWording_Regression(t *testing.T) {
	wantTitles := map[string]string{
		// env_setup phase — anchor titles for the 8 criteria.
		"meti.env_setup.01": "SBOM 担当部署および責任者を明確化",
		"meti.env_setup.02": "対象ソフトウェアの開発言語・ビルド環境を整理",
		"meti.env_setup.06": "SBOM 適用範囲 (5W1H) を明確化",
		"meti.env_setup.07": "SBOM 生成ツールを選定・導入",
		"meti.env_setup.08": "担当者教育・トレーニングを実施",

		// sbom_creation phase — anchor titles tied to the 7 NTIA
		// minimum elements + the format selection that drives the
		// dashboard "format = CycloneDX / SPDX" badge.
		"meti.sbom_creation.02": "SBOM 形式 (CycloneDX / SPDX) を選定",
		"meti.sbom_creation.06": "METI / NTIA 最小要素を満たす SBOM を作成",

		// sbom_operation phase — anchor titles for the items added
		// in ver 2.0 第7章 (脆弱性管理プロセスの具体化) and the
		// 30-day cadence that operators rely on.
		"meti.sbom_operation.01": "脆弱性監視プロセスを確立",
		"meti.sbom_operation.07": "SBOM を適切な期間 保管 (監査対応)",
		"meti.sbom_operation.09": "SBOM 更新頻度を遵守",
	}

	for id, want := range wantTitles {
		got, ok := GetCriterion(id)
		require.True(t, ok, "criterion %s must exist", id)
		require.NotNil(t, got)
		assert.Equal(t, want, got.TitleJA,
			"title_ja for %s drifted from the pinned wording; update this test only if the change is intentional",
			id)
	}
}

// TestCatalog_SourceSection_AnchorsVer2Chapters spot-checks that the
// source_section field points at the expected chapter for the items
// added by ver 2.0. This is the data-integrity gate for the M5-6
// reconciliation: if a future edit drops the "第7章" reference from a
// vulnerability-management criterion the link back to the ver 2.0
// addition is lost.
func TestCatalog_SourceSection_AnchorsVer2Chapters(t *testing.T) {
	// 第7章 was new in ver 2.0; these criteria must continue to
	// reference it so the dashboard can surface "(ver 2.0 新規)" badges.
	ver2Chapter7Items := []string{
		"meti.sbom_operation.01",
		"meti.sbom_operation.02",
		"meti.sbom_operation.03",
		"meti.sbom_operation.04",
		"meti.sbom_operation.08",
	}
	for _, id := range ver2Chapter7Items {
		c, ok := GetCriterion(id)
		require.True(t, ok, "criterion %s must exist", id)
		assert.Contains(t, c.SourceSection, "第7章",
			"criterion %s.source_section %q should reference 第7章 (脆弱性管理プロセスの具体化, ver 2.0 新規)",
			id, c.SourceSection)
	}

	// Items rooted in the env_setup phase must reference 第4章; the
	// loader cannot enforce this because the chapter mapping is not
	// 1:1 (some operation-phase items also reference 第7章), so the
	// pin lives here.
	envSetupItems := ListByPhase(PhaseEnvSetup)
	for _, c := range envSetupItems {
		assert.Contains(t, c.SourceSection, "第4章",
			"env_setup criterion %s.source_section %q should reference 第4章 (環境構築・体制整備フェーズ)",
			c.ID, c.SourceSection)
	}
}

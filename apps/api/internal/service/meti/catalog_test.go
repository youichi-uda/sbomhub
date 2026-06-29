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
//
// M8-1 (issue #62, 2026-06-28): pinned the exact 32-item distribution
// (env_setup 11 / sbom_creation 10 / sbom_operation 11) so a future
// regression that drops one of the IPA 32-item full-coverage items is
// caught here at test time rather than silently shrinking the catalog.
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

	// M8-1 exact-count pin: bump these intentionally when adding new
	// criteria (do not silently relax — the dashboard surfaces the
	// IPA 32-item coverage claim verbatim).
	assert.Equal(t, 32, total,
		"M8-1 (#62): catalog must hold exactly 32 criteria for IPA full-coverage; got %d", total)
	assert.Equal(t, 11, envSetup,
		"M8-1 (#62): env_setup must hold exactly 11 criteria; got %d", envSetup)
	assert.Equal(t, 10, sbomCreation,
		"M8-1 (#62): sbom_creation must hold exactly 10 criteria; got %d", sbomCreation)
	assert.Equal(t, 11, sbomOperation,
		"M8-1 (#62): sbom_operation must hold exactly 11 criteria; got %d", sbomOperation)
}

// TestCatalog_M8_1_NewCriteriaPresent pins the 5 IDs added by M8-1
// (#62) so a regression that silently drops any of them — and thereby
// regresses the IPA 32-item coverage claim — is caught at test time.
// Title / wording exact-match is the M8-2 wave's responsibility; here
// we only assert presence + phase classification.
func TestCatalog_M8_1_NewCriteriaPresent(t *testing.T) {
	wantPhase := map[string]Phase{
		"meti.env_setup.09":     PhaseEnvSetup,     // 4.1.4 構成図可視化
		"meti.env_setup.10":     PhaseEnvSetup,     // 4.4 ツール導入・設定
		"meti.env_setup.11":     PhaseEnvSetup,     // 4.5 ツール学習
		"meti.sbom_creation.10": PhaseSBOMCreation, // 5.3 共有 個別運用
		"meti.sbom_operation.11": PhaseSBOMOperation, // 6.3 提供期間 個別運用
	}
	for id, phase := range wantPhase {
		got, ok := GetCriterion(id)
		require.True(t, ok, "M8-1 criterion %s must exist in catalog", id)
		require.NotNil(t, got)
		assert.Equal(t, phase, got.Phase,
			"M8-1 criterion %s phase should be %s; got %s", id, phase, got.Phase)
		assert.NotEmpty(t, got.TitleJA, "M8-1 criterion %s should have title_ja", id)
		assert.NotEmpty(t, got.EvaluatorHint, "M8-1 criterion %s should have evaluator_hint", id)
		// stub evaluators advertise themselves as M8-1-added in the hint
		// so a grep over the codebase quickly finds the auto-signal TODO.
		assert.Contains(t, got.EvaluatorHint, "M8-1",
			"M8-1 criterion %s evaluator_hint should mention M8-1 provenance; got %q",
			id, got.EvaluatorHint)
	}
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
// wording for ALL 32 catalog criteria. Originally (M5-6, issue #52)
// only a 10-item representative slice was pinned; M8-2 (issue #63,
// 2026-06-28) expanded it to full 32-criteria coverage so that any
// title drift — including for items that don't appear in dashboard
// shortlists — is caught at test time.
//
// A future edit that changes any of these titles will fail this test
// and the author must update the test deliberately, which is the
// M5-6 / M8-2 contract: wording becomes catalog data, not a comment.
//
// Provenance note: M10-2 (issue #75, 2026-06-29) confirmed the
// title_ja wording remains as the M8-1 (issue #62) 1-line
// distillation. Direct char-by-char comparison against the primary
// METI ver 2.0 PDF was completed in M10-2: title_ja values are
// curated 1-line summaries (UI labels) rather than verbatim copies
// of the primary PDF's paragraph-form checklist items, by intentional
// design. See metadata.verification_notes + each criterion's notes:
// field in catalog.yaml for the M10-2 distillation rationale.
//
// Why title_ja and not description_ja: titles surface in the UI as
// short labels (dashboard rows, CRA report headings), so silent drift
// there is highest-visibility. Descriptions are intentionally not
// pinned char-by-char so prose polish does not require a test edit
// per round, but their leading-token shape is asserted in
// TestCatalog_DescriptionJA_LeadingTokens.
func TestCatalog_OfficialWording_Regression(t *testing.T) {
	// 32 criteria full coverage (M8-2, issue #63). Keep in id order so
	// review diffs read top-to-bottom against the catalog file.
	wantTitles := map[string]string{
		// env_setup phase — 11 items (M3-3 で 8 + M8-1 で +3).
		"meti.env_setup.01": "SBOM 担当部署および責任者を明確化",
		"meti.env_setup.02": "対象ソフトウェアの開発言語・ビルド環境を整理",
		"meti.env_setup.03": "サプライヤー / OSS 配布元との契約形態・取引慣行を明確化",
		"meti.env_setup.04": "適用される規制・要求事項を確認",
		"meti.env_setup.05": "組織内制約 (機密情報の取り扱い / 公開範囲) を明確化",
		"meti.env_setup.06": "SBOM 適用範囲 (5W1H) を明確化",
		"meti.env_setup.07": "SBOM 生成ツールを選定・導入",
		"meti.env_setup.08": "担当者教育・トレーニングを実施",
		"meti.env_setup.09": "対象ソフトウェアの構成図を可視化",
		"meti.env_setup.10": "SBOM ツールを導入・設定 (個別運用)",
		"meti.env_setup.11": "SBOM ツールの学習 (運用習熟度確認)",

		// sbom_creation phase — 10 items (M3-3 で 9 + M8-1 で +1).
		"meti.sbom_creation.01": "SBOM 作成方針 (頻度 / トリガー / 粒度) を決定",
		"meti.sbom_creation.02": "SBOM 形式 (CycloneDX / SPDX) を選定",
		"meti.sbom_creation.03": "コンポーネントを解析し SBOM を生成",
		"meti.sbom_creation.04": "解析エラー (パース失敗 / バージョン不明) を確認",
		"meti.sbom_creation.05": "誤検出・検出漏れを確認",
		"meti.sbom_creation.06": "METI / NTIA 最小要素を満たす SBOM を作成",
		"meti.sbom_creation.07": "SBOM 共有方法・配布契約を整備",
		"meti.sbom_creation.08": "SBOM のバージョン管理と差分追跡を実施",
		"meti.sbom_creation.09": "サプライヤー受領 SBOM のマージ / 検証",
		"meti.sbom_creation.10": "SBOM 共有プロセスを個別運用 (受領者管理 / 通知)",

		// sbom_operation phase — 11 items (M3-3 で 10 + M8-1 で +1).
		"meti.sbom_operation.01": "脆弱性監視プロセスを確立",
		"meti.sbom_operation.02": "脆弱性情報源 (NVD / JVN / KEV / GHSA / JPCERT) を特定",
		"meti.sbom_operation.03": "脆弱性を優先付け (EPSS / SSVC / CVSS / KEV)",
		"meti.sbom_operation.04": "脆弱性対応 (VEX 作成・承認・配布) を実施",
		"meti.sbom_operation.05": "ライセンス違反 / コンプライアンス逸脱を確認",
		"meti.sbom_operation.06": "EOL / End-of-Support コンポーネントを特定",
		"meti.sbom_operation.07": "SBOM を適切な期間 保管 (監査対応)",
		"meti.sbom_operation.08": "インシデント対応プロセス (悪用検知時) を整備",
		"meti.sbom_operation.09": "SBOM 更新頻度を遵守",
		"meti.sbom_operation.10": "監査ログ (作成 / 共有 / 承認 / 配布) を記録",
		"meti.sbom_operation.11": "SBOM 提供期間を個別運用 (顧客 / 製品ライン別)",
	}

	// Full-coverage guard: the map must hold exactly 32 entries (one
	// per IPA full-coverage criterion). If the catalog grows or shrinks
	// the author must update this map deliberately — silent drift is
	// not allowed.
	require.Len(t, wantTitles, 32,
		"M8-2 (#63): wantTitles must hold exactly 32 entries to match the IPA full-coverage catalog; got %d",
		len(wantTitles))

	for id, want := range wantTitles {
		got, ok := GetCriterion(id)
		require.True(t, ok, "criterion %s must exist", id)
		require.NotNil(t, got)
		assert.Equal(t, want, got.TitleJA,
			"title_ja for %s drifted from the pinned wording; update this test only if the change is intentional",
			id)
	}

	// Inverse coverage: every catalog criterion must have a pinned
	// title. This catches the case where a new criterion is added
	// without a corresponding regression entry above.
	items, err := LoadCatalog()
	require.NoError(t, err)
	for _, c := range items {
		_, pinned := wantTitles[c.ID]
		assert.True(t, pinned,
			"catalog criterion %s has no pinned title in TestCatalog_OfficialWording_Regression; add it to wantTitles",
			c.ID)
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

// TestCatalog_SourceSection_M10_2_StrictPin (issue #75, 2026-06-29) locks
// down the exact source_section string for every catalog criterion against
// the primary METI ver 2.0 PDF structure as confirmed by character-by-
// character audit. M5-6 / M8-1 / M8-2 used the IPA secondary catalogue's
// table numbering (表：4.1.1 / 表：4.5.1 / 表：6.3.1, etc.) because the
// primary PDF was network-unreachable; M10-2 reset every source_section
// to anchor on the primary PDF's actual section numbers (4.1 / 4.2 /
// 4.3 / 4.4 / 5.1 / 5.2 / 5.3 / 6.1 / 6.2 / 7.x).
//
// A future edit that drifts the source_section will fail this test, and
// the author must update both the catalog and this pin deliberately —
// that is the M10-2 contract: source_section is provenance data, not
// free-form commentary.
func TestCatalog_SourceSection_M10_2_StrictPin(t *testing.T) {
	// Exact source_section strings, keyed by criterion ID. The full
	// pin is intentional: section drift is high-stakes (it determines
	// which PDF passage an auditor opens to verify the catalog claim)
	// and the strings double as the provenance shown by the dashboard.
	wantSections := map[string]string{
		// env_setup phase — 11 items, anchored to primary 4.1 / 4.2 /
		// 4.3 / 4.4 (M10-2 reset from IPA secondary 4.1.x / 4.2 / 4.3 /
		// 4.4 / 4.5 numbering).
		"meti.env_setup.01": "第4章 環境構築・体制整備フェーズ — 章導入文 (体制整備の必要性) + 4.1 SBOM 適用範囲の明確化 (組織内の制約 — 体制の制約) + 6.2 SBOM 情報の管理 (PSIRT / 品質管理部門による管理体制)",
		"meti.env_setup.02": "第4章 環境構築・体制整備フェーズ — 4.1 SBOM 適用範囲の明確化 (checklist No.1 開発言語・コンポーネント形態・開発ツール等)",
		"meti.env_setup.03": "第4章 環境構築・体制整備フェーズ — 4.1 SBOM 適用範囲の明確化 (checklist No.3 利用者及びサプライヤーとの契約形態・取引慣行) / 付録 9 SBOM 取引モデル (ver 2.0 新規)",
		"meti.env_setup.04": "第4章 環境構築・体制整備フェーズ — 4.1 SBOM 適用範囲の明確化 (checklist No.4 SBOM に関する規制・要求事項)",
		"meti.env_setup.05": "第4章 環境構築・体制整備フェーズ — 4.1 SBOM 適用範囲の明確化 (checklist No.5 SBOM 導入に関する組織内の制約)",
		"meti.env_setup.06": "第4章 環境構築・体制整備フェーズ — 4.1 SBOM 適用範囲の明確化 (checklist No.6 SBOM 適用範囲 (5W1H) / 表 4-1 SBOM 適用範囲 (5W1H))",
		"meti.env_setup.07": "第4章 環境構築・体制整備フェーズ — 4.2 SBOM ツールの選定 + 4.3 SBOM ツールの導入・設定",
		"meti.env_setup.08": "第4章 環境構築・体制整備フェーズ — 4.4 SBOM ツールに関する学習",
		"meti.env_setup.09": "第4章 環境構築・体制整備フェーズ — 4.1 SBOM 適用範囲の明確化 (checklist No.2 対象ソフトウェアの正確な構成図 / 図 4-1 システム構成図の例 — 歯科用 CT)",
		"meti.env_setup.10": "第4章 環境構築・体制整備フェーズ — 4.3 SBOM ツールの導入・設定",
		"meti.env_setup.11": "第4章 環境構築・体制整備フェーズ — 4.4 SBOM ツールに関する学習",

		// sbom_creation phase — 10 items, anchored to primary 5.1 / 5.2 /
		// 5.3 plus 2.3 / 2.4 / 6.2 cross-refs (M10-2 reset).
		"meti.sbom_creation.01": "第5章 SBOM 作成・共有フェーズ — 5.2 SBOM の作成 (checklist No.1 SBOM の項目・フォーマット・出力ファイル形式等の要件決定)",
		"meti.sbom_creation.02": "第5章 SBOM 作成・共有フェーズ — 5.2 SBOM の作成 (checklist No.1 SBOM の項目・フォーマット・出力ファイル形式等の要件決定) + 第2章 2.4 SBOM フォーマットの例 (SPDX / CycloneDX / SWID タグ)",
		"meti.sbom_creation.03": "第5章 SBOM 作成・共有フェーズ — 5.1 コンポーネントの解析 (checklist No.1 対象ソフトウェアのスキャン) + 5.2 SBOM の作成 (checklist No.2 SBOM ツールを用いた SBOM 作成)",
		"meti.sbom_creation.04": "第5章 SBOM 作成・共有フェーズ — 5.1 コンポーネントの解析 (checklist No.2 SBOM ツールの解析ログ調査・解析中断・省略の確認)",
		"meti.sbom_creation.05": "第5章 SBOM 作成・共有フェーズ — 5.1 コンポーネントの解析 (checklist No.3 誤検出・検出漏れの確認) + 図 5-1 コンポーネント解析結果の確認の観点及び確認方法",
		"meti.sbom_creation.06": "第2章 SBOM の概要 — 2.3 SBOM の「最小要素」 (表 2-3 / 表 2-4 NTIA Minimum Elements) + 第5章 5.2 SBOM の作成",
		"meti.sbom_creation.07": "第5章 SBOM 作成・共有フェーズ — 5.3 SBOM の共有 (checklist No.1 SBOM 共有方法の検討 / No.2 電子署名等の改ざん防止) / 付録 9 SBOM 取引モデル (ver 2.0 新規)",
		"meti.sbom_creation.08": "第6章 SBOM 運用・管理フェーズ — 6.2 SBOM 情報の管理 (checklist No.1 変更履歴も含めた SBOM 保管 / 本文 SBOM の改変履歴 — 資産管理システム保管)",
		"meti.sbom_creation.09": "第5章 SBOM 作成・共有フェーズ — 5.2 SBOM の作成 (本文 サードパーティ提供 SBOM のインポート・突合) / 付録 9 SBOM 取引モデル (受領 SBOM の品質・責任、 ver 2.0 新規)",
		"meti.sbom_creation.10": "第5章 SBOM 作成・共有フェーズ — 5.3 SBOM の共有 (本文 動的更新・利用者ごとの共有方法選定)",

		// sbom_operation phase — 11 items, anchored to primary 6.1 / 6.2 /
		// 7.4.x (M10-2 reset from IPA secondary 6.1 / 6.2 / 6.3 numbering).
		"meti.sbom_operation.01": "第7章 脆弱性管理プロセスの具体化 (ver 2.0 新規) — 7.4.1 脆弱性特定フェーズ / 第6章 6.1 SBOM に基づく脆弱性管理、ライセンス管理等の実施 (checklist No.1 脆弱性対応)",
		"meti.sbom_operation.02": "第7章 脆弱性管理プロセスの具体化 (ver 2.0 新規) — 7.4.1 脆弱性特定フェーズ ((1.3) 対象とする脆弱性 DB の選択) / 第6章 6.1 SBOM に基づく脆弱性管理、ライセンス管理等の実施",
		"meti.sbom_operation.03": "第7章 脆弱性管理プロセスの具体化 (ver 2.0 新規) — 7.4.2 脆弱性対応優先付けフェーズ ((2.1) 優先付け情報の選択・取得 / (2.2) 優先付け判断ツリー / (2.3) 優先度スコア評価)",
		"meti.sbom_operation.04": "第7章 脆弱性管理プロセスの具体化 (ver 2.0 新規) — 7.4.3 情報共有フェーズ / 7.4.4 脆弱性対応フェーズ ((4.2) SBOM・VEX 等の更新・共有)",
		"meti.sbom_operation.05": "第6章 SBOM 運用・管理フェーズ — 6.1 SBOM に基づく脆弱性管理、ライセンス管理等の実施 (checklist No.2 OSS ライセンス違反確認)",
		"meti.sbom_operation.06": "第6章 SBOM 運用・管理フェーズ — 6.1 SBOM に基づく脆弱性管理、ライセンス管理等の実施 (本文 EOL コンポーネントの特定は手作業)",
		"meti.sbom_operation.07": "第6章 SBOM 運用・管理フェーズ — 6.2 SBOM 情報の管理 (checklist No.1 変更履歴も含めた一定期間保管 / 本文 保管期間 — 製品流通中・販売終了後の保証期間・サポート提供期間・交換部品提供期間・ライセンス指定期間)",
		"meti.sbom_operation.08": "第7章 脆弱性管理プロセスの具体化 (ver 2.0 新規) — 7.4.3 情報共有フェーズ / 7.4.4 脆弱性対応フェーズ (暫定対応の周知 / 根本対応)",
		"meti.sbom_operation.09": "第6章 SBOM 運用・管理フェーズ — 6.2 SBOM 情報の管理 (本文 SBOM に含まれる情報の定期更新)",
		"meti.sbom_operation.10": "第6章 SBOM 運用・管理フェーズ — 6.2 SBOM 情報の管理 (本文 SBOM の改変履歴を資産管理システム等で保管 / 管理体制 — PSIRT・品質管理部門)",
		"meti.sbom_operation.11": "第6章 SBOM 運用・管理フェーズ — 6.2 SBOM 情報の管理 (本文 保管期間の検討要素 — 保証期間・サポート期間・ライセンス条件別の個別指定)",
	}

	require.Len(t, wantSections, 32,
		"M10-2 (#75): wantSections must hold exactly 32 entries; got %d", len(wantSections))

	for id, want := range wantSections {
		got, ok := GetCriterion(id)
		require.True(t, ok, "criterion %s must exist", id)
		require.NotNil(t, got)
		assert.Equal(t, want, got.SourceSection,
			"source_section for %s drifted from the M10-2 primary-PDF pin; update both catalog.yaml and this test only if the change is intentional",
			id)
	}

	// Inverse coverage: every catalog criterion must have a pinned
	// source_section. Catches the case where a new criterion is added
	// without an M10-2 regression entry.
	items, err := LoadCatalog()
	require.NoError(t, err)
	for _, c := range items {
		_, pinned := wantSections[c.ID]
		assert.True(t, pinned,
			"catalog criterion %s has no pinned source_section in TestCatalog_SourceSection_M10_2_StrictPin; add it to wantSections",
			c.ID)
	}
}

// TestCatalog_SourceSection_RejectsIPASecondaryTableNumbering is the
// M10-2 (issue #75) drift guard: the M5-6 / M8-1 wave referenced IPA
// secondary catalogue table numbering (表：4.1.1 / 表：4.5.1 /
// 表：6.3.1, …) because the primary METI ver 2.0 PDF was network-
// unreachable. M10-2 confirmed via local PDF fixture that the primary
// PDF does NOT use such numbering — sections are flat 4.1 / 4.2 / 4.3 /
// 4.4 / 5.1 / 5.2 / 5.3 / 6.1 / 6.2 / 7.x and the only tables in those
// sections are 表 2-3, 表 2-4, 表 4-1, 表 4-2, 図 4-1, 図 5-1, etc.
//
// A future authoring round that copy-pastes from the IPA secondary
// would re-introduce 表：N.N.N references and silently regress the
// M10-2 anchoring. This test catches that.
//
// Banned forms locked in:
//   - 表：4.X.X / 表：5.X.X / 表：6.X.X — IPA dotted-table numbering
//   - "4.5 SBOM ツール" — primary uses 4.4 for tool learning
//   - "6.3 SBOM 情報の管理" — primary uses 6.2
//   - "4.4 SBOM ツールの導入・設定" — primary uses 4.3
//   - "4.3 SBOM ツールの選定" — primary uses 4.2
//   - "4.1.4 対象ソフトウェアの構成図" — primary has no 4.1.x sub-sections,
//     the diagram is checklist No.2 under 4.1
//   - "6.2 SBOM に基づくライセンス管理" — primary 6.1 covers both vuln + licence
func TestCatalog_SourceSection_RejectsIPASecondaryTableNumbering(t *testing.T) {
	bannedPatterns := []struct {
		needle string
		reason string
	}{
		{"表：4.1.1", "IPA secondary table numbering; primary METI ver 2.0 PDF has no 表：4.1.1"},
		{"表：4.2.1", "IPA secondary table numbering"},
		{"表：4.3.1", "IPA secondary table numbering"},
		{"表：4.4.1", "IPA secondary table numbering"},
		{"表：4.5.1", "IPA secondary table numbering"},
		{"表：4.1.2", "IPA secondary table numbering"},
		{"表：4.1.4", "IPA secondary table numbering"},
		{"表：5.1.1", "IPA secondary table numbering"},
		{"表：5.2.1", "IPA secondary table numbering"},
		{"表：5.3.1", "IPA secondary table numbering"},
		{"表：6.1.1", "IPA secondary table numbering"},
		{"表：6.2.1", "IPA secondary table numbering"},
		{"表：6.3.1", "IPA secondary table numbering"},
		{"4.5 SBOM ツールの学習", "primary METI ver 2.0 PDF uses 4.4 for tool learning"},
		{"6.3 SBOM 情報の管理", "primary METI ver 2.0 PDF uses 6.2 for SBOM 情報の管理"},
		{"4.4 SBOM ツールの導入・設定", "primary METI ver 2.0 PDF uses 4.3 for tool install"},
		{"4.3 SBOM ツールの選定", "primary METI ver 2.0 PDF uses 4.2 for tool selection"},
		{"4.1.4 対象ソフトウェアの構成図", "primary METI ver 2.0 PDF has no 4.1.x; diagram is 4.1 checklist No.2"},
		{"6.2 SBOM に基づくライセンス管理", "primary METI ver 2.0 PDF combines vuln + licence into 6.1"},
		{"4.2 SBOM 導入体制の整備", "primary METI ver 2.0 PDF has no separate 4.2 体制 section"},
	}

	items, err := LoadCatalog()
	require.NoError(t, err)

	for _, c := range items {
		for _, banned := range bannedPatterns {
			assert.NotContains(t, c.SourceSection, banned.needle,
				"criterion %s.source_section %q contains banned IPA-secondary form %q (%s) — M10-2 reset every source_section to anchor on the primary PDF; do not re-introduce",
				c.ID, c.SourceSection, banned.needle, banned.reason)
		}
	}
}

// TestCatalog_Notes_PresentForDistilledCriteria (M10-2, issue #75) pins
// the criteria where the catalog text is a deliberate distillation of
// the primary METI ver 2.0 PDF (rather than a verbatim quote of a
// checklist item) — for these, the notes: field must be populated so
// the dashboard can surface "why does this label not match the PDF
// verbatim" provenance, and a future edit that strips the notes must
// fail loudly.
//
// All 32 criteria are listed: every M10-2 criterion gained a notes
// field documenting the primary PDF passage(s) and the distillation
// rationale. If a future criterion lands without one, this test
// catches it.
func TestCatalog_Notes_PresentForDistilledCriteria(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err)

	for _, c := range items {
		assert.NotEmpty(t, c.Notes,
			"criterion %s.notes must be set (M10-2 distillation rationale); empty notes implies the catalog claims verbatim PDF match which is not the case",
			c.ID)
		assert.Contains(t, c.Notes, "M10-2",
			"criterion %s.notes %q should mention M10-2 provenance so a grep over the codebase finds the verification wave",
			c.ID, c.Notes)
	}
}

// TestLoadMetadata_M10_2_VerificationNotesShape (issue #75) asserts the
// verification_notes contain the load-bearing claims that M10-2 makes:
// the primary PDF SHA256, the methodology summary, and the honest
// "partial" rationale. A future round that rewrites the notes must
// preserve these load-bearing tokens or update this test deliberately.
func TestLoadMetadata_M10_2_VerificationNotesShape(t *testing.T) {
	meta, err := LoadMetadata()
	require.NoError(t, err)

	// M10-2 provenance markers — these must remain so the dashboard
	// provenance pane can render the verification chain back to the
	// PDF fixture.
	wantSubstrings := []string{
		"M10-2",
		"issue #75",
		"2026-06-29",
		// Primary PDF SHA256.
		"cd24eff4e082286698f77253492b0eb07a515e3f70e9835ff8d3c1b276b7336a",
		// Summary PDF SHA256.
		"9d46a2f16e4f075b18671b646c8ce0006e057211b041e5a26efa2942c83d0567",
		// Honest distillation note.
		"distillation",
	}
	for _, want := range wantSubstrings {
		assert.Contains(t, meta.VerificationNotes, want,
			"metadata.verification_notes must contain %q (M10-2 load-bearing token)", want)
	}

	// last_synced bump — M10-2 ran on 2026-06-29.
	assert.Equal(t, "2026-06-29", meta.LastSynced,
		"metadata.last_synced should be 2026-06-29 after the M10-2 wave")
	assert.Contains(t, meta.SyncedBy, "M10-2",
		"metadata.synced_by should mention M10-2; got %q", meta.SyncedBy)
}

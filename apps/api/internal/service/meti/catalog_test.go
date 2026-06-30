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

// TestCatalog_VerbatimMatch_Strict (M11-3, issue #78) is the strict
// byte-exact regression for all 32 catalog title_ja strings. It
// replaces the M5-6 / M8-2 TestCatalog_OfficialWording_Regression which
// pinned the 1-line distillation wording; M11-3 rewrote title_ja for
// 17/32 criteria to be byte-for-byte verbatim copies of the primary
// METI ver 2.0 PDF (□ checklist rows or section headings), and kept
// the remaining 15/32 as honest curated distillations with notes:
// rationale. The pin below is therefore the authoritative wording
// table after M11-3.
//
// Tally:
//   - 17 VERBATIM: env_setup.02-09; sbom_creation.02-05/07;
//     sbom_operation.01/02/05/07.
//   - 15 DISTILLED: env_setup.01/10/11; sbom_creation.01/06/08/09/10;
//     sbom_operation.03/04/06/08/09/10/11.
//
// Why title_ja and not description_ja: titles surface in the UI as
// short labels (dashboard rows, CRA report headings). Description
// wording for VERBATIM criteria is verbatim from PDF body too, but
// description prose is allowed to be 1-2 sentences from the PDF
// section body rather than the single checklist row, so the
// byte-exact pin lives on title_ja. Description verbatim is asserted
// by sentinel-token containment instead (see
// TestCatalog_VerbatimDescription_TokenContainment below).
//
// A failure of this test indicates UNINTENTIONAL DRIFT — either the
// catalog wording or this test must be updated deliberately, and
// NEVER by loosening the assertion. If the official PDF is updated
// (ver 2.0 → ver 3.0), bump source_version + re-extract title_ja
// + update this pin in one reviewed change.
func TestCatalog_VerbatimMatch_Strict(t *testing.T) {
	// 32 criteria full coverage. Keep in id order so review diffs read
	// top-to-bottom against the catalog file.
	//
	// VERBATIM entries below correspond to primary METI ver 2.0 PDF
	// (SBOMv2.pdf, SHA256
	// cd24eff4e082286698f77253492b0eb07a515e3f70e9835ff8d3c1b276b7336a)
	// □ checklist rows or section headings, with trailing 。 stripped
	// for label-style rendering. DISTILLED entries are curated 1-line
	// UI labels documented in each criterion's notes: field.
	wantTitles := map[string]string{
		// ── env_setup phase — 11 items ───────────────────────────
		// DISTILLED: no primary PDF anchor (IPA secondary derived).
		"meti.env_setup.01": "SBOM 担当部署および責任者を明確化",
		// VERBATIM 4.1 No.1 (L.2493-2494).
		"meti.env_setup.02": "対象ソフトウェアの開発言語、コンポーネント形態、開発ツール等、対象ソフトウェアに関する情報を明確化する",
		// VERBATIM 4.1 No.3 (L.2496).
		"meti.env_setup.03": "対象ソフトウェアの利用者及びサプライヤーとの契約形態・取引慣行を明確化する",
		// VERBATIM 4.1 No.4 (L.2497).
		"meti.env_setup.04": "対象ソフトウェアの SBOM に関する規制・要求事項を確認する",
		// VERBATIM 4.1 No.5 (L.2498).
		"meti.env_setup.05": "SBOM 導入に関する組織内の制約（体制の制約、コストの制約等）を明確化する",
		// VERBATIM 4.1 No.6 (L.2499).
		"meti.env_setup.06": "整理した情報に基づき、SBOM 適用範囲（5W1H）を明確化する",
		// VERBATIM 4.2 section heading (L.2869).
		"meti.env_setup.07": "SBOM ツールの選定",
		// VERBATIM 4.4 section heading (L.3202).
		"meti.env_setup.08": "SBOM ツールに関する学習",
		// VERBATIM 4.1 No.2 (L.2495).
		"meti.env_setup.09": "対象ソフトウェアの正確な構成図を作成し、SBOM 適用の対象を可視化する",
		// DISTILLED: 4.3 split with env_setup.07; IPA secondary.
		"meti.env_setup.10": "SBOM ツールを導入・設定 (個別運用)",
		// DISTILLED: 4.4 split with env_setup.08; IPA secondary.
		"meti.env_setup.11": "SBOM ツールの学習 (運用習熟度確認)",

		// ── sbom_creation phase — 10 items ───────────────────────
		// DISTILLED: no PDF □ row for cadence/trigger/granularity.
		"meti.sbom_creation.01": "SBOM 作成方針 (頻度 / トリガー / 粒度) を決定",
		// VERBATIM 5.2 No.1 (L.3513).
		"meti.sbom_creation.02": "作成する SBOM の項目、フォーマット、出力ファイル形式等の SBOM に関する要件を決定する",
		// VERBATIM 5.1 No.1 (L.3243).
		"meti.sbom_creation.03": "SBOM ツールを用いて対象ソフトウェアのスキャンを行い、コンポーネントの情報を解析する",
		// VERBATIM 5.1 No.2 (L.3244-3245).
		"meti.sbom_creation.04": "SBOM ツールの解析ログ等を調査し、エラー発生や情報不足による解析の中断や省略がなく、解析が正しく実行されたかを確認する",
		// VERBATIM 5.1 No.3 (L.3246).
		"meti.sbom_creation.05": "コンポーネントの解析結果について、コンポーネントの誤検出や検出漏れがないかを確認する",
		// DISTILLED: NTIA 7-elements is table, not 1-line.
		"meti.sbom_creation.06": "METI / NTIA 最小要素を満たす SBOM を作成",
		// VERBATIM 5.3 No.1 (L.3564-3565).
		"meti.sbom_creation.07": "対象ソフトウェアの利用者及び納入先に対する SBOM の共有方法を検討した上で、必要に応じて、SBOM を共有する",
		// DISTILLED: diff tracking is SBOMHub extension of 6.2 No.1.
		"meti.sbom_creation.08": "SBOM のバージョン管理と差分追跡を実施",
		// DISTILLED: supplier merge in 5.2 body only, no □ row.
		"meti.sbom_creation.09": "サプライヤー受領 SBOM のマージ / 検証",
		// DISTILLED: IPA secondary; per-recipient operation.
		"meti.sbom_creation.10": "SBOM 共有プロセスを個別運用 (受領者管理 / 通知)",

		// ── sbom_operation phase — 11 items ──────────────────────
		// VERBATIM 6.1 No.1 (L.3615-3616).
		"meti.sbom_operation.01": "脆弱性に関する SBOM ツールの出力結果を踏まえ、深刻度の評価、影響度の評価、脆弱性の修正、残存リスクの確認、関係機関への情報提供等の脆弱性対応を行う",
		// VERBATIM 7.4.1 (3) (L.4041-4042).
		"meti.sbom_operation.02": "脆弱性特定や脆弱性対応優先付けにおいて利用する脆弱性 DB を選択する",
		// DISTILLED: 7.4.2 multi-step; SBOMHub 4-axis selection.
		"meti.sbom_operation.03": "脆弱性を優先付け (EPSS / SSVC / CVSS / KEV)",
		// DISTILLED: VEX scattered across 2.5 / 7.4.3 / 7.4.4.
		"meti.sbom_operation.04": "脆弱性対応 (VEX 作成・承認・配布) を実施",
		// VERBATIM 6.1 No.2 (L.3617-3618).
		"meti.sbom_operation.05": "ライセンスに関する SBOM ツールの出力結果を踏まえ、OSS のライセンス違反が発生していないかを確認する",
		// DISTILLED: EOL in 6.1 body only, no □ row.
		"meti.sbom_operation.06": "EOL / End-of-Support コンポーネントを特定",
		// VERBATIM 6.2 No.1 (L.3727-3728).
		"meti.sbom_operation.07": "作成した SBOM は、社外からの問合せがあった場合等に参照できるよう、変更履歴も含めて一定期間保管する",
		// DISTILLED: 24h/72h EU CRA timeline is SBOMHub extension.
		"meti.sbom_operation.08": "インシデント対応プロセス (悪用検知時) を整備",
		// DISTILLED: 30-day cadence is SBOMHub rule.
		"meti.sbom_operation.09": "SBOM 更新頻度を遵守",
		// DISTILLED: audit_log action names are SBOMHub schema.
		"meti.sbom_operation.10": "監査ログ (作成 / 共有 / 承認 / 配布) を記録",
		// DISTILLED: IPA secondary; per-customer provision window.
		"meti.sbom_operation.11": "SBOM 提供期間を個別運用 (顧客 / 製品ライン別)",
	}

	// Full-coverage guard: the map must hold exactly 32 entries. If
	// the catalog grows or shrinks the author must update this map
	// deliberately — silent drift is not allowed.
	require.Len(t, wantTitles, 32,
		"M11-3 (#78): wantTitles must hold exactly 32 entries to match the IPA full-coverage catalog; got %d",
		len(wantTitles))

	for id, want := range wantTitles {
		got, ok := GetCriterion(id)
		require.True(t, ok, "criterion %s must exist", id)
		require.NotNil(t, got)
		assert.Equal(t, want, got.TitleJA,
			"criterion %s drift: title_ja byte-exact mismatch against M11-3 PDF-verbatim pin (or M11-3 distillation pin); fix the catalog or update this test deliberately, NEVER loosen the assertion",
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
			"catalog criterion %s has no pinned title in TestCatalog_VerbatimMatch_Strict; add it to wantTitles",
			c.ID)
	}
}

// TestCatalog_VerbatimDescription_TokenContainment (M11-3, issue #78)
// asserts that the 17 VERBATIM criteria carry description_ja that
// contains the load-bearing PDF body sentence stem. We do not byte-
// exact pin descriptions because they're paragraph-form and may be
// wrapped at different column widths by future yaml lint passes;
// instead, we lock down 1-2 sentinel substrings per criterion that
// must remain present — those substrings come from the primary PDF
// body at the line ranges named in each criterion's notes: field.
//
// Drift here means description_ja diverged from the PDF body the
// notes: field claims is its source — either the description was
// edited away from verbatim, or the notes: field is now lying. Either
// way the author must fix the catalog deliberately.
//
// The 15 DISTILLED criteria are not checked here: their description
// wording is curated and may legitimately evolve without PDF anchor.
func TestCatalog_VerbatimDescription_TokenContainment(t *testing.T) {
	// (criterion_id, sentinel substring that must appear in
	// description_ja). One sentinel per criterion is enough; we pick a
	// distinctive primary-PDF phrase (>=15 chars, not present in any
	// distilled criterion) so a careless prose tweak that drops the
	// verbatim anchor fails this test loudly.
	wantSentinels := map[string]string{
		"meti.env_setup.02":      "SBOM 導入により解決したい自社の課題と SBOM 導入の目的を踏まえ",
		"meti.env_setup.03":      "対象ソフトウェアの利用者及びサプライヤーとの契約形態・取引慣行を整理すること",
		"meti.env_setup.04":      "SBOM のフォーマット・項目や SBOM の活用範囲を決定するために",
		"meti.env_setup.05":      "組織内の体制に関する制約やコストに関する制約",
		"meti.env_setup.06":      "5W1H の観点に分類することができ",
		"meti.env_setup.07":      "整理した観点に基づき、複数の SBOM ツールを評価し、選定する",
		"meti.env_setup.08":      "ツールの使い方に関するノウハウや各機能の概要は記録し、組織内で共有する",
		"meti.env_setup.09":      "リスク管理の範囲を明確化することができる",
		"meti.sbom_creation.02":  "SBOM に含める項目、フォーマット、出力ファイル形式等の SBOM に関する要件を事前に決定する必要がある",
		"meti.sbom_creation.03":  "手動の場合と比較し、効率的にコンポーネントの解析及び SBOM の作成を行うことができる",
		"meti.sbom_creation.04":  "「既知の未知」として把握することが望まれる",
		"meti.sbom_creation.05":  "シンボリックリンクやランタイムライブラリ等のコンポーネント",
		"meti.sbom_creation.07":  "ソフトウェアサプライチェーンの透明性を高める観点で",
		"meti.sbom_operation.01": "脆弱性の箇所を特定し、影響範囲を分析するとともに、リスクの推定及び評価を行い",
		"meti.sbom_operation.02": "NVD、JVN のような公的な脆弱性情報データベース以外に、独自に脆弱性情報データベースを強化",
		"meti.sbom_operation.05": "ライセンスコンプライアンスの状況を確認するとともに",
		"meti.sbom_operation.07": "保管期間は、一般的に対象製品が市場に流通している間",
	}
	require.Len(t, wantSentinels, 17,
		"M11-3 (#78): wantSentinels must hold exactly 17 entries (one per VERBATIM criterion); got %d",
		len(wantSentinels))

	for id, sentinel := range wantSentinels {
		got, ok := GetCriterion(id)
		require.True(t, ok, "criterion %s must exist", id)
		require.NotNil(t, got)
		assert.Contains(t, got.DescriptionJA, sentinel,
			"criterion %s drift: description_ja no longer contains the load-bearing PDF body fragment %q; either the verbatim quote was edited or notes: now misrepresents the source",
			id, sentinel)
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

// TestCatalog_Notes_PresentForDistilledCriteria (M10-2, issue #75;
// extended by M11-3, issue #78) requires every criterion to carry a
// non-empty notes: field. M10-2 introduced the field to document the
// distillation rationale; M11-3 either replaced the notes (for the 17
// VERBATIM criteria) with "M11-3 VERBATIM: ..." provenance or
// reaffirmed them (for the 15 DISTILLED criteria) with "M11-3
// DISTILLED: ..." rationale.
//
// The contract: every criterion's notes: must mention either M10-2
// (legacy provenance preserved) OR M11-3 (current wave provenance) —
// because if neither marker is present, the notes are too old to
// reflect the current catalog wording. M11-3 dropped M10-2 mentions
// from many criteria because the new notes are M11-3-authored; the
// test treats either marker as valid evidence of provenance.
func TestCatalog_Notes_PresentForDistilledCriteria(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err)

	for _, c := range items {
		assert.NotEmpty(t, c.Notes,
			"criterion %s.notes must be set (provenance / distillation rationale); empty notes leaves the dashboard with no way to surface why the label diverges from a literal PDF quote",
			c.ID)
		// Either marker is acceptable; M11-3 is the most current wave
		// but M10-2 markers may persist for criteria whose notes were
		// not rewritten.
		hasMarker := strings.Contains(c.Notes, "M10-2") || strings.Contains(c.Notes, "M11-3")
		assert.True(t, hasMarker,
			"criterion %s.notes %q should mention M10-2 or M11-3 provenance so a grep over the codebase finds the verification wave",
			c.ID, c.Notes)
	}
}

// TestCatalog_Notes_M11_3_VerbatimDistilledTagging (M11-3, issue #78)
// locks in the explicit "M11-3 VERBATIM" vs "M11-3 DISTILLED" tag in
// each criterion's notes: field. This is the M11-3 contract: every
// criterion must either claim VERBATIM (and the catalog wording must
// match the PDF) or DISTILLED (and the notes must document why).
//
// A future edit that flips a criterion from DISTILLED to VERBATIM (or
// vice versa) without updating both the catalog wording and this test
// will fail loudly. Silent toggling is not allowed.
func TestCatalog_Notes_M11_3_VerbatimDistilledTagging(t *testing.T) {
	// Per-criterion expected M11-3 tag. Exactly one of "VERBATIM" /
	// "DISTILLED" must appear in notes: for each id.
	wantTag := map[string]string{
		// 17 VERBATIM
		"meti.env_setup.02":      "VERBATIM",
		"meti.env_setup.03":      "VERBATIM",
		"meti.env_setup.04":      "VERBATIM",
		"meti.env_setup.05":      "VERBATIM",
		"meti.env_setup.06":      "VERBATIM",
		"meti.env_setup.07":      "VERBATIM",
		"meti.env_setup.08":      "VERBATIM",
		"meti.env_setup.09":      "VERBATIM",
		"meti.sbom_creation.02":  "VERBATIM",
		"meti.sbom_creation.03":  "VERBATIM",
		"meti.sbom_creation.04":  "VERBATIM",
		"meti.sbom_creation.05":  "VERBATIM",
		"meti.sbom_creation.07":  "VERBATIM",
		"meti.sbom_operation.01": "VERBATIM",
		"meti.sbom_operation.02": "VERBATIM",
		"meti.sbom_operation.05": "VERBATIM",
		"meti.sbom_operation.07": "VERBATIM",
		// 15 DISTILLED
		"meti.env_setup.01":      "DISTILLED",
		"meti.env_setup.10":      "DISTILLED",
		"meti.env_setup.11":      "DISTILLED",
		"meti.sbom_creation.01":  "DISTILLED",
		"meti.sbom_creation.06":  "DISTILLED",
		"meti.sbom_creation.08":  "DISTILLED",
		"meti.sbom_creation.09":  "DISTILLED",
		"meti.sbom_creation.10":  "DISTILLED",
		"meti.sbom_operation.03": "DISTILLED",
		"meti.sbom_operation.04": "DISTILLED",
		"meti.sbom_operation.06": "DISTILLED",
		"meti.sbom_operation.08": "DISTILLED",
		"meti.sbom_operation.09": "DISTILLED",
		"meti.sbom_operation.10": "DISTILLED",
		"meti.sbom_operation.11": "DISTILLED",
	}
	require.Len(t, wantTag, 32,
		"M11-3 (#78): wantTag must hold exactly 32 entries; got %d", len(wantTag))

	verbatimCount, distilledCount := 0, 0
	for id, tag := range wantTag {
		got, ok := GetCriterion(id)
		require.True(t, ok, "criterion %s must exist", id)
		require.NotNil(t, got)
		assert.Contains(t, got.Notes, "M11-3 "+tag,
			"criterion %s.notes should carry the M11-3 %s tag; current notes: %q",
			id, tag, got.Notes)
		// Mutual exclusion guard.
		otherTag := "VERBATIM"
		if tag == "VERBATIM" {
			otherTag = "DISTILLED"
		}
		assert.NotContains(t, got.Notes, "M11-3 "+otherTag,
			"criterion %s.notes carries BOTH M11-3 %s and M11-3 %s tags — exactly one is allowed",
			id, tag, otherTag)
		if tag == "VERBATIM" {
			verbatimCount++
		} else {
			distilledCount++
		}
	}
	assert.Equal(t, 17, verbatimCount,
		"M11-3 (#78): exactly 17 criteria should be tagged VERBATIM; got %d", verbatimCount)
	assert.Equal(t, 15, distilledCount,
		"M11-3 (#78): exactly 15 criteria should be tagged DISTILLED; got %d", distilledCount)
}

// TestLoadMetadata_M10_2_VerificationNotesShape (issue #75) asserts the
// verification_notes still cite the M10-2 source_section anchor
// verification load-bearing claims: the primary PDF SHA256, the
// methodology summary, and the honest "partial" rationale. M11-3
// (issue #78) extended the notes block; this test preserves the
// historical M10-2 tokens while the M11-3-specific tokens are checked
// by TestLoadMetadata_M11_3_VerificationNotesShape below.
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

	// last_synced bump — M10-2 / M11-3 ran on 2026-06-29; M12-2 (#83)
	// bumped it to 2026-06-30 when the schema split landed and
	// verification_status moved partial → full.
	assert.Equal(t, "2026-06-30", meta.LastSynced,
		"metadata.last_synced should be 2026-06-30 after the M12-2 wave")
}

// TestLoadMetadata_M11_3_VerificationNotesShape (issue #78) asserts the
// load-bearing claims of the M11-3 verbatim-rewrite wave: the
// synced_by attribution, the 17/15 VERBATIM/DISTILLED split, and the
// honest "partial" rationale. A future round that rewrites the notes
// must preserve these tokens or update this test deliberately.
func TestLoadMetadata_M11_3_VerificationNotesShape(t *testing.T) {
	meta, err := LoadMetadata()
	require.NoError(t, err)

	// M11-3 provenance + tally markers — these must remain so the
	// dashboard provenance pane can render "M11-3: 17 verbatim / 15
	// distilled" honestly.
	wantSubstrings := []string{
		"M11-3",
		"issue #78",
		// 17/15 tally.
		"17 件 VERBATIM",
		"15 件 DISTILLED",
		// Methodology + honest partial rationale.
		"VERBATIM",
		"DISTILLED",
		"partial",
		// Both PDF SHA256s cited.
		"cd24eff4e082286698f77253492b0eb07a515e3f70e9835ff8d3c1b276b7336a",
		"9d46a2f16e4f075b18671b646c8ce0006e057211b041e5a26efa2942c83d0567",
	}
	for _, want := range wantSubstrings {
		assert.Contains(t, meta.VerificationNotes, want,
			"metadata.verification_notes must contain %q (M11-3 load-bearing token)", want)
	}

	assert.Contains(t, meta.SyncedBy, "M11-3",
		"metadata.synced_by should still cite M11-3 in the chain (M12-2 extends, not replaces); got %q", meta.SyncedBy)
	// M12-2 (#83) bumped verification_status partial → full when the
	// schema split (verbatim_title_ja + evaluator_text_ja) landed and
	// all 32 criteria gained byte-exact verbatim_title_ja from primary
	// METI ver 2.0 PDF (27 criteria) or IPA secondary (5 criteria).
	// This pin protects against a silent downgrade.
	assert.Equal(t, "full", meta.VerificationStatus,
		"M12-2 (#83) verification_status: full (32/32 verbatim_title_ja populated from primary METI ver 2.0 PDF or IPA secondary); silent downgrade to partial means a regression")
}

// TestLoadMetadata_M12_2_VerificationNotesShape (issue #83) asserts the
// load-bearing claims of the M12-2 schema-split wave: the synced_by
// attribution, the option-A schema (verbatim_title_ja +
// evaluator_text_ja), the IPA-derived 5-criterion provenance, and the
// honest "full" rationale. A future round that rewrites the notes must
// preserve these tokens or update this test deliberately.
func TestLoadMetadata_M12_2_VerificationNotesShape(t *testing.T) {
	meta, err := LoadMetadata()
	require.NoError(t, err)

	// M12-2 provenance + schema markers — these must remain so the
	// dashboard provenance pane can render the M12-2 promotion honestly.
	wantSubstrings := []string{
		"M12-2",
		"issue #83",
		"2026-06-30",
		// option A schema split.
		"verbatim_title_ja",
		"evaluator_text_ja",
		// IPA-derived 5-criterion bucket.
		"ipa-derived",
		// "full" verification claim.
		"full",
		// IPA secondary PDF filename — proves IPA URL was actually
		// fetched as part of M12-2.
		"sbn8o10000001zcl",
		// Primary PDF SHA256 still cited.
		"cd24eff4e082286698f77253492b0eb07a515e3f70e9835ff8d3c1b276b7336a",
	}
	for _, want := range wantSubstrings {
		assert.Contains(t, meta.VerificationNotes, want,
			"metadata.verification_notes must contain %q (M12-2 load-bearing token)", want)
	}

	assert.Contains(t, meta.SyncedBy, "M12-2",
		"metadata.synced_by should mention M12-2; got %q", meta.SyncedBy)
}

// TestCatalog_M12_2_SchemaSplit_AllPopulated (issue #83) asserts that
// every catalog criterion carries non-empty verbatim_title_ja and
// evaluator_text_ja. The M12-2 schema-split contract requires that:
//
//   - VerbatimTitleJA holds the byte-exact official wording (primary
//     METI ver 2.0 PDF, or IPA secondary 2024-12 for the 5 IPA-derived
//     criteria).
//   - EvaluatorTextJA holds the SBOMHub-tuned evaluator-correspondent
//     label (= the M11-3 title_ja that the criteria/*.go signal logic
//     and dashboard render against).
//
// Empty either field would silently regress the audit posture, so the
// loader (catalog.go) rejects it at parse time and this test pins it
// at the test layer too — defence in depth.
func TestCatalog_M12_2_SchemaSplit_AllPopulated(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err)
	require.Len(t, items, 32, "M12-2 (#83) requires the 32-criterion catalog")

	for _, c := range items {
		assert.NotEmpty(t, c.VerbatimTitleJA,
			"criterion %s.verbatim_title_ja must be set (M12-2 #83 schema requires byte-exact official wording for every criterion)",
			c.ID)
		assert.NotEmpty(t, c.EvaluatorTextJA,
			"criterion %s.evaluator_text_ja must be set (M12-2 #83 schema requires evaluator-correspondent wording for every criterion)",
			c.ID)
	}
}

// TestCatalog_M12_2_VerbatimEvaluatorSplit_MutuallyExclusiveForDistilled
// (issue #83) is the M12-2 mutually-exclusive contract: for the 15
// DISTILLED criteria, verbatim_title_ja (official PDF wording) and
// evaluator_text_ja (SBOMHub-tuned wording) must NOT be byte-exact
// equal. This is the structural reason the schema split exists — if
// the two strings overlap exactly there was no reason to distill.
//
// For the 17 VERBATIM criteria, the two fields ARE allowed to be
// equal (the official wording already matches the evaluator semantics
// and no distillation was needed). The test asserts that direction
// too — equality is required on the 17 — so a careless edit that
// drifts the verbatim field from the evaluator field on a VERBATIM
// criterion is caught here.
//
// The VERBATIM / DISTILLED partition is read from the existing M11-3
// notes-tag map (TestCatalog_Notes_M11_3_VerbatimDistilledTagging) so
// the two tests cannot disagree about the canonical split.
func TestCatalog_M12_2_VerbatimEvaluatorSplit_MutuallyExclusiveForDistilled(t *testing.T) {
	// Mirror of the M11-3 tag map. Keep in sync with
	// TestCatalog_Notes_M11_3_VerbatimDistilledTagging — both tests pin
	// the same partition deliberately.
	verbatimIDs := map[string]struct{}{
		"meti.env_setup.02":      {},
		"meti.env_setup.03":      {},
		"meti.env_setup.04":      {},
		"meti.env_setup.05":      {},
		"meti.env_setup.06":      {},
		"meti.env_setup.07":      {},
		"meti.env_setup.08":      {},
		"meti.env_setup.09":      {},
		"meti.sbom_creation.02":  {},
		"meti.sbom_creation.03":  {},
		"meti.sbom_creation.04":  {},
		"meti.sbom_creation.05":  {},
		"meti.sbom_creation.07":  {},
		"meti.sbom_operation.01": {},
		"meti.sbom_operation.02": {},
		"meti.sbom_operation.05": {},
		"meti.sbom_operation.07": {},
	}
	require.Len(t, verbatimIDs, 17,
		"M11-3 partition: exactly 17 criteria are VERBATIM")

	items, err := LoadCatalog()
	require.NoError(t, err)

	verbatimMatchCount, distilledDifferCount := 0, 0
	for _, c := range items {
		_, isVerbatim := verbatimIDs[c.ID]
		if isVerbatim {
			// VERBATIM criteria: verbatim_title_ja and evaluator_text_ja
			// must match — the official wording IS the evaluator label.
			assert.Equal(t, c.VerbatimTitleJA, c.EvaluatorTextJA,
				"VERBATIM criterion %s: verbatim_title_ja and evaluator_text_ja must be equal (official wording is the evaluator label); silent divergence is a M12-2 schema violation",
				c.ID)
			if c.VerbatimTitleJA == c.EvaluatorTextJA {
				verbatimMatchCount++
			}
		} else {
			// DISTILLED criteria: verbatim_title_ja (PDF) and
			// evaluator_text_ja (SBOMHub-tuned) MUST differ. If they
			// happened to be equal, the schema split would be a no-op
			// for this criterion — which violates the M11-3 distillation
			// rationale that the field separation is meant to preserve.
			assert.NotEqual(t, c.VerbatimTitleJA, c.EvaluatorTextJA,
				"DISTILLED criterion %s: verbatim_title_ja and evaluator_text_ja must differ — the whole point of the M12-2 schema split is that the official wording (verbatim) and the SBOMHub-tuned evaluator label (evaluator_text) carry different semantics for distilled criteria",
				c.ID)
			if c.VerbatimTitleJA != c.EvaluatorTextJA {
				distilledDifferCount++
			}
		}
	}
	assert.Equal(t, 17, verbatimMatchCount,
		"M12-2 (#83): exactly 17 VERBATIM criteria should have verbatim_title_ja == evaluator_text_ja; got %d", verbatimMatchCount)
	assert.Equal(t, 15, distilledDifferCount,
		"M12-2 (#83): exactly 15 DISTILLED criteria should have verbatim_title_ja != evaluator_text_ja; got %d", distilledDifferCount)
}

// TestCatalog_M12_2_EvaluatorText_MatchesTitleJA_ForBackwardCompat
// (issue #83) pins the backward-compatibility contract: for every
// criterion, evaluator_text_ja MUST equal title_ja so the existing
// handler (apps/api/internal/handler/meti.go) / evidence_pack
// (apps/api/internal/service/evidence_pack/builder.go) / web frontend
// consumers that read title_ja continue to see the same wording the
// evaluator is matching against.
//
// If a future wave wants to diverge title_ja from evaluator_text_ja
// (e.g. shorten the UI label) the consumer migration must be done in
// the same change so the test does not silently pass with stale UI.
func TestCatalog_M12_2_EvaluatorText_MatchesTitleJA_ForBackwardCompat(t *testing.T) {
	items, err := LoadCatalog()
	require.NoError(t, err)

	for _, c := range items {
		assert.Equal(t, c.TitleJA, c.EvaluatorTextJA,
			"criterion %s: evaluator_text_ja must equal title_ja for backward compat with handler/evidence_pack/web consumers that read title_ja; divergence requires a coordinated consumer migration",
			c.ID)
	}
}

// TestCatalog_M12_2_IPADerivedSource (issue #83) pins the exact set of
// 5 IPA-derived criteria. M12-2 confirmed that these 5 criteria have
// no anchoring sentence in the primary METI ver 2.0 PDF and that
// their verbatim_title_ja was extracted from the IPA secondary
// catalogue (sbn8o10000001zcl.pdf, 2024-12). The Source field
// therefore must be "ipa-derived" so the dashboard provenance pane
// renders the correct badge.
//
// All other 27 criteria must have Source == "" (default =
// meti-primary-ver2.0) — explicit setting is allowed but the loader
// defaults are the maintenance-friendly choice.
func TestCatalog_M12_2_IPADerivedSource(t *testing.T) {
	wantIPADerived := map[string]struct{}{
		"meti.env_setup.01":      {},
		"meti.env_setup.11":      {},
		"meti.sbom_creation.01":  {},
		"meti.sbom_creation.10":  {},
		"meti.sbom_operation.11": {},
	}
	require.Len(t, wantIPADerived, 5,
		"M12-2 (#83): exactly 5 criteria are IPA-derived")

	items, err := LoadCatalog()
	require.NoError(t, err)

	gotIPADerived := 0
	for _, c := range items {
		_, want := wantIPADerived[c.ID]
		if want {
			assert.Equal(t, "ipa-derived", c.Source,
				"criterion %s should have source: ipa-derived (M12-2 IPA secondary provenance); got %q",
				c.ID, c.Source)
			if c.Source == "ipa-derived" {
				gotIPADerived++
			}
		} else {
			// Non-IPA: empty or meti-primary-ver2.0 both acceptable.
			assert.Contains(t, []string{"", "meti-primary-ver2.0"}, c.Source,
				"criterion %s source %q must be empty or 'meti-primary-ver2.0' (primary METI ver 2.0 PDF); only the 5 explicitly IPA-derived criteria carry 'ipa-derived'",
				c.ID, c.Source)
		}
	}
	assert.Equal(t, 5, gotIPADerived,
		"M12-2 (#83): expected exactly 5 IPA-derived criteria; got %d", gotIPADerived)
}

// TestCatalog_M12_2_VerbatimTitleJA_StrictPin (issue #83) is the M12-2
// byte-exact regression for all 32 catalog verbatim_title_ja strings.
// Drift here means the official PDF wording was edited (intentionally
// or not). The author must update both the catalog and this pin
// deliberately — silent drift is not allowed.
//
// Wording sources (per M12-2 verification_notes block):
//
//   - 17 entries: existing M11-3 VERBATIM titles (primary PDF □ rows
//     or section headings). Mirror of TestCatalog_VerbatimMatch_Strict
//     wantTitles[verbatim 17].
//   - 10 entries: M12-2 new primary-PDF anchors (4.3 No.1, 2.3
//     heading, 6.2 No.2, 5.2 body, 7.4.2 / 7.4.3 / 7.4.4 headings,
//     6.1 body, 6.2 body x2).
//   - 5 entries: IPA secondary catalogue (表：4.2.1 No.1 / 表：4.5.1
//     No.1 / 表：6.3.1 No.3 / 表：5.3.1 No.2 / 表：6.3.1 No.2).
func TestCatalog_M12_2_VerbatimTitleJA_StrictPin(t *testing.T) {
	wantVerbatim := map[string]string{
		// ── 17 entries inherited from M11-3 VERBATIM ────────────────
		"meti.env_setup.02":      "対象ソフトウェアの開発言語、コンポーネント形態、開発ツール等、対象ソフトウェアに関する情報を明確化する",
		"meti.env_setup.03":      "対象ソフトウェアの利用者及びサプライヤーとの契約形態・取引慣行を明確化する",
		"meti.env_setup.04":      "対象ソフトウェアの SBOM に関する規制・要求事項を確認する",
		"meti.env_setup.05":      "SBOM 導入に関する組織内の制約（体制の制約、コストの制約等）を明確化する",
		"meti.env_setup.06":      "整理した情報に基づき、SBOM 適用範囲（5W1H）を明確化する",
		"meti.env_setup.07":      "SBOM ツールの選定",
		"meti.env_setup.08":      "SBOM ツールに関する学習",
		"meti.env_setup.09":      "対象ソフトウェアの正確な構成図を作成し、SBOM 適用の対象を可視化する",
		"meti.sbom_creation.02":  "作成する SBOM の項目、フォーマット、出力ファイル形式等の SBOM に関する要件を決定する",
		"meti.sbom_creation.03":  "SBOM ツールを用いて対象ソフトウェアのスキャンを行い、コンポーネントの情報を解析する",
		"meti.sbom_creation.04":  "SBOM ツールの解析ログ等を調査し、エラー発生や情報不足による解析の中断や省略がなく、解析が正しく実行されたかを確認する",
		"meti.sbom_creation.05":  "コンポーネントの解析結果について、コンポーネントの誤検出や検出漏れがないかを確認する",
		"meti.sbom_creation.07":  "対象ソフトウェアの利用者及び納入先に対する SBOM の共有方法を検討した上で、必要に応じて、SBOM を共有する",
		"meti.sbom_operation.01": "脆弱性に関する SBOM ツールの出力結果を踏まえ、深刻度の評価、影響度の評価、脆弱性の修正、残存リスクの確認、関係機関への情報提供等の脆弱性対応を行う",
		"meti.sbom_operation.02": "脆弱性特定や脆弱性対応優先付けにおいて利用する脆弱性 DB を選択する",
		"meti.sbom_operation.05": "ライセンスに関する SBOM ツールの出力結果を踏まえ、OSS のライセンス違反が発生していないかを確認する",
		"meti.sbom_operation.07": "作成した SBOM は、社外からの問合せがあった場合等に参照できるよう、変更履歴も含めて一定期間保管する",
		// ── 10 entries new in M12-2 from primary PDF anchors ────────
		"meti.env_setup.10":      "SBOM ツールが導入可能な環境の要件を確認し、整備する",
		"meti.sbom_creation.06":  "SBOM の「最小要素」",
		"meti.sbom_creation.08":  "SBOM に含まれる情報や SBOM 自体を適切に管理する",
		"meti.sbom_creation.09":  "サードパーティや OSS コミュニティ等の第三者から提供されたコンポーネントを使用している場合は、当該コンポーネントの SBOM の提供を受けることができる場合もある",
		"meti.sbom_operation.03": "脆弱性対応優先付けフェーズ",
		"meti.sbom_operation.04": "脆弱性対応フェーズ（暫定対応・根本対応）",
		"meti.sbom_operation.06": "SBOM ツールでコンポーネントの EOL を特定できない場合、別途個別に調査する必要がある",
		"meti.sbom_operation.08": "情報共有フェーズ",
		"meti.sbom_operation.09": "SBOM に含まれる情報は定期的に更新し、管理する必要がある",
		"meti.sbom_operation.10": "出荷済み製品と SBOM 情報とを対応づけられるよう、SBOM の改変履歴も含めて資産管理システム等で保管することも想定される",
		// ── 5 entries from IPA secondary catalogue ─────────────────
		"meti.env_setup.01":      "自組織における SBOM 導入・運用に係る役割と部門を精査する",
		"meti.env_setup.11":      "導入した SBOM ツールの手順書を作成する",
		"meti.sbom_creation.01":  "SBOM の更新条件や時期を決める",
		"meti.sbom_creation.10":  "SBOM の公開範囲、自社の特性を考慮し共有方法を検討する",
		"meti.sbom_operation.11": "SBOM の提供期間を定める",
	}
	require.Len(t, wantVerbatim, 32,
		"M12-2 (#83): wantVerbatim must hold exactly 32 entries (one per criterion); got %d", len(wantVerbatim))

	for id, want := range wantVerbatim {
		got, ok := GetCriterion(id)
		require.True(t, ok, "criterion %s must exist", id)
		require.NotNil(t, got)
		assert.Equal(t, want, got.VerbatimTitleJA,
			"criterion %s drift: verbatim_title_ja byte-exact mismatch against M12-2 PDF / IPA pin; fix the catalog or update this test deliberately, NEVER loosen the assertion",
			id)
	}

	// Inverse coverage: every catalog criterion must have a pinned
	// verbatim_title_ja. Catches the case where a new criterion is
	// added without an M12-2 regression entry.
	items, err := LoadCatalog()
	require.NoError(t, err)
	for _, c := range items {
		_, pinned := wantVerbatim[c.ID]
		assert.True(t, pinned,
			"catalog criterion %s has no pinned verbatim_title_ja in TestCatalog_M12_2_VerbatimTitleJA_StrictPin; add it to wantVerbatim",
			c.ID)
	}
}

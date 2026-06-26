package criteria

// sbom_creation.go — phase 2 (SBOM 作成・共有) evaluators (9 criteria).
//
// Mapping per catalog.yaml evaluator_hint (M3-3 / #39):
//
//   01 作成方針 / 頻度        — auto via sbom count within last 30 days.
//   02 形式選定               — auto: latest sbom.format is CycloneDX or SPDX.
//   03 コンポーネント解析     — auto: latest sbom has components > 0.
//   04 解析エラー             — auto: # components with empty / "unknown"
//                              version on the latest sbom == 0.
//   05 誤検出 / 検出漏れ      — manual only (cross-tool diff is M3 follow-up).
//   06 NTIA 最小要素          — auto: in-package implementation of the seven
//                              minimum-element sub-checks (independent from
//                              the larger ComplianceService implementation
//                              to avoid an import cycle with internal/service).
//                              ※要確認: lift the shared logic into a tiny
//                              helper package once M3-6 evidence-pack also
//                              needs it; current copy is intentionally
//                              scoped to the boolean "all 7 pass" verdict.
//   07 共有チャネル / 配布契約 — auto: public_links exist for the project.
//   08 版管理 / 差分追跡       — auto: >=2 sboms exist (diff computable).
//   09 サプライヤー SBOM マージ — manual only (sboms.source column TBD).

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
)

// EvaluateSBOMCreation01 — SBOM 作成方針 (頻度 / トリガー / 粒度) を決定.
//
// Auto: any SBOM uploaded within the last 30 days demonstrates an
// active cadence. If sboms exist but all are older than 30 days,
// downgrade to needs_review (the policy may exist but is no longer
// being honoured — operator should attest). Zero sboms -> not_achieved.
func EvaluateSBOMCreation01(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sboms, err := deps.ListSbomsByProject(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if len(sboms) == 0 {
		return Result{
			Status:            StatusNotAchieved,
			Evidence:          emptyEvidence(),
			ImprovementAction: "SBOM の生成頻度 / トリガー / 粒度を決め、 CI に組み込んでください (推奨: リリース毎・コンテナイメージ単位)。",
		}, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -30)
	recent := 0
	for _, s := range sboms {
		if s.CreatedAt.After(cutoff) {
			recent++
		}
	}
	ev := mustEvidence([]map[string]any{
		evidenceEntry("sboms_count_total", len(sboms)),
		evidenceEntry("sboms_count_last_30d", recent),
	})
	if recent >= 1 {
		return Result{Status: StatusAchieved, Evidence: ev}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          ev,
		ImprovementAction: "直近 30 日 SBOM 更新がありません。 CI に SBOM 再生成を組み込み、 リリース毎の cadence を回復してください。",
	}, nil
}

// EvaluateSBOMCreation02 — SBOM 形式 (CycloneDX / SPDX) を選定.
//
// Auto: latest sbom.format normalises to "cyclonedx" or "spdx".
// The repository stores either uppercase or lowercase depending on
// the import path; we compare case-insensitively.
func EvaluateSBOMCreation02(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sbom, err := deps.GetLatestSbom(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if sbom == nil {
		return Result{
			Status:            StatusNotAchieved,
			Evidence:          emptyEvidence(),
			ImprovementAction: "CycloneDX または SPDX 形式の SBOM を選定し、 取引先 / 監査人 / 規制要件に合わせてバージョンを固定してください。",
		}, nil
	}
	normalised := strings.ToLower(strings.TrimSpace(sbom.Format))
	if normalised == "cyclonedx" || normalised == "spdx" {
		return Result{
			Status: StatusAchieved,
			Evidence: mustEvidence([]map[string]any{
				evidenceEntry("latest_format", sbom.Format),
				evidenceEntry("latest_spec_version", sbom.Version),
			}),
		}, nil
	}
	return Result{
		Status: StatusNotAchieved,
		Evidence: mustEvidence([]map[string]any{
			evidenceEntry("latest_format", sbom.Format),
		}),
		ImprovementAction: "SBOM 形式が CycloneDX / SPDX 以外です。 業界標準形式に切り替えてください。",
	}, nil
}

// EvaluateSBOMCreation03 — コンポーネントを解析し SBOM を生成.
//
// Auto: latest sbom has > 0 components. Zero (or no sbom) ->
// not_achieved.
func EvaluateSBOMCreation03(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sbom, err := deps.GetLatestSbom(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if sbom == nil {
		return Result{
			Status:            StatusNotAchieved,
			Evidence:          emptyEvidence(),
			ImprovementAction: "SBOM がアップロードされていません。 ビルド成果物をスキャンして SBOM を生成してください。",
		}, nil
	}
	components, err := deps.ListComponentsBySbom(ctx, sbom.ID)
	if err != nil {
		return Result{}, err
	}
	if len(components) == 0 {
		return Result{
			Status:            StatusNotAchieved,
			Evidence:          mustEvidence([]map[string]any{evidenceEntry("components_count", 0)}),
			ImprovementAction: "最新 SBOM のコンポーネントがゼロです。 スキャナ設定 (対象ディレクトリ / lockfile) を確認してください。",
		}, nil
	}
	return Result{
		Status: StatusAchieved,
		Evidence: mustEvidence([]map[string]any{
			evidenceEntry("components_count", len(components)),
		}),
	}, nil
}

// EvaluateSBOMCreation04 — 解析エラー (パース失敗 / バージョン不明) を確認.
//
// Auto: count of components with empty / "unknown" version on the
// latest sbom. Zero -> achieved. Otherwise -> not_achieved with the
// count surfaced as evidence.
func EvaluateSBOMCreation04(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sbom, err := deps.GetLatestSbom(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if sbom == nil {
		return Result{
			Status:            StatusNeedsReview,
			Evidence:          emptyEvidence(),
			ImprovementAction: "SBOM がアップロードされていないため解析エラーを判定できません。 先に SBOM を生成してください。",
		}, nil
	}
	components, err := deps.ListComponentsBySbom(ctx, sbom.ID)
	if err != nil {
		return Result{}, err
	}
	unknown := 0
	for _, c := range components {
		v := strings.ToLower(strings.TrimSpace(c.Version))
		if v == "" || v == "unknown" {
			unknown++
		}
	}
	ev := mustEvidence([]map[string]any{
		evidenceEntry("components_count", len(components)),
		evidenceEntry("unknown_version_count", unknown),
	})
	if unknown == 0 {
		return Result{Status: StatusAchieved, Evidence: ev}, nil
	}
	return Result{
		Status:            StatusNotAchieved,
		Evidence:          ev,
		ImprovementAction: "「version: unknown」 のコンポーネントが残っています。 スキャナ警告を確認し、 lockfile 等で版を解決してください。",
	}, nil
}

// EvaluateSBOMCreation05 — 誤検出・検出漏れを確認.
//
// Manual only; cross-tool diff (Syft vs Trivy) is an M3 follow-up.
func EvaluateSBOMCreation05(_ context.Context, _ Deps, _, _ uuid.UUID) (Result, error) {
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "package-lock / go.sum 等のビルド成果物と SBOM を突き合わせ、 誤検出 / 検出漏れを確認してください。",
	}, nil
}

// EvaluateSBOMCreation06 — METI / NTIA 最小要素を満たす SBOM を作成.
//
// Auto: re-implement the seven sub-checks inline. The full
// ComplianceService implementation in apps/api/internal/service/
// compliance.go also raw-parses sbom.RawData (which carries the
// document-level metadata fields like timestamp / authors); the
// version below mirrors the same logic so this package stays
// self-contained and does not pull in the parent service import.
// A failure on ANY of the seven sub-checks -> not_achieved; otherwise
// achieved. Evidence enumerates which sub-checks passed.
func EvaluateSBOMCreation06(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sbom, err := deps.GetLatestSbom(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if sbom == nil {
		return Result{
			Status:            StatusNotAchieved,
			Evidence:          emptyEvidence(),
			ImprovementAction: "SBOM がアップロードされていないため最小要素を判定できません。",
		}, nil
	}
	components, err := deps.ListComponentsBySbom(ctx, sbom.ID)
	if err != nil {
		return Result{}, err
	}
	checks := minimumElementsResult(components, sbom)
	allPass := true
	for _, v := range checks {
		if !v {
			allPass = false
			break
		}
	}
	evEntries := []map[string]any{
		evidenceEntry("components_count", len(components)),
	}
	for k, v := range checks {
		evEntries = append(evEntries, map[string]any{"kind": "minimum_element", "field": k, "value": v})
	}
	if allPass {
		return Result{Status: StatusAchieved, Evidence: mustEvidence(evEntries)}, nil
	}
	return Result{
		Status:            StatusNotAchieved,
		Evidence:          mustEvidence(evEntries),
		ImprovementAction: "NTIA / METI 最小要素 (supplier_name / component_name / component_version / unique_identifier / dependency_relationship / sbom_author / timestamp) のうち未充足項目を SBOM に追加してください。",
	}, nil
}

// EvaluateSBOMCreation07 — SBOM 共有方法・配布契約を整備.
//
// Auto: at least one public_link configured for the project.
func EvaluateSBOMCreation07(ctx context.Context, deps Deps, tenantID, projectID uuid.UUID) (Result, error) {
	links, err := deps.ListPublicLinksByProject(ctx, tenantID, projectID)
	if err != nil {
		return Result{}, err
	}
	if len(links) > 0 {
		return Result{
			Status: StatusAchieved,
			Evidence: mustEvidence([]map[string]any{
				evidenceEntry("public_links_count", len(links)),
			}),
		}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "顧客 / 監査人への SBOM 配布チャネル (公開リンク / 顧客ポータル 等) と受領者の取り扱い条項を整備してください。",
	}, nil
}

// EvaluateSBOMCreation08 — SBOM のバージョン管理と差分追跡を実施.
//
// Auto: at least two SBOM revisions in the project so the diff
// service can compute a delta. Single SBOM -> needs_review (the
// operator may have just started; no failure verdict). Zero -> needs_review.
func EvaluateSBOMCreation08(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sboms, err := deps.ListSbomsByProject(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	ev := mustEvidence([]map[string]any{
		evidenceEntry("sboms_count", len(sboms)),
	})
	if len(sboms) >= 2 {
		return Result{Status: StatusAchieved, Evidence: ev}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          ev,
		ImprovementAction: "SBOM の版管理を行い、 リリース毎に前版との差分 (追加 / 削除 / 更新) を可視化してください。",
	}, nil
}

// EvaluateSBOMCreation09 — サプライヤー受領 SBOM のマージ / 検証.
//
// Manual only (sboms.source column does not yet distinguish
// uploaded vs merged supplier SBOMs).
func EvaluateSBOMCreation09(_ context.Context, _ Deps, _, _ uuid.UUID) (Result, error) {
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "サプライヤー受領 SBOM を自社 SBOM とマージ or リンクし、 署名 / タイムスタンプ / 形式準拠を検証してください。",
	}, nil
}

// minimumElementsResult evaluates the seven NTIA / METI minimum
// elements over the supplied components + raw SBOM metadata, and
// returns a per-element pass/fail map.
//
// Per-component checks (supplier_name / component_name /
// component_version / unique_identifier) use the same 80% threshold
// as ComplianceService.checkMinimumElements; document-level checks
// (dependency_relationship / sbom_author / timestamp) are boolean.
// The threshold mirrors the existing logic so the M3 evaluator
// matches the legacy compliance dashboard verdict for a given SBOM.
func minimumElementsResult(components []model.Component, sbom *model.Sbom) map[string]bool {
	out := map[string]bool{
		"supplier_name":           false,
		"component_name":          false,
		"component_version":       false,
		"unique_identifier":       false,
		"dependency_relationship": false,
		"sbom_author":             false,
		"timestamp":               false,
	}
	if len(components) == 0 {
		return out
	}
	threshold := 0.8
	total := float64(len(components))
	supplier, name, version, purl := 0, 0, 0, 0
	for _, c := range components {
		if hasSupplierFromPurl(c.Purl) {
			supplier++
		}
		if strings.TrimSpace(c.Name) != "" {
			name++
		}
		if strings.TrimSpace(c.Version) != "" {
			version++
		}
		if strings.TrimSpace(c.Purl) != "" {
			purl++
		}
	}
	out["supplier_name"] = float64(supplier)/total >= threshold
	out["component_name"] = float64(name)/total >= threshold
	out["component_version"] = float64(version)/total >= threshold
	out["unique_identifier"] = float64(purl)/total >= threshold

	var raw map[string]any
	if sbom != nil && len(sbom.RawData) > 0 {
		_ = json.Unmarshal(sbom.RawData, &raw)
	}
	out["dependency_relationship"] = hasDependencyRelationship(raw, sbom)
	out["sbom_author"] = hasSBOMAuthor(raw, sbom)
	out["timestamp"] = hasSBOMTimestamp(raw, sbom)
	return out
}

// hasSupplierFromPurl returns true when a PURL carries a namespace
// segment (pkg:type/namespace/name@version). A namespace is the most
// common proxy for "supplier" in NTIA terms — the legacy
// ComplianceService uses the same heuristic. We do NOT consult
// the raw SBOM components[].supplier field here (the legacy code
// does) because the criteria/ package cannot reach into raw SBOM
// JSON per-component without re-implementing the format dispatcher
// — that is what the legacy ComplianceService is for and is out of
// scope for the M3-2 evaluator. The 80% threshold gives the
// heuristic enough slack to pass projects where most components
// have a namespace.
func hasSupplierFromPurl(purl string) bool {
	p := strings.TrimSpace(purl)
	if p == "" || !strings.HasPrefix(p, "pkg:") {
		return false
	}
	// pkg:type/namespace/name@version — count "/" between "pkg:" and
	// "@". Two slashes => type + namespace + name; one slash => type +
	// name only (no supplier namespace).
	body := p[len("pkg:"):]
	if at := strings.IndexByte(body, '@'); at >= 0 {
		body = body[:at]
	}
	return strings.Count(body, "/") >= 2
}

// hasDependencyRelationship returns true when the raw SBOM document
// carries dependency edges. CycloneDX uses `dependencies[]`; SPDX
// uses `relationships[]`. Format dispatch follows sbom.Format.
func hasDependencyRelationship(raw map[string]any, sbom *model.Sbom) bool {
	if raw == nil || sbom == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(sbom.Format)) {
	case "cyclonedx":
		if v, ok := raw["dependencies"].([]any); ok && len(v) > 0 {
			return true
		}
	case "spdx":
		if v, ok := raw["relationships"].([]any); ok && len(v) > 0 {
			return true
		}
	}
	return false
}

// hasSBOMAuthor returns true when the raw SBOM declares its author /
// generating tool. Mirrors the legacy ComplianceService heuristic
// (CycloneDX metadata.authors OR metadata.tools[]; SPDX
// creationInfo.creators[]).
func hasSBOMAuthor(raw map[string]any, sbom *model.Sbom) bool {
	if raw == nil || sbom == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(sbom.Format)) {
	case "cyclonedx":
		meta, ok := raw["metadata"].(map[string]any)
		if !ok {
			return false
		}
		if authors, ok := meta["authors"].([]any); ok && len(authors) > 0 {
			return true
		}
		// CycloneDX 1.4 tools as array; 1.5+ tools as object with components.
		switch tools := meta["tools"].(type) {
		case []any:
			if len(tools) > 0 {
				return true
			}
		case map[string]any:
			if comps, ok := tools["components"].([]any); ok && len(comps) > 0 {
				return true
			}
		}
	case "spdx":
		info, ok := raw["creationInfo"].(map[string]any)
		if !ok {
			return false
		}
		if creators, ok := info["creators"].([]any); ok && len(creators) > 0 {
			return true
		}
	}
	return false
}

// hasSBOMTimestamp returns true when the raw SBOM carries a generation
// timestamp. Mirrors the legacy heuristic (CycloneDX metadata.timestamp;
// SPDX creationInfo.created).
func hasSBOMTimestamp(raw map[string]any, sbom *model.Sbom) bool {
	if raw == nil || sbom == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(sbom.Format)) {
	case "cyclonedx":
		if meta, ok := raw["metadata"].(map[string]any); ok {
			if ts, ok := meta["timestamp"].(string); ok && strings.TrimSpace(ts) != "" {
				return true
			}
		}
	case "spdx":
		if info, ok := raw["creationInfo"].(map[string]any); ok {
			if created, ok := info["created"].(string); ok && strings.TrimSpace(created) != "" {
				return true
			}
		}
	}
	return false
}

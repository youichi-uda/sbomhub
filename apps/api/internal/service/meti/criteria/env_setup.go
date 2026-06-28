package criteria

// env_setup.go — phase 1 (環境構築・体制整備) evaluators (11 criteria).
//
// Mapping notes per the catalog.yaml evaluator_hint (M3-3 / #39 + M8-1 / #62):
//
//   01 担当部署 / 責任者     — manual only, no DB signal -> needs_review.
//   02 開発言語 / ビルド環境 — auto via distinct PURL prefixes across the
//                              project's latest SBOM components.
//   03 契約 / 取引慣行       — manual only -> needs_review.
//   04 規制 / 要求事項       — manual base; auto-augment: cra_reports >= 1
//                              implies EU CRA scope is in play.
//   05 組織内制約 / 公開範囲 — manual base; auto-augment: public_links exist
//                              implies disclosure scope already considered.
//   06 SBOM 適用範囲 (5W1H)  — manual only -> needs_review (sbom presence
//                              alone cannot confirm the 5W1H matrix).
//   07 SBOM 生成ツール       — auto: sboms count >= 1 implies a tool was
//                              chosen and installed.
//   08 担当者教育            — manual only -> needs_review.
//   09 構成図可視化 (4.1.4)  — M8-1 で追加。 auto-signal 未実装の stub。
//                              architecture diagram は現状 DB 表現を持たず
//                              manual attestation 必須 -> needs_review。
//   10 ツール導入・設定 (4.4) — M8-1 で追加。 auto-signal 未実装の stub。
//                              ツール選定 (07) との重複を避け個別運用設定
//                              の妥当性を将来的に scan_settings から判定。
//   11 ツール学習 (4.5)       — M8-1 で追加。 auto-signal 未実装の stub。
//                              担当者教育 (08) との重複を避けハンズオン
//                              実績 (sbom.created actor 多様性) を将来判定。
//
// Status of "needs_review" is deliberate for the manual items: the
// evaluator does NOT default to not_achieved for those, because the
// dashboard reads "not_achieved" as "we verified you failed" — which
// would be wrong when the evaluator can't see the answer at all.

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
)

// EvaluateEnvSetup01 — SBOM 担当部署および責任者を明確化.
//
// No DB-side signal exists for organisational responsibility
// assignments (M3-6 may add a tenant_users role table). Return
// needs_review so the M3-4 override path is the dominant resolution
// channel; the dashboard surfaces the improvement_action to nudge
// the operator.
func EvaluateEnvSetup01(_ context.Context, _ Deps, _, _ uuid.UUID) (Result, error) {
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "SBOM 担当部署と責任者 (例: PSIRT 長) を文書化し、 連絡窓口を明示してください。",
	}, nil
}

// EvaluateEnvSetup02 — 対象ソフトウェアの開発言語・ビルド環境を整理.
//
// Auto-signal: distinct PURL `pkg:<type>` prefixes observed across
// the project's latest SBOM components. ≥1 prefix means the scanner
// successfully identified at least one ecosystem; we treat that as
// "the operator has decided which language(s) the SBOM tool should
// cover". Zero PURLs / no SBOM -> needs_review (the inventory has
// not been recorded in a machine-readable place yet).
func EvaluateEnvSetup02(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sbom, err := deps.GetLatestSbom(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if sbom == nil {
		return Result{
			Status:            StatusNeedsReview,
			Evidence:          emptyEvidence(),
			ImprovementAction: "対象ソフトウェアの開発言語・ビルドツールを棚卸しし、 SBOM 生成ツールの担当範囲を確定してください。",
		}, nil
	}
	components, err := deps.ListComponentsBySbom(ctx, sbom.ID)
	if err != nil {
		return Result{}, err
	}
	prefixes := distinctPurlPrefixes(components)
	if len(prefixes) == 0 {
		return Result{
			Status:            StatusNeedsReview,
			Evidence:          mustEvidence([]map[string]any{evidenceEntry("components_count", len(components))}),
			ImprovementAction: "コンポーネントの PURL が空です。 SBOM 生成ツールが対象スタックを正しく解析できているか確認してください。",
		}, nil
	}
	return Result{
		Status: StatusAchieved,
		Evidence: mustEvidence([]map[string]any{
			evidenceEntry("ecosystems", prefixes),
			evidenceEntry("components_count", len(components)),
		}),
		ImprovementAction: "",
	}, nil
}

// EvaluateEnvSetup03 — サプライヤー / OSS 配布元との契約形態・取引慣行を明確化.
//
// Manual only; supplier_contracts table does not exist yet.
func EvaluateEnvSetup03(_ context.Context, _ Deps, _, _ uuid.UUID) (Result, error) {
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "サプライヤー / OSS の SBOM 受領経路と取り扱いポリシーを契約条項に明記してください。",
	}, nil
}

// EvaluateEnvSetup04 — 適用される規制・要求事項を確認.
//
// Auto-augment: a CRA report on file means the operator has already
// engaged with the EU Cyber Resilience Act process for this project,
// which is the strongest available signal that regulation scope has
// been confirmed. Absence of a CRA report does not imply failure (the
// project may not ship to the EU at all), so the fallback is
// needs_review, not not_achieved.
func EvaluateEnvSetup04(ctx context.Context, deps Deps, tenantID, projectID uuid.UUID) (Result, error) {
	reports, err := deps.ListCRAReportsByProject(ctx, tenantID, projectID)
	if err != nil {
		return Result{}, err
	}
	if len(reports) > 0 {
		return Result{
			Status: StatusAchieved,
			Evidence: mustEvidence([]map[string]any{
				evidenceEntry("cra_reports_count", len(reports)),
			}),
			ImprovementAction: "",
		}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "出荷地域・業界の規制 (EU CRA / EO 14028 / IPA 政府調達基準 等) を棚卸しし、 SBOM 最小要素・提出期限を設計に反映してください。",
	}, nil
}

// EvaluateEnvSetup05 — 組織内制約 (機密 / 公開範囲) を明確化.
//
// Auto-augment: a configured public link means the operator has made
// at least one external-share decision, which presupposes a
// confidentiality policy. Absence is not failure — most projects
// keep SBOMs internal — so the fallback is needs_review.
func EvaluateEnvSetup05(ctx context.Context, deps Deps, tenantID, projectID uuid.UUID) (Result, error) {
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
			ImprovementAction: "",
		}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "内部依存・社内ライブラリの機密区分と、 顧客 / 第三者への SBOM 開示範囲を文書化してください。",
	}, nil
}

// EvaluateEnvSetup06 — SBOM 適用範囲 (5W1H) を明確化.
//
// Manual; the 5W1H matrix is a documentation artefact that cannot
// be inferred from "SBOM exists". needs_review keeps the operator
// in the loop. We surface the SBOM presence as evidence so the
// override reviewer has the most relevant signal at hand.
func EvaluateEnvSetup06(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sboms, err := deps.ListSbomsByProject(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          mustEvidence([]map[string]any{evidenceEntry("sboms_count", len(sboms))}),
		ImprovementAction: "SBOM の Who / When / Where / What / Why / How を文書化してください (リリース毎 / 自動 / 内部+顧客 等)。",
	}, nil
}

// EvaluateEnvSetup07 — SBOM 生成ツールを選定・導入.
//
// Auto: at least one SBOM upload proves a tool was installed and
// produced output. Zero SBOMs -> not_achieved (the operator has
// not stood up the tool at all yet).
func EvaluateEnvSetup07(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sboms, err := deps.ListSbomsByProject(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if len(sboms) == 0 {
		return Result{
			Status:            StatusNotAchieved,
			Evidence:          emptyEvidence(),
			ImprovementAction: "Syft / Trivy / cdxgen 等の SBOM 生成ツールを選定し、 ローカル / CI で実行できる環境を整備してください。",
		}, nil
	}
	latest := sboms[0] // ListSbomsByProject is created_at DESC.
	return Result{
		Status: StatusAchieved,
		Evidence: mustEvidence([]map[string]any{
			evidenceEntry("sboms_count", len(sboms)),
			evidenceEntry("latest_format", latest.Format),
			evidenceEntry("latest_uploaded_at", latest.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")),
		}),
		ImprovementAction: "",
	}, nil
}

// EvaluateEnvSetup08 — 担当者教育・トレーニングを実施.
//
// Manual only (no training_records table yet).
func EvaluateEnvSetup08(_ context.Context, _ Deps, _, _ uuid.UUID) (Result, error) {
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "CycloneDX / SPDX / PURL / VEX / 脆弱性 DB の利用方法について担当者向け教育を実施し、 受講記録を保管してください。",
	}, nil
}

// EvaluateEnvSetup09 — 対象ソフトウェアの構成図を可視化 (4.1.4).
//
// M8-1 (issue #62) で追加。 auto-signal 未実装の stub。 構成図 (architecture
// diagram) は現状 DB 表現を持たないため manual attestation を要する。 M8-2
// 以降の hook 候補: projects.architecture_diagram_url / sboms.RawData の
// metadata.component 階層解析。
func EvaluateEnvSetup09(_ context.Context, _ Deps, _, _ uuid.UUID) (Result, error) {
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "M8-1 で追加: 対象ソフトウェアの構成図 (アプリ / コンテナ / OS / ファームウェア / サプライヤー提供コンポーネントのレイヤと境界) を可視化し、 SBOM 対象範囲を識別してください。 auto-signal pending、 manual assessment 推奨。",
	}, nil
}

// EvaluateEnvSetup10 — SBOM ツールを導入・設定 (個別運用) (4.4).
//
// M8-1 (issue #62) で追加。 auto-signal 未実装の stub。 ツール選定
// (EvaluateEnvSetup07) との重複を避け、 ここでは個別設定値 (scan_settings
// .enabled_scanners 詳細 / exclusion patterns / output spec_version 固定) の
// 妥当性を将来的に判定したい。 現状は sbomhub-cli の `doctor` 出力 / 個別
// scan_settings の整備状況を踏まえ manual attestation を要する。
func EvaluateEnvSetup10(_ context.Context, _ Deps, _, _ uuid.UUID) (Result, error) {
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "M8-1 で追加: ツール選定 (env_setup.07) 後、 対象スタック毎の個別設定 (スキャン対象 / 除外パターン / 出力形式 / lockfile 解決ポリシー 等) を最適化してください。 auto-signal pending、 manual assessment 推奨。",
	}, nil
}

// EvaluateEnvSetup11 — SBOM ツールの学習 (運用習熟度確認) (4.5).
//
// M8-1 (issue #62) で追加。 auto-signal 未実装の stub。 担当者教育
// (EvaluateEnvSetup08) との重複を避け、 ここでは「教育受講後に実機で動かしたか」
// のハンズオン実績 (sboms.created_by ユーザ多様性 / 直近 90 日の operator 数) を
// 将来的に判定したい。
func EvaluateEnvSetup11(_ context.Context, _ Deps, _, _ uuid.UUID) (Result, error) {
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "M8-1 で追加: 教育 (env_setup.08) 後に実機ハンズオンを実施し、 生成所要時間 / エラー復旧時間 / 解釈精度等の運用習熟度ベースラインを記録してください。 auto-signal pending、 manual assessment 推奨。",
	}, nil
}

// distinctPurlPrefixes returns the unique `pkg:<type>` prefixes
// observed across the supplied components. Components with no PURL,
// or PURLs that do not start with `pkg:`, are ignored. The slice is
// deduplicated and returned in stable (insertion-order) order so the
// evidence diff stays readable across re-evaluations.
//
// PURL grammar: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
// We only need the `pkg:<type>` prefix to identify the ecosystem.
func distinctPurlPrefixes(components []model.Component) []string {
	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)
	for _, c := range components {
		purl := strings.TrimSpace(c.Purl)
		if purl == "" || !strings.HasPrefix(purl, "pkg:") {
			continue
		}
		// "pkg:npm/foo@1.2.3" -> prefix "pkg:npm".
		rest := purl[len("pkg:"):]
		typeEnd := strings.IndexAny(rest, "/@?#")
		var prefix string
		if typeEnd < 0 {
			prefix = "pkg:" + rest
		} else {
			prefix = "pkg:" + rest[:typeEnd]
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out
}

package criteria

// sbom_operation.go — phase 3 (SBOM 運用・管理) evaluators (11 criteria).
//
// Mapping per catalog.yaml evaluator_hint (M3-3 / #39 + M8-1 / #62):
//
//   01 脆弱性監視プロセス      — auto: vulnerabilities matched for the
//                                project (any row implies a scan ran).
//   02 脆弱性情報源 (NVD/KEV/JVN) — auto: KEV sync settings have a fresh
//                                  last_sync_at (<= 48h). ※要確認: NVD /
//                                  JVN freshness checks are out of scope
//                                  for v1; absence of NVD sync row
//                                  resolves to needs_review.
//   03 優先付け (EPSS / KEV / SSVC) — auto: any vulnerability with
//                                     EPSSScore or InKEV populated.
//   04 VEX 作成・承認・配布     — auto: VEX drafts with decision in
//                                  ('approved','edited') >= 1.
//   05 ライセンス違反確認      — auto: license_policies configured for
//                                the project.
//   06 EOL / EoS 特定          — auto: EOL summary returns total > 0
//                                (EOL scan has produced results). Empty
//                                summary resolves to not_applicable
//                                because most projects without runtime
//                                dependencies legitimately have no EOL
//                                surface.
//   07 SBOM 保管               — auto: at least one tenant-scoped audit
//                                log entry, which implies retention /
//                                audit machinery is active.
//   08 インシデント対応プロセス — auto: cra_reports >= 1 (M2 product
//                                surface; any CRA report implies the
//                                customer-notification timeline is being
//                                tracked).
//   09 更新頻度遵守            — auto: latest sboms.created_at within 30 days.
//   10 監査ログ記録            — auto: tenant audit_logs total >= 1.
//   11 提供期間 個別運用 (6.3) — M8-1 で追加。 auto-signal 未実装の stub。
//                                保管 (07) との重複を避け、 顧客 / 製品ライン別
//                                の提供期間個別運用を将来判定。

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// freshnessWindowHours is the SLA for the vulnerability-source sync
// check (sbom_operation.02). Aligned with the catalog hint's "<48h"
// guidance. Stored as a duration constant so the per-criterion
// function reads naturally and the bar is easy to tweak in one place
// if the SLA changes.
const freshnessWindowHours = 48 * time.Hour

// updateCadenceDays mirrors the ver 2.0 30-day re-generation
// recommendation (sbom_operation.09 / sbom_creation.01).
const updateCadenceDays = 30

// EvaluateSBOMOperation01 — 脆弱性監視プロセスを確立.
//
// Auto: vulnerabilities exist for the project, which means
// NVD/JVN scanning has run at least once and matched something.
// We treat "list returns successfully with >= 0 rows AND >= 1 vuln"
// as the achievable bar; bare zero with non-empty SBOM resolves
// to needs_review (the scan may have run and matched nothing, or
// may never have run — the data alone cannot disambiguate).
// Achieved bar: >= 1 matched vulnerability.
func EvaluateSBOMOperation01(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	vulns, err := deps.ListVulnerabilitiesByProject(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if len(vulns) >= 1 {
		return Result{
			Status: StatusAchieved,
			Evidence: mustEvidence([]map[string]any{
				evidenceEntry("vulnerabilities_count", len(vulns)),
			}),
		}, nil
	}
	// Zero matched — could be "no vulns" or "scan never ran".
	// needs_review so the operator can attest the scan SLA.
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          mustEvidence([]map[string]any{evidenceEntry("vulnerabilities_count", 0)}),
		ImprovementAction: "脆弱性スキャンの実行頻度 / 担当 / SLA を確立し、 NVD / JVN マッチング結果をダッシュボードで確認してください。",
	}, nil
}

// EvaluateSBOMOperation02 — 脆弱性情報源 (NVD / JVN / KEV) を特定.
//
// Auto: the KEV sync settings row carries a last_sync_at within the
// freshness window. The catalog hint also names NVD / JVN sync
// timestamps, but the model surface for those is heterogeneous; we
// scope v1 to KEV (the canonical "we are tracking exploited CVEs"
// signal) and emit needs_review when the KEV row is absent or stale.
// ※要確認: extend to NVDSyncSettings / JVNSyncSettings once the
// repository surfaces those rows uniformly (out of M3-2 scope).
func EvaluateSBOMOperation02(ctx context.Context, deps Deps, _, _ uuid.UUID) (Result, error) {
	settings, err := deps.GetKEVSyncSettings(ctx)
	if err != nil {
		return Result{}, err
	}
	if settings == nil || settings.LastSyncAt == nil {
		return Result{
			Status:            StatusNeedsReview,
			Evidence:          emptyEvidence(),
			ImprovementAction: "KEV / NVD / JVN の同期頻度と重要度通知の閾値 (例: CVSS 7.0 以上) を定義してください。",
		}, nil
	}
	age := time.Since(*settings.LastSyncAt)
	ev := mustEvidence([]map[string]any{
		evidenceEntry("kev_last_sync_at", settings.LastSyncAt.UTC().Format(time.RFC3339)),
		evidenceEntry("kev_age_hours", int(age.Hours())),
		evidenceEntry("kev_total_entries", settings.TotalEntries),
	})
	if age <= freshnessWindowHours {
		return Result{Status: StatusAchieved, Evidence: ev}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          ev,
		ImprovementAction: "KEV 同期が 48h 以上更新されていません。 同期 job / cron を確認してください。",
	}, nil
}

// EvaluateSBOMOperation03 — 脆弱性優先付け (EPSS / KEV / SSVC / CVSS).
//
// Auto: at least one vulnerability for the project carries an EPSS
// score or is flagged InKEV. SSVC decisions live in a separate
// repository (apps/api/internal/repository/ssvc.go) — not consulted
// here to keep Deps minimal; EPSS + KEV alone is a strong enough
// proxy for "operator is using something beyond bare CVSS".
func EvaluateSBOMOperation03(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	vulns, err := deps.ListVulnerabilitiesByProject(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	epssCount, kevCount := 0, 0
	for _, v := range vulns {
		if v.EPSSScore != nil {
			epssCount++
		}
		if v.InKEV {
			kevCount++
		}
	}
	ev := mustEvidence([]map[string]any{
		evidenceEntry("vulnerabilities_count", len(vulns)),
		evidenceEntry("epss_populated_count", epssCount),
		evidenceEntry("kev_listed_count", kevCount),
	})
	if epssCount >= 1 || kevCount >= 1 {
		return Result{Status: StatusAchieved, Evidence: ev}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          ev,
		ImprovementAction: "EPSS / KEV / SSVC のいずれかで優先順位付けを行ってください (CVSS 単独は推奨されません)。",
	}, nil
}

// EvaluateSBOMOperation04 — VEX 作成・承認・配布.
//
// Auto: vex_drafts.decision in ('approved','edited') for at least
// one row implies a human approved or edited an AI draft, which is
// the M1 "no AI output without human approval" contract. Zero
// approved -> needs_review when drafts exist (pending review) or
// not_achieved when zero drafts altogether.
func EvaluateSBOMOperation04(ctx context.Context, deps Deps, tenantID, projectID uuid.UUID) (Result, error) {
	drafts, err := deps.ListVEXDraftsByProject(ctx, tenantID, projectID)
	if err != nil {
		return Result{}, err
	}
	if len(drafts) == 0 {
		return Result{
			Status:            StatusNotAchieved,
			Evidence:          emptyEvidence(),
			ImprovementAction: "未対応 / 影響なし / 修正済の判断を VEX (CycloneDX VEX or CSAF) で表現し、 人による承認後に顧客へ配布してください。",
		}, nil
	}
	approved := 0
	for _, d := range drafts {
		switch d.Decision {
		case "approved", "edited":
			approved++
		}
	}
	ev := mustEvidence([]map[string]any{
		evidenceEntry("vex_drafts_count", len(drafts)),
		evidenceEntry("vex_drafts_approved_or_edited", approved),
	})
	if approved >= 1 {
		return Result{Status: StatusAchieved, Evidence: ev}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          ev,
		ImprovementAction: "VEX ドラフトはありますが承認待ちです。 レビュー / 編集 / 承認のフローを完了させてください。",
	}, nil
}

// EvaluateSBOMOperation05 — ライセンス違反 / コンプライアンス逸脱を確認.
//
// Auto: at least one license policy configured for the project. The
// policy presence is the operator's declared intent; a runtime
// violation check is the responsibility of the compliance service
// (out of M3-2 scope — needs_review is the worst case here).
func EvaluateSBOMOperation05(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	policies, err := deps.ListLicensePoliciesByProject(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if len(policies) >= 1 {
		return Result{
			Status: StatusAchieved,
			Evidence: mustEvidence([]map[string]any{
				evidenceEntry("license_policies_count", len(policies)),
			}),
		}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "禁止 / 要承認ライセンスを定義したライセンスポリシーを設定し、 SBOM 内コンポーネントと突合してください。",
	}, nil
}

// EvaluateSBOMOperation06 — EOL / End-of-Support コンポーネントを特定.
//
// Auto: GetEOLSummary returns total > 0 (EOL analysis ran and
// produced output). When the summary is empty / nil we treat that
// as not_applicable: the operator has not enabled EOL scanning OR
// the project has no runtime dependencies in scope of endoflife.date.
// Either way it is not a failure of the M3 evaluator; the operator
// can override to achieved via the M3-4 handler if EOL is genuinely
// out of scope, or enable EOL scanning to flip the auto-signal.
func EvaluateSBOMOperation06(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	summary, err := deps.GetEOLSummary(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if summary == nil || summary.TotalComponents == 0 {
		return Result{
			Status:            StatusNotApplicable,
			Evidence:          emptyEvidence(),
			ImprovementAction: "EOL 解析がまだ実行されていません。 endoflife.date 連携を有効化するか、 ランタイム依存が無いことを確認してください。",
		}, nil
	}
	return Result{
		Status: StatusAchieved,
		Evidence: mustEvidence([]map[string]any{
			evidenceEntry("eol_total_components", summary.TotalComponents),
			evidenceEntry("eol_eol_count", summary.EOL),
			evidenceEntry("eol_eos_count", summary.EOS),
			evidenceEntry("eol_active_count", summary.Active),
		}),
	}, nil
}

// EvaluateSBOMOperation07 — SBOM を適切な期間 保管.
//
// Auto: at least one audit_log row for the tenant. The catalog hint
// asks for "retention policy enforced — no rows hard-deleted in
// window"; the simpler bar in v1 is "audit machinery exists at all".
// Improving to a true retention check requires diffing
// audit_logs.delete events against a configured retention window —
// out of M3-2 scope; needs_review remains the fallback.
func EvaluateSBOMOperation07(ctx context.Context, deps Deps, tenantID, _ uuid.UUID) (Result, error) {
	n, err := deps.CountAuditLogsForTenant(ctx, tenantID)
	if err != nil {
		return Result{}, err
	}
	ev := mustEvidence([]map[string]any{
		evidenceEntry("audit_logs_count", n),
	})
	if n >= 1 {
		return Result{Status: StatusAchieved, Evidence: ev}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          ev,
		ImprovementAction: "SBOM の保管期間 (製品サポート期間 + 規制要求期間) と完全性確認 (hash / timestamp) を運用ルール化してください。",
	}, nil
}

// EvaluateSBOMOperation08 — インシデント対応プロセス (悪用検知時) を整備.
//
// Auto: cra_reports >= 1 (M2 product surface; the report types
// 'early_warning' / 'detailed_notification' / 'final_report' map
// directly to the EU CRA Article 14 timeline this criterion asks for).
func EvaluateSBOMOperation08(ctx context.Context, deps Deps, tenantID, projectID uuid.UUID) (Result, error) {
	reports, err := deps.ListCRAReportsByProject(ctx, tenantID, projectID)
	if err != nil {
		return Result{}, err
	}
	if len(reports) >= 1 {
		// Count by report_type so the evidence enumerates which
		// timeline stages have been entered.
		typeCounts := map[string]int{}
		for _, r := range reports {
			typeCounts[r.ReportType]++
		}
		entries := []map[string]any{
			evidenceEntry("cra_reports_count", len(reports)),
		}
		for k, v := range typeCounts {
			entries = append(entries, map[string]any{"kind": "cra_report_type", "report_type": k, "count": v})
		}
		return Result{Status: StatusAchieved, Evidence: mustEvidence(entries)}, nil
	}
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "KEV 追加 / EPSS 急上昇 / 悪用例レポートに対する 24h / 72h / 最終報告のタイムラインを EU CRA Art.14 と整合させて定義してください。",
	}, nil
}

// EvaluateSBOMOperation09 — SBOM 更新頻度を遵守.
//
// Auto: latest SBOM created within 30 days. The hint pins the 30-day
// cadence as a ver 2.0 recommendation; updateCadenceDays makes the
// number easy to find.
func EvaluateSBOMOperation09(ctx context.Context, deps Deps, _, projectID uuid.UUID) (Result, error) {
	sbom, err := deps.GetLatestSbom(ctx, projectID)
	if err != nil {
		return Result{}, err
	}
	if sbom == nil {
		return Result{
			Status:            StatusNotAchieved,
			Evidence:          emptyEvidence(),
			ImprovementAction: "SBOM がアップロードされていません。 ソフトウェア改変・依存追加・依存削除のたびに SBOM を更新してください。",
		}, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -updateCadenceDays)
	ev := mustEvidence([]map[string]any{
		evidenceEntry("latest_uploaded_at", sbom.CreatedAt.UTC().Format(time.RFC3339)),
		evidenceEntry("cutoff_days", updateCadenceDays),
	})
	if sbom.CreatedAt.After(cutoff) {
		return Result{Status: StatusAchieved, Evidence: ev}, nil
	}
	return Result{
		Status:            StatusNotAchieved,
		Evidence:          ev,
		ImprovementAction: "最新 SBOM が 30 日以上前です。 SBOM 再生成を運用ルールとして固定してください (ver 2.0 推奨)。",
	}, nil
}

// EvaluateSBOMOperation10 — 監査ログを記録.
//
// Auto: at least one tenant-scoped audit_logs row. SBOMHub writes
// audit entries for every SBOM upload / VEX decision / CRA decision
// so the bar is almost always met for an active tenant; an empty
// table is the strong negative signal.
func EvaluateSBOMOperation10(ctx context.Context, deps Deps, tenantID, _ uuid.UUID) (Result, error) {
	n, err := deps.CountAuditLogsForTenant(ctx, tenantID)
	if err != nil {
		return Result{}, err
	}
	ev := mustEvidence([]map[string]any{
		evidenceEntry("audit_logs_count", n),
	})
	if n >= 1 {
		return Result{Status: StatusAchieved, Evidence: ev}, nil
	}
	return Result{
		Status:            StatusNotAchieved,
		Evidence:          ev,
		ImprovementAction: "監査ログがゼロです。 SBOM 生成 / 共有 / 承認 / 配布の各イベントが audit_logs に記録されるか確認してください。",
	}, nil
}

// EvaluateSBOMOperation11 — SBOM 提供期間を個別運用 (顧客 / 製品ライン別) (6.3).
//
// M8-1 (issue #62) で追加。 auto-signal 未実装の stub。 保管
// (EvaluateSBOMOperation07) との重複を避け、 ここでは「顧客 / 製品ライン
// 毎の提供期間が個別運用されているか」 (project metadata の retention_window /
// customer_id 紐付け / provision_end_at 配列) を将来的に判定したい。 M8-2
// 以降の hook 候補: project_customer_provision_windows テーブル、
// sboms.retention_end_at 個別列。
func EvaluateSBOMOperation11(_ context.Context, _ Deps, _, _ uuid.UUID) (Result, error) {
	return Result{
		Status:            StatusNeedsReview,
		Evidence:          emptyEvidence(),
		ImprovementAction: "M8-1 で追加: 保管枠組み (sbom_operation.07) を前提に、 顧客 / 製品ライン / 出荷地域 / 契約タイプ毎に SBOM 提供期間 (開始 / 終了 / 延長条件 / 再提供 SLA) を個別運用してください。 auto-signal pending、 manual assessment 推奨。",
	}, nil
}

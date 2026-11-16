// The compliance overview (GET /api/v1/projects/:id/compliance) is answered
// in Japanese only: `label` and `details` are Japanese strings
// (apps/api/internal/service/compliance.go). /en showed them verbatim. The
// category `name` and check `id` are stable, so their labels are translated
// by key; `details` is free text with numbers in it, so the known sentences
// are recognised here and re-worded through next-intl. Anything not
// recognised (a newer API) is shown as the API sent it.

export const COMPLIANCE_CATEGORIES = [
  "sbom_generation",
  "vulnerability_management",
  "license_management",
  "minimum_elements",
] as const;

export const COMPLIANCE_CHECKS = [
  "sbom_exists",
  "required_fields",
  "recently_updated",
  "scan_performed",
  "no_unresolved_critical",
  "vex_in_use",
  "policy_configured",
  "no_violations",
  "supplier_name",
  "component_name",
  "component_version",
  "unique_identifier",
  "dependency_relationship",
  "sbom_author",
  "timestamp",
] as const;

/** Message key under `Compliance` for a category name, or null if unknown. */
export function categoryLabelKey(name: string): string | null {
  return (COMPLIANCE_CATEGORIES as readonly string[]).includes(name) ? `category.${name}` : null;
}

/** Message key under `Compliance` for a check id, or null if unknown. */
export function checkLabelKey(id: string): string | null {
  return (COMPLIANCE_CHECKS as readonly string[]).includes(id) ? `check.${id}` : null;
}

export interface DetailMessage {
  key: string;
  values: Record<string, string>;
}

// Each Japanese sentence compliance.go writes, as a pattern.
const DETAIL_PATTERNS: Array<{ re: RegExp; key: string; names: string[] }> = [
  { re: /^SBOMがアップロードされていません$/, key: "detail.noSbomUploaded", names: [] },
  { re: /^一部のコンポーネントに名前またはバージョンがありません$/, key: "detail.missingNameOrVersion", names: [] },
  { re: /^SBOMが存在しないため確認できません$/, key: "detail.noSbomCannotCheck", names: [] },
  { re: /^最終更新: (\S+)$/, key: "detail.lastUpdated", names: ["date"] },
  { re: /^(\d+)件のCritical脆弱性が未対応$/, key: "detail.unresolvedCritical", names: ["count"] },
  { re: /^VEXステートメントが登録されていません$/, key: "detail.noVex", names: [] },
  { re: /^ライセンスポリシーが設定されていません$/, key: "detail.noLicensePolicy", names: [] },
  { re: /^(\d+)件のライセンス違反があります$/, key: "detail.licenseViolations", names: ["count"] },
  { re: /^コンポーネントが存在しません$/, key: "detail.noComponents", names: [] },
  {
    re: /^(\d+)\/(\d+) コンポーネント \((\d+)%\) にサプライヤー情報があります$/,
    key: "detail.withSupplier",
    names: ["n", "total", "pct"],
  },
  { re: /^(\d+)\/(\d+) コンポーネント \((\d+)%\) に名前があります$/, key: "detail.withName", names: ["n", "total", "pct"] },
  {
    re: /^(\d+)\/(\d+) コンポーネント \((\d+)%\) にバージョンがあります$/,
    key: "detail.withVersion",
    names: ["n", "total", "pct"],
  },
  { re: /^(\d+)\/(\d+) コンポーネント \((\d+)%\) にPURLがあります$/, key: "detail.withPurl", names: ["n", "total", "pct"] },
  { re: /^SBOMに依存関係情報が含まれていません$/, key: "detail.noDependencies", names: [] },
  { re: /^SBOMに作成者情報が含まれていません$/, key: "detail.noAuthor", names: [] },
  { re: /^SBOMにタイムスタンプが含まれていません$/, key: "detail.noTimestamp", names: [] },
];

/** The message for a known `details` sentence, or null (show it as sent). */
export function detailMessage(details: string): DetailMessage | null {
  for (const p of DETAIL_PATTERNS) {
    const m = p.re.exec(details);
    if (!m) continue;
    const values: Record<string, string> = {};
    p.names.forEach((n, i) => (values[n] = m[i + 1]));
    return { key: p.key, values };
  }
  return null;
}

/** `label_ja` for Japanese, `label` otherwise (checklist / visualization options). */
export function localizedLabel(item: { label: string; label_ja: string }, locale: string): string {
  return locale === "ja" ? item.label_ja || item.label : item.label || item.label_ja;
}

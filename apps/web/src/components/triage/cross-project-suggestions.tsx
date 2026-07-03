"use client";

/**
 * CrossProjectSuggestions — read-only "already decided in other projects"
 * section for the triage page (M26 F376, issue #131).
 *
 * Renders human-approved VEX statements from OTHER projects in the same
 * tenant that match this project's vulnerabilities, so a reviewer can reuse
 * an existing organisational decision instead of re-triaging the same
 * finding. Each row surfaces:
 *   - the source project name (provenance the reviewer trusts on),
 *   - the VEX status (same badge palette as the confirmed-VEX list),
 *   - the match precision (component purl match vs coarse CVE-only match),
 *   - the justification / impact / action statements.
 *
 * READ-ONLY Phase 1: there is INTENTIONALLY no apply/reuse control here.
 * 1-click reuse (copy the source statement into this project + audit action)
 * ships in M27 Phase 2 — see sbomhub-internal/planning/M26_KICKOFF_PROMPT.md
 * ("apply (1-click reuse): provenance table + audit action = Phase 2").
 * Adding a button here now would touch the F281/F271 audit-action parity
 * surface the kickoff deliberately deferred, so this component only reads.
 *
 * Wire shape: VEXSuggestion from @/lib/api, pinned to the M26 API contract
 * shared with the Wave A backend.
 */

import { useTranslations } from "next-intl";
import { Building2, GitCompareArrows, Package } from "lucide-react";

import { VEXStatus, VEXSuggestion } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Badge variant per VEX status — mirrors getVexStatusVariant in
 * projects/[id]/page.tsx so a suggestion reads the same colour as the same
 * status in this project's confirmed-VEX list.
 */
function statusVariant(
  status: VEXStatus,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "not_affected":
      return "secondary";
    case "affected":
      return "destructive";
    case "fixed":
      return "default";
    case "under_investigation":
      return "outline";
    default:
      return "outline";
  }
}

export interface CrossProjectSuggestionsProps {
  suggestions: VEXSuggestion[];
}

export function CrossProjectSuggestions({
  suggestions,
}: CrossProjectSuggestionsProps) {
  const t = useTranslations("Triage.CrossProject");
  const tStatus = useTranslations("Triage.VexStatus");

  // Empty → render nothing. On the common path no other project has triaged
  // the same finding, so an always-present "no cross-project decisions" panel
  // would be visual noise above the pending-drafts queue.
  if (!suggestions || suggestions.length === 0) {
    return null;
  }

  return (
    <Card className="mb-6" data-testid="cross-project-suggestions">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <GitCompareArrows className="h-5 w-5" />
          {t("title")} ({suggestions.length})
        </CardTitle>
        <p className="text-sm text-muted-foreground">{t("description")}</p>
      </CardHeader>
      <CardContent className="space-y-3">
        {suggestions.map((s) => (
          <div
            key={`${s.source.statement_id}-${s.vulnerability_id}`}
            data-testid="cross-project-suggestion-card"
            data-cve-id={s.cve_id}
            data-match-type={s.match_type}
            className="rounded-lg border p-3"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-bold">{s.cve_id}</span>
              <Badge variant={statusVariant(s.source.status)}>
                {tStatus(s.source.status)}
              </Badge>
              <Badge
                variant="outline"
                className="font-normal"
                title={
                  s.match_type === "purl"
                    ? t("matchPurlHint")
                    : t("matchVulnerabilityOnlyHint")
                }
              >
                {s.match_type === "purl"
                  ? t("matchPurl")
                  : t("matchVulnerabilityOnly")}
              </Badge>
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1">
                <Building2 className="h-3.5 w-3.5" />
                {t("sourceProject")}:{" "}
                <span className="font-medium text-foreground">
                  {s.source.project_name}
                </span>
              </span>
              <span className="inline-flex items-center gap-1">
                <Package className="h-3.5 w-3.5" />
                <code className="font-mono">
                  {s.component.name} {s.component.version}
                </code>
              </span>
            </div>

            {s.source.justification && (
              <p className="mt-2 text-sm">
                <span className="font-semibold">
                  {t("justificationLabel")}:
                </span>{" "}
                {s.source.justification.replace(/_/g, " ")}
              </p>
            )}
            {s.source.impact_statement && (
              <p className="mt-1 text-sm text-muted-foreground">
                <span className="font-semibold">{t("impactLabel")}:</span>{" "}
                {s.source.impact_statement}
              </p>
            )}
            {s.source.action_statement && (
              <p className="mt-1 text-sm text-muted-foreground">
                <span className="font-semibold">{t("actionLabel")}:</span>{" "}
                {s.source.action_statement}
              </p>
            )}
          </div>
        ))}

        {/* Read-only Phase 1 — no apply/reuse control (M27 Phase 2, see file header). */}
        <p className="pt-1 text-xs text-muted-foreground">{t("readOnlyNote")}</p>
      </CardContent>
    </Card>
  );
}

export default CrossProjectSuggestions;

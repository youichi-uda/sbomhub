"use client";

/**
 * CrossProjectSuggestions — "already decided in other projects" section for
 * the triage page (M26 F376, issue #131; M27 F382 apply, issue #133).
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
 * M27 Phase 2 (F382): each row now carries a Reuse control that copies the
 * source decision into THIS project. Per the product's "AI drafts, humans
 * approve" rule there is NO auto-apply — the Reuse button opens an
 * AlertDialog confirm (the apikeys destructive-confirm pattern), and the
 * apply request only fires when the reviewer confirms. On success the parent
 * refetches (onApplied); the reused suggestion drops out of the list because
 * the backend now excludes it as already-triaged. A 409 (this project already
 * triaged the finding) is surfaced inline as a natural "already triaged here"
 * notice rather than an error.
 *
 * Wire shape: VEXSuggestion / VEXApplyRequest from @/lib/api, pinned to the
 * M26 + M27 API contracts shared with the Wave A backend.
 */

import { useCallback, useState } from "react";
import { useTranslations } from "next-intl";
import { Building2, Check, GitCompareArrows, Loader2, Package } from "lucide-react";

import { APIError, VEXStatus, VEXSuggestion, api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

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
  /** This project's id — the target the reused decision is copied onto. */
  projectId: string;
  /**
   * Called after a successful reuse so the parent refetches. The reused
   * suggestion then drops out of the list (backend excludes it as
   * already-triaged).
   */
  onApplied: () => void;
}

/**
 * Stable per-row key — mirrors the React key below and the F377 fan-out
 * disambiguation: {statement_id, vulnerability_id} alone is not unique because
 * a vulnerability_only source fans out across every target component, so the
 * target component_id is part of the key. Used to scope apply loading /
 * inline-notice state to the exact row the reviewer acted on.
 */
function suggestionKey(s: VEXSuggestion): string {
  return `${s.source.statement_id}-${s.vulnerability_id}-${s.component.component_id}`;
}

/** Inline per-row feedback after a reuse attempt (409 notice vs hard error). */
interface RowNotice {
  kind: "notice" | "error";
  text: string;
}

export function CrossProjectSuggestions({
  suggestions,
  projectId,
  onApplied,
}: CrossProjectSuggestionsProps) {
  const t = useTranslations("Triage.CrossProject");
  const tStatus = useTranslations("Triage.VexStatus");

  // Which row is mid-apply (disables its button + shows a spinner) and any
  // inline notice per row. Both are keyed by suggestionKey so concurrent rows
  // never bleed each other's state.
  const [applyingKey, setApplyingKey] = useState<string | null>(null);
  const [notices, setNotices] = useState<Record<string, RowNotice>>({});

  const handleApply = useCallback(
    async (s: VEXSuggestion) => {
      const key = suggestionKey(s);
      setApplyingKey(key);
      // Clear any stale notice from a previous attempt on this row.
      setNotices((prev) => {
        if (!(key in prev)) return prev;
        const next = { ...prev };
        delete next[key];
        return next;
      });
      try {
        await api.vex.apply(projectId, {
          source_statement_id: s.source.statement_id,
          vulnerability_id: s.vulnerability_id,
          component_id: s.component.component_id,
        });
        // Success — refetch. The reused row disappears (already-triaged
        // exclusion), so no row-level success state is needed.
        onApplied();
      } catch (err) {
        // 409 = this project already triaged the finding. This is an expected
        // outcome (a race with another reviewer, or a stale suggestion), not a
        // failure — surface it as a natural "already triaged here" notice.
        if (err instanceof APIError && err.status === 409) {
          setNotices((prev) => ({
            ...prev,
            [key]: { kind: "notice", text: t("alreadyTriaged") },
          }));
        } else {
          setNotices((prev) => ({
            ...prev,
            [key]: { kind: "error", text: t("applyError") },
          }));
        }
      } finally {
        setApplyingKey(null);
      }
    },
    [projectId, onApplied, t],
  );

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
        {suggestions.map((s) => {
          // F377 (issue #131): key on the target component_id too. A single
          // vulnerability_only source statement fans out across every target
          // component the vulnerability touches, and two target rows may
          // share the same (name, version, purl), so {statement_id,
          // vulnerability_id} alone is not unique and produced duplicate React
          // keys. component_id disambiguates each fanned-out row. (Collapsing
          // the fan-out itself is deferred to M27 Phase 2 grouping.)
          const key = suggestionKey(s);
          const applying = applyingKey === key;
          const notice = notices[key];
          return (
          <div
            key={key}
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

            {/*
              M27 F382 reuse control. "Humans approve": the button only OPENS
              a confirm dialog; the apply request fires from AlertDialogAction,
              never on the single click. Loading state is scoped to this row.
            */}
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={applying}
                    data-testid="cross-project-apply-button"
                  >
                    {applying ? (
                      <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Check className="mr-1 h-3.5 w-3.5" />
                    )}
                    {applying ? t("applying") : t("applyButton")}
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>{t("applyConfirmTitle")}</AlertDialogTitle>
                    <AlertDialogDescription>
                      {t("applyConfirmBody", {
                        project: s.source.project_name,
                        status: tStatus(s.source.status),
                      })}
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>
                      {t("applyConfirmCancel")}
                    </AlertDialogCancel>
                    <AlertDialogAction onClick={() => handleApply(s)}>
                      {t("applyConfirmAction")}
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>

              {notice && (
                <span
                  data-testid="cross-project-apply-notice"
                  className={
                    notice.kind === "error"
                      ? "text-xs text-destructive"
                      : "text-xs text-muted-foreground"
                  }
                >
                  {notice.text}
                </span>
              )}
            </div>
          </div>
          );
        })}

        {/* Reuse copies the source decision here after an explicit confirm (M27 F382). */}
        <p className="pt-1 text-xs text-muted-foreground">{t("reuseNote")}</p>
      </CardContent>
    </Card>
  );
}

export default CrossProjectSuggestions;

"use client";

/**
 * AI Summary panel for the SBOM diff detail page — M11-4 (#79).
 *
 * Renders the structured envelope returned by
 * `api.projects.getDiffSummary` with the audit-required Confidence /
 * Evidence / Approve display pattern from
 * sbomhub/CLAUDE.md (AI policy):
 *
 *   "AI-drafted artefacts always render confidence + evidence +
 *    Approve / Edit / Reject controls."
 *
 * The Approve / Edit / Reject buttons are intentionally cosmetic
 * client-side in M11-4 — they record the operator decision locally so
 * the audit reviewer can confirm "a human looked at this" while the
 * persistence layer (a diff_summaries table + decision endpoint) is
 * deferred to M12. The backend already writes the AI-generated audit
 * row at summary-creation time, so the chain is:
 *
 *   diff_summary_ai_generated (always)
 *     → human reviews here
 *     → (M12) diff_summary_decided when persistence lands
 *
 * This is the same staged-decision pattern VEX triage shipped in M1.
 */

import { useState, useCallback } from "react";
import { useTranslations } from "next-intl";
import {
  Sparkles,
  ShieldCheck,
  Pencil,
  XCircle,
  AlertTriangle,
  Loader2,
} from "lucide-react";

import { api, ProjectDiffSummaryResponse, APIError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface AiSummaryPanelProps {
  projectId: string;
  from?: string;
  to?: string;
  lang: string;
}

type Decision = "pending" | "approved" | "edited" | "rejected";

export function AiSummaryPanel({
  projectId,
  from,
  to,
  lang,
}: AiSummaryPanelProps) {
  const t = useTranslations("SbomDiff.AiSummary");

  const [summary, setSummary] = useState<ProjectDiffSummaryResponse | null>(
    null,
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [decision, setDecision] = useState<Decision>("pending");

  const handleGenerate = useCallback(async () => {
    setLoading(true);
    setError(null);
    setDecision("pending");
    try {
      const res = await api.projects.getDiffSummary(projectId, {
        from,
        to,
        lang,
      });
      setSummary(res);
    } catch (err) {
      if (err instanceof APIError && err.status === 503) {
        // Service-level disabled (handler/no-wiring). Render the
        // same banner as the in-band ai_disabled path so the UI
        // doesn't have two error shapes for the same condition.
        setSummary({
          project_id: projectId,
          from: null,
          to: null,
          summary: t("disabledBanner"),
          highlights: [],
          confidence: 0,
          evidence: [],
          provider: "disabled",
          model: "",
          lang,
          generated_at: new Date().toISOString(),
          ai_disabled: true,
        });
      } else {
        setError(
          err instanceof Error ? err.message : t("generateFailed"),
        );
      }
    } finally {
      setLoading(false);
    }
  }, [projectId, from, to, lang, t]);

  const confidencePct = Math.round((summary?.confidence ?? 0) * 100);
  const confidenceVariant: "default" | "destructive" | "outline" | "secondary" =
    confidencePct >= 75
      ? "default"
      : confidencePct >= 50
        ? "secondary"
        : "outline";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-blue-500" />
          {t("title")}
        </CardTitle>
        <p className="text-xs text-muted-foreground mt-1">
          {t("description")}
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {summary === null && !error && (
          <div className="flex flex-col items-start gap-2">
            <p className="text-sm text-muted-foreground">{t("idleHint")}</p>
            <Button onClick={handleGenerate} disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  {t("generating")}
                </>
              ) : (
                <>
                  <Sparkles className="h-4 w-4 mr-2" />
                  {t("generate")}
                </>
              )}
            </Button>
          </div>
        )}

        {error && (
          <div className="rounded-md border border-red-200 bg-red-50/60 p-3 flex items-start gap-2">
            <AlertTriangle className="h-4 w-4 text-red-600 mt-0.5" />
            <div className="text-sm text-red-700">{error}</div>
          </div>
        )}

        {summary && (
          <>
            {summary.ai_disabled && (
              <div className="rounded-md border border-amber-200 bg-amber-50/60 p-3 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
                <div className="text-sm text-amber-800">
                  {t("disabledBanner")}
                </div>
              </div>
            )}

            <div>
              <p className="text-sm whitespace-pre-wrap leading-relaxed">
                {summary.summary}
              </p>
            </div>

            {summary.highlights.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
                  {t("highlights")}
                </h4>
                <ul className="list-disc pl-5 space-y-1 text-sm">
                  {summary.highlights.map((h, i) => (
                    <li key={i}>{h}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div>
                <p className="text-muted-foreground">{t("confidence")}</p>
                <Badge variant={confidenceVariant}>
                  {confidencePct}%
                </Badge>
              </div>
              <div>
                <p className="text-muted-foreground">{t("provider")}</p>
                <p className="font-mono">
                  {summary.provider}
                  {summary.model ? ` / ${summary.model}` : ""}
                </p>
              </div>
              <div>
                <p className="text-muted-foreground">{t("generatedAt")}</p>
                <p className="font-mono">
                  {new Date(summary.generated_at).toLocaleString()}
                </p>
              </div>
            </div>

            {summary.evidence.length > 0 && (
              <details className="text-xs">
                <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
                  {t("evidenceToggle", { count: summary.evidence.length })}
                </summary>
                <ul className="mt-2 list-disc pl-5 space-y-0.5">
                  {summary.evidence.slice(0, 50).map((e, i) => (
                    <li key={i} className="font-mono">
                      <span className="text-muted-foreground">[{e.kind}]</span>{" "}
                      {e.ref}
                    </li>
                  ))}
                </ul>
              </details>
            )}

            <div className="flex flex-wrap items-center gap-2 pt-2 border-t">
              <span className="text-xs text-muted-foreground mr-2">
                {t("decisionPrompt")}
              </span>
              <Button
                variant={decision === "approved" ? "default" : "outline"}
                size="sm"
                onClick={() => setDecision("approved")}
                disabled={summary.ai_disabled}
              >
                <ShieldCheck className="h-3 w-3 mr-1" />
                {t("approve")}
              </Button>
              <Button
                variant={decision === "edited" ? "default" : "outline"}
                size="sm"
                onClick={() => setDecision("edited")}
                disabled={summary.ai_disabled}
              >
                <Pencil className="h-3 w-3 mr-1" />
                {t("edit")}
              </Button>
              <Button
                variant={decision === "rejected" ? "destructive" : "outline"}
                size="sm"
                onClick={() => setDecision("rejected")}
              >
                <XCircle className="h-3 w-3 mr-1" />
                {t("reject")}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleGenerate}
                disabled={loading}
              >
                {loading ? (
                  <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                ) : (
                  <Sparkles className="h-3 w-3 mr-1" />
                )}
                {t("regenerate")}
              </Button>
              {decision !== "pending" && (
                <span className="text-xs text-muted-foreground ml-2">
                  {t("decisionLocal", { decision })}
                </span>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

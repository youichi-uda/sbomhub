"use client";

/**
 * SubmissionTimeline — the append-only ledger of authority submissions for
 * one approved CRA report (M33 Wave C, F420).
 *
 * CRA Art.14 requires a 24h early-warning / 72h detailed / final submission
 * timeline, so a single incident produces multiple rows (early-warning →
 * detailed → final + corrections). The backend has no uniqueness constraint
 * on cra_submissions by design; this component renders each recorded
 * submission newest-first (authority / submitted_at / reference_number /
 * notes) and shows an explicit empty state when nothing has been recorded
 * yet.
 *
 * Wire shape: repository.CRASubmission (snake_case json tags). See
 * apps/web/src/lib/api.ts CRASubmission and the frozen contract in
 * sbomhub-internal/planning/M33_KICKOFF_PROMPT.md.
 */

import { useLocale, useTranslations } from "next-intl";
import { Clock } from "lucide-react";

import { CRASubmission } from "@/lib/api";
import { Badge } from "@/components/ui/badge";

export interface SubmissionTimelineProps {
  submissions: CRASubmission[];
}

/**
 * Format an RFC3339 timestamp for display. Falls back to the raw string if
 * the value is unparseable so a malformed backend value stays inspectable
 * instead of rendering "Invalid Date".
 */
function formatSubmittedAt(value: string, locale: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function SubmissionTimeline({ submissions }: SubmissionTimelineProps) {
  const t = useTranslations("CRAReports.ReportCard");
  const locale = useLocale();

  // Defensive: the API returns submitted_at DESC, and optimistic inserts
  // prepend, but re-sort so a mixed source can never render out of order.
  const rows = [...submissions].sort((a, b) => {
    const ta = new Date(a.submitted_at).getTime();
    const tb = new Date(b.submitted_at).getTime();
    if (Number.isNaN(ta) || Number.isNaN(tb)) return 0;
    return tb - ta;
  });

  return (
    <section className="border-t pt-4" data-testid="cra-submission-timeline">
      <h4 className="mb-2 flex items-center gap-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        <Clock className="h-3.5 w-3.5" />
        {t("timelineTitle")} ({rows.length})
      </h4>

      {rows.length === 0 ? (
        <p
          className="text-xs text-muted-foreground"
          data-testid="cra-submission-timeline-empty"
        >
          {t("timelineEmpty")}
        </p>
      ) : (
        <ol className="space-y-2" data-testid="cra-submission-timeline-list">
          {rows.map((s) => (
            <li
              key={s.id}
              className="rounded border bg-muted/40 p-2 text-xs"
              data-testid="cra-submission-row"
            >
              <div className="mb-1 flex flex-wrap items-center gap-2">
                <Badge variant="secondary" className="text-[10px]">
                  {t("authorityLabel")}
                </Badge>
                <span className="font-semibold text-foreground">
                  {s.authority}
                </span>
                <span className="text-muted-foreground">
                  {formatSubmittedAt(s.submitted_at, locale)}
                </span>
              </div>
              {s.reference_number ? (
                <p className="text-muted-foreground">
                  <span className="font-semibold">
                    {t("referenceNumberLabel")}:{" "}
                  </span>
                  <code className="font-mono text-blue-700">
                    {s.reference_number}
                  </code>
                </p>
              ) : null}
              {s.notes ? (
                <p className="mt-1 italic text-muted-foreground">{s.notes}</p>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

export default SubmissionTimeline;

"use client";

/**
 * ReportCard — one AI-drafted CRA report awaiting human decision.
 *
 * Renders the regulatory milestone (report_type) / language / state /
 * decision badges, the rendered draft_text body, the evidence list
 * (with a deep link back into the source VEX draft via /triage when
 * source_vex_draft_id is set), and the four decision controls
 * (Approve / Edit / Reject / Re-analyse) plus a deliberately-disabled
 * [Submit to authority] placeholder that hooks into M3.
 *
 * Backend wire shape: repository.CRAReport — snake_case json tags
 * declared at the struct level (see apps/api/internal/repository/
 * cra_reports.go header comment), in contrast to repository.VEXDraft
 * which uses Go-default PascalCase. The DraftCard / ReportCard split
 * mirrors the wire-shape split; do not unify them without first
 * collapsing the wire shapes.
 *
 * Issue: #32 (M2 Wave M2-5). PRODUCT_REBOOT_PLAN.md §7.2.
 */

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import Link from "next/link";
import { useLocale, useTranslations } from "next-intl";
import {
  CheckCircle2,
  Edit3,
  XCircle,
  RefreshCw,
  FileText,
  Bot,
  Send,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
} from "lucide-react";

import {
  CRAReport,
  CRAReportDecision,
  CRAReportEvidence,
  CRAReportState,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";

const DRAFT_TRUNCATE_LENGTH = 800;

const editSchema = z.object({
  draft_text: z.string().min(1, "draft_text is required").max(50000),
  decision_note: z.string().max(2000),
});

export type ReportEditFormValues = z.infer<typeof editSchema>;

export interface ReportCardProps {
  report: CRAReport;
  projectId: string;
  /** Disable controls while a sibling action is in-flight (optimistic update). */
  busy?: boolean;
  onApprove: (report: CRAReport, note?: string) => Promise<void> | void;
  onEdit: (report: CRAReport, values: ReportEditFormValues) => Promise<void> | void;
  onReject: (report: CRAReport, note?: string) => Promise<void> | void;
  onReanalyse: (report: CRAReport) => Promise<void> | void;
}

/**
 * Map state to badge variant. `under_investigation` (forward-compat:
 * not in the DB CHECK list today, but reserved for M3-era policies) is
 * surfaced in yellow per the M1 #F-low-confidence pattern carried over
 * from DraftCard. ※要確認: confirm the backend never emits
 * `under_investigation` for CRA reports today; if it does we should
 * align the DB CHECK list.
 */
function stateVariant(
  state: CRAReportState,
): "default" | "secondary" | "destructive" | "outline" | "medium" {
  switch (state) {
    case "draft":
      return "outline";
    case "approved":
      return "default";
    case "submitted":
      return "secondary";
    case "archived":
      return "secondary";
    case "under_investigation":
      return "medium";
    default:
      return "outline";
  }
}

function decisionVariant(
  decision: CRAReportDecision,
): "default" | "secondary" | "destructive" | "outline" {
  switch (decision) {
    case "approved":
      return "default";
    case "rejected":
      return "destructive";
    case "edited":
      return "secondary";
    case "pending":
    default:
      return "outline";
  }
}

/** Build a compact label for an evidence kind (CRA-specific kinds). */
function evidenceKindLabel(kind: string): string {
  switch (kind) {
    case "vex_draft":
      return "vex";
    case "source_vex_draft":
      return "vex";
    case "advisory_excerpt":
      return "advisory";
    case "llm_call":
      return "llm";
    case "llm_rationale":
      return "rationale";
    case "vulnerability":
      return "cve";
    default:
      return kind;
  }
}

/**
 * Resolve the human-facing pointer string for one evidence row.
 * The CRA runner emits open-ended jsonb; the most common keys we see
 * today are `ref` (the FK string) and `description` (the operator-
 * facing snippet). We preserve everything in raw_snippet for
 * transparency. ※要確認: lock the shape once cra.Runner stabilises.
 */
function evidenceRef(e: CRAReportEvidence): string {
  if (typeof e.ref === "string" && e.ref !== "") return e.ref;
  return "";
}

export function ReportCard({
  report,
  projectId,
  busy = false,
  onApprove,
  onEdit,
  onReject,
  onReanalyse,
}: ReportCardProps) {
  const t = useTranslations("CRAReports.ReportCard");
  const tType = useTranslations("CRAReports.ReportType");
  const tLang = useTranslations("CRAReports.Lang");
  const tState = useTranslations("CRAReports.State");
  const tDecision = useTranslations("CRAReports.Decision");
  const locale = useLocale();

  const [mode, setMode] = useState<"view" | "edit" | "reject">("view");
  const [draftExpanded, setDraftExpanded] = useState(false);
  const [noteDraft, setNoteDraft] = useState("");

  const evidence = Array.isArray(report.evidence) ? report.evidence : [];

  // fail-safe: evidence 0 の report は表示しない (M1 #F4 carried over).
  // The DB enforces the non-empty array via CHECK + the runner's
  // ValidateEvidence guard, but a client-side guard ensures a backend
  // regression cannot leak an evidence-less compliance artefact.
  if (evidence.length === 0) {
    return null;
  }

  const draft = report.draft_text ?? "";
  const draftTruncated = draft.length > DRAFT_TRUNCATE_LENGTH && !draftExpanded;
  const draftDisplay = draftTruncated
    ? `${draft.slice(0, DRAFT_TRUNCATE_LENGTH)}…`
    : draft;

  const alreadyDecided = report.decision !== "pending";
  const controlsDisabled = busy || alreadyDecided;

  // Deep link back into the M1 triage page for the source VEX draft
  // (issue #32 spec). Use the locale prefix so next-intl routing
  // resolves the URL under the [locale] segment.
  const sourceVexHref = report.source_vex_draft_id
    ? `/${locale}/projects/${projectId}/triage`
    : null;

  return (
    <Card
      data-testid="cra-report-card"
      data-cve-id={report.cve_id}
      data-report-type={report.report_type}
      data-lang={report.lang}
      data-state={report.state}
      data-decision={report.decision}
    >
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle className="font-mono text-base">{report.cve_id}</CardTitle>
            <Badge variant="outline" className="uppercase">
              {safeT(tType, report.report_type)}
            </Badge>
            <Badge variant="outline" className="uppercase">
              {safeT(tLang, report.lang)}
            </Badge>
            <Badge variant={stateVariant(report.state)}>
              {safeT(tState, report.state)}
            </Badge>
            {alreadyDecided && (
              <Badge variant={decisionVariant(report.decision)}>
                {safeT(tDecision, report.decision)}
              </Badge>
            )}
            {report.provider && (
              <span
                className="inline-flex items-center gap-1 text-xs text-muted-foreground"
                title={report.model || undefined}
              >
                <Bot className="h-3 w-3" />
                {report.provider}
              </span>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Draft body — markdown */}
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {t("draftLabel")}
          </h4>
          {/*
            ※要確認: render with a proper Markdown renderer (react-markdown
             not currently a dep — adding it would inflate bundle size
             without immediate UX value). The whitespace-pre-wrap +
             monospace fallback preserves headings / lists / code blocks
             as text, which is acceptable for review-then-submit flows
             where the operator copies into the regulator's web form.
          */}
          <pre
            data-testid="cra-report-draft"
            className="max-h-[24rem] overflow-y-auto whitespace-pre-wrap rounded border bg-muted/30 p-3 font-sans text-sm leading-relaxed"
          >
            {draftDisplay}
          </pre>
          {draft.length > DRAFT_TRUNCATE_LENGTH && (
            <button
              type="button"
              onClick={() => setDraftExpanded((v) => !v)}
              className="mt-1 inline-flex items-center gap-1 text-xs text-blue-600 hover:underline"
            >
              {draftExpanded ? (
                <>
                  <ChevronUp className="h-3 w-3" /> {t("collapse")}
                </>
              ) : (
                <>
                  <ChevronDown className="h-3 w-3" /> {t("expand")}
                </>
              )}
            </button>
          )}
        </section>

        {/* Source VEX draft deep link */}
        {sourceVexHref && (
          <section className="rounded border border-blue-200 bg-blue-50 px-3 py-2 text-xs text-blue-900">
            <span className="font-semibold">{t("sourceVEXLabel")}: </span>
            <Link
              href={sourceVexHref}
              className="inline-flex items-center gap-1 underline"
              data-testid="cra-source-vex-link"
            >
              {report.source_vex_draft_id}
              <ExternalLink className="h-3 w-3" />
            </Link>
          </section>
        )}

        {/* Evidence list */}
        <section>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {t("evidenceLabel")} ({evidence.length})
          </h4>
          <ul className="space-y-2" data-testid="cra-evidence-list">
            {evidence.map((e, idx) => {
              const ref = evidenceRef(e);
              const kind = typeof e.kind === "string" ? e.kind : "unknown";
              return (
                <li
                  key={`${kind}-${idx}`}
                  className="rounded border bg-muted/40 p-2 text-xs"
                >
                  <div className="mb-1 flex flex-wrap items-center gap-2">
                    <Badge variant="outline" className="text-[10px]">
                      {evidenceKindLabel(kind)}
                    </Badge>
                    {ref && (
                      <code className="font-mono text-xs text-blue-700">
                        {ref}
                      </code>
                    )}
                  </div>
                  {typeof e.description === "string" && e.description !== "" && (
                    <p className="text-muted-foreground">{e.description}</p>
                  )}
                  {typeof e.note === "string" && e.note !== "" && (
                    <p className="mt-1 italic text-muted-foreground">{e.note}</p>
                  )}
                </li>
              );
            })}
          </ul>
        </section>

        {/* Decision controls */}
        {mode === "view" && (
          <div className="flex flex-wrap items-center gap-2 border-t pt-4">
            <Button
              size="sm"
              disabled={controlsDisabled}
              onClick={() => onApprove(report)}
              data-testid="cra-approve"
            >
              <CheckCircle2 className="mr-1 h-4 w-4" />
              {t("approve")}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={controlsDisabled}
              onClick={() => setMode("edit")}
              data-testid="cra-edit"
            >
              <Edit3 className="mr-1 h-4 w-4" />
              {t("edit")}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={controlsDisabled}
              onClick={() => setMode("reject")}
              data-testid="cra-reject"
            >
              <XCircle className="mr-1 h-4 w-4" />
              {t("reject")}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={controlsDisabled}
              onClick={() => onReanalyse(report)}
              data-testid="cra-reanalyse"
            >
              <RefreshCw className="mr-1 h-4 w-4" />
              {t("reanalyse")}
            </Button>
            <div className="flex-1" />
            {/* M3 hook — disabled placeholder per issue #32 spec. */}
            <Button
              size="sm"
              variant="ghost"
              disabled
              title={t("submitDisabled")}
              data-testid="cra-submit"
            >
              <Send className="mr-1 h-4 w-4" />
              {t("submit")}
            </Button>
          </div>
        )}

        {mode === "reject" && (
          <RejectControls
            disabled={busy}
            note={noteDraft}
            onNoteChange={setNoteDraft}
            onConfirm={async () => {
              await onReject(report, noteDraft || undefined);
              setNoteDraft("");
              setMode("view");
            }}
            onCancel={() => {
              setNoteDraft("");
              setMode("view");
            }}
          />
        )}

        {mode === "edit" && (
          <EditForm
            report={report}
            disabled={busy}
            onSubmit={async (values) => {
              await onEdit(report, values);
              setMode("view");
            }}
            onCancel={() => setMode("view")}
          />
        )}
      </CardContent>

      {/* Already-decided breadcrumb when a row briefly appears in a
          pending list (optimistic update race). */}
      {alreadyDecided && (
        <CardContent className="border-t pt-3">
          <p className="flex items-start gap-1 text-xs text-yellow-700">
            <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" />
            <span>
              {t("alreadyDecided", { decision: safeT(tDecision, report.decision) })}
            </span>
          </p>
        </CardContent>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * useTranslations throws on missing keys. CRA report types / langs /
 * states / decisions come from the backend allow-list, but a new
 * backend value (e.g. a future report_type) would crash the card. Fall
 * back to the raw string in that case so an unknown badge label stays
 * inspectable instead of taking the whole queue down.
 */
function safeT(t: (key: string) => string, key: string): string {
  try {
    return t(key);
  } catch {
    return key;
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface RejectControlsProps {
  disabled?: boolean;
  note: string;
  onNoteChange: (v: string) => void;
  onConfirm: () => void;
  onCancel: () => void;
}

function RejectControls({
  disabled,
  note,
  onNoteChange,
  onConfirm,
  onCancel,
}: RejectControlsProps) {
  const t = useTranslations("CRAReports.ReportCard");
  return (
    <div className="space-y-2 border-t pt-4" data-testid="cra-reject-controls">
      <label className="block text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {t("rejectReasonLabel")}
      </label>
      <Textarea
        value={note}
        onChange={(e) => onNoteChange(e.target.value)}
        rows={3}
        placeholder={t("rejectReasonPlaceholder")}
      />
      <div className="flex gap-2">
        <Button
          size="sm"
          variant="destructive"
          disabled={disabled}
          onClick={onConfirm}
        >
          {t("rejectConfirm")}
        </Button>
        <Button size="sm" variant="outline" disabled={disabled} onClick={onCancel}>
          {t("cancel")}
        </Button>
      </div>
    </div>
  );
}

interface EditFormProps {
  report: CRAReport;
  disabled?: boolean;
  onSubmit: (values: ReportEditFormValues) => Promise<void> | void;
  onCancel: () => void;
}

function EditForm({ report, disabled, onSubmit, onCancel }: EditFormProps) {
  const t = useTranslations("CRAReports.ReportCard");

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ReportEditFormValues>({
    resolver: zodResolver(editSchema),
    defaultValues: {
      draft_text: report.draft_text ?? "",
      decision_note: "",
    },
  });

  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      className="space-y-3 border-t pt-4"
      data-testid="cra-edit-form"
    >
      <div>
        <label
          htmlFor={`edit-draft-${report.id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("draftLabel")}
        </label>
        <Textarea
          id={`edit-draft-${report.id}`}
          rows={16}
          {...register("draft_text")}
          disabled={disabled || isSubmitting}
          className="font-mono text-sm"
        />
        {errors.draft_text && (
          <p className="mt-1 text-xs text-red-600">{errors.draft_text.message}</p>
        )}
      </div>

      <div>
        <label
          htmlFor={`edit-note-${report.id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("noteLabel")}
        </label>
        <Textarea
          id={`edit-note-${report.id}`}
          rows={2}
          {...register("decision_note")}
          disabled={disabled || isSubmitting}
          placeholder={t("notePlaceholder")}
        />
      </div>

      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={disabled || isSubmitting}>
          <FileText className="mr-1 h-4 w-4" />
          {isSubmitting ? t("saving") : t("saveEdit")}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={disabled || isSubmitting}
          onClick={onCancel}
        >
          {t("cancel")}
        </Button>
      </div>
    </form>
  );
}

export default ReportCard;

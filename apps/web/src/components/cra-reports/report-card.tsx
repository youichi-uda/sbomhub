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
  CRAReportDeadlineStatus,
  CRAReportDecision,
  CRAReportEvidence,
  CRAReportState,
  CRASubmission,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { SubmissionTimeline } from "@/components/cra-reports/submission-timeline";

const DRAFT_TRUNCATE_LENGTH = 800;

const editSchema = z.object({
  draft_text: z.string().min(1, "draft_text is required").max(50000),
  decision_note: z.string().max(2000),
});

export type ReportEditFormValues = z.infer<typeof editSchema>;

// SubmitForm schema. authority is required (backend rejects empty with 400)
// and free-text VARCHAR(255) (Wave A: no enum). submitted_at is a
// datetime-local value that page.tsx converts to RFC3339 before POST; an
// empty value lets the server default to NOW(). reference_number is
// VARCHAR(255); notes is TEXT (kept generous but bounded client-side).
const submitSchema = z.object({
  authority: z.string().min(1, "authority is required").max(255),
  submitted_at: z.string(),
  reference_number: z.string().max(255),
  notes: z.string().max(5000),
});

export type ReportSubmitFormValues = z.infer<typeof submitSchema>;

/**
 * Current wall-clock time formatted for a <input type="datetime-local">
 * value (`YYYY-MM-DDTHH:mm`, local timezone). Used as the SubmitForm
 * default so the operator only tweaks the time if the real submission
 * happened earlier.
 */
function nowLocalDatetime(): string {
  const now = new Date();
  const offsetMs = now.getTimezoneOffset() * 60000;
  return new Date(now.getTime() - offsetMs).toISOString().slice(0, 16);
}

export interface ReportCardProps {
  report: CRAReport;
  projectId: string;
  /** Disable controls while a sibling action is in-flight (optimistic update). */
  busy?: boolean;
  /**
   * The report's recorded submissions (submitted_at DESC). Only approved
   * reports can carry submissions; pass an empty array otherwise.
   */
  submissions?: CRASubmission[];
  onApprove: (report: CRAReport, note?: string) => Promise<void> | void;
  onEdit: (report: CRAReport, values: ReportEditFormValues) => Promise<void> | void;
  onReject: (report: CRAReport, note?: string) => Promise<void> | void;
  onReanalyse: (report: CRAReport) => Promise<void> | void;
  /**
   * Record a human-attested submission to an authority. Only invoked for
   * approved reports (the button is disabled otherwise). page.tsx maps the
   * form values to CRASubmissionInput and POSTs to the submissions endpoint.
   */
  onRecordSubmission: (
    report: CRAReport,
    values: ReportSubmitFormValues,
  ) => Promise<void> | void;
}

/**
 * Map state to badge variant. `under_investigation` (forward-compat:
 * not in the DB CHECK list today, but reserved for M3-era policies) is
 * surfaced in yellow per the M1 #F-low-confidence pattern carried over
 * from DraftCard. The backend cannot emit `under_investigation` for a
 * CRA report today: cra.Runner persists state='draft' only, and the
 * DB CHECK (apps/api/migrations/038_cra_reports.up.sql) rejects any
 * value outside draft / approved / submitted / archived — the branch
 * below is purely forward-compat.
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

/**
 * Map the Art.14 deadline verdict (M34) to a Badge variant. Returns null for
 * not_applicable (final-report type / no awareness_time) so the caller renders no
 * badge at all. `on_time` reuses the positive/approved variant (`default`),
 * mirroring stateVariant's `approved → default`, since the Badge primitive
 * has no dedicated success/green variant. `pending → outline` (neutral,
 * still open), `overdue`/`late → destructive` (missed / past-window).
 */
function deadlineVariant(
  status: CRAReportDeadlineStatus,
): "default" | "destructive" | "outline" | null {
  switch (status) {
    case "on_time":
      return "default";
    case "pending":
      return "outline";
    case "overdue":
    case "late":
      return "destructive";
    case "not_applicable":
    default:
      return null;
  }
}

/**
 * Translation key for a deadline verdict label. not_applicable has no key
 * (it renders nothing); the default arm returns the raw status so an
 * unforeseen backend value stays inspectable via safeT.
 */
function deadlineLabelKey(status: CRAReportDeadlineStatus): string {
  switch (status) {
    case "on_time":
      return "onTime";
    case "late":
      return "late";
    case "pending":
      return "pending";
    case "overdue":
      return "overdue";
    default:
      return status;
  }
}

/**
 * Format an RFC3339 timestamp (awareness_time) for a muted read-only line.
 * Mirrors submission-timeline.tsx's formatSubmittedAt: falls back to the raw
 * string if unparseable so a malformed value stays inspectable rather than
 * rendering "Invalid Date".
 */
function formatTimestamp(value: string, locale: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

/**
 * Short remaining-time hint for a pending deadline, e.g. "残り Xh" / "Xh left".
 * Computed at render time from deadline_at (no live countdown — the card is
 * not re-rendered on a timer). Returns null if deadline_at is unparseable or
 * already elapsed (a pending status with a past deadline means clock skew;
 * suppress the misleading "0h"). Rounds up so a sub-hour window still reads as
 * at least "1h".
 */
function remainingTimeLabel(
  deadlineAt: string,
  t: (key: string, values?: Record<string, string | number>) => string,
): string | null {
  const ms = new Date(deadlineAt).getTime();
  if (Number.isNaN(ms)) return null;
  const remainingMs = ms - Date.now();
  if (remainingMs <= 0) return null;
  const hours = Math.max(1, Math.ceil(remainingMs / 3_600_000));
  try {
    return t("remaining", { hours });
  } catch {
    return `${hours}h`;
  }
}

/**
 * Build a compact label for an evidence kind (CRA-specific kinds).
 *
 * The case list mirrors the six kinds cra.Runner actually emits
 * (apps/api/internal/service/cra/runner.go — the runAIDisabled
 * synthetic evidence block plus buildEvidence): ai_disabled /
 * vex_draft / template / advisory_excerpt / reachability_result /
 * llm_rationale. F342 (M23-2 #124) removed the never-emitted
 * source_vex_draft / llm_call / vulnerability cases (F280 discipline:
 * no register without an emit site) and added the three emitted kinds
 * the pre-F342 switch missed. The default arm keeps rendering the raw
 * kind string as defence for a future backend kind this list has not
 * caught up with yet.
 */
function evidenceKindLabel(kind: string): string {
  switch (kind) {
    case "ai_disabled":
      return "ai-disabled";
    case "vex_draft":
      return "vex";
    case "template":
      return "template";
    case "advisory_excerpt":
      return "advisory";
    case "reachability_result":
      return "reachability";
    case "llm_rationale":
      return "rationale";
    default:
      return kind;
  }
}

/**
 * Resolve the human-facing pointer string for one evidence row.
 * The emitting shape is locked at cra.Runner's evidenceEntry struct
 * (apps/api/internal/service/cra/runner.go): {kind, ref?, source?,
 * description?, note?}, where `ref` carries the FK string (VEX draft /
 * advisory excerpt / reachability result id) and `description` the
 * operator-facing snippet. The column stays open-ended jsonb, so
 * unknown keys are tolerated on the wire but not rendered.
 */
function evidenceRef(e: CRAReportEvidence): string {
  if (typeof e.ref === "string" && e.ref !== "") return e.ref;
  return "";
}

export function ReportCard({
  report,
  projectId,
  busy = false,
  submissions = [],
  onApprove,
  onEdit,
  onReject,
  onReanalyse,
  onRecordSubmission,
}: ReportCardProps) {
  const t = useTranslations("CRAReports.ReportCard");
  const tType = useTranslations("CRAReports.ReportType");
  const tLang = useTranslations("CRAReports.Lang");
  const tState = useTranslations("CRAReports.State");
  const tDecision = useTranslations("CRAReports.Decision");
  const tDeadline = useTranslations("CRAReports.Deadline");
  const locale = useLocale();

  const [mode, setMode] = useState<"view" | "edit" | "reject" | "submit">(
    "view",
  );
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

  // Submission recording is only legitimate for an approved report (the
  // backend rejects any other decision with 409). Multiple submissions are
  // allowed by design (Art.14 early-warning → detailed → final timeline), so
  // an already-submitted report stays enabled.
  const canSubmit = report.decision === "approved";

  // Art.14 deadline verdict (M34). Guarded on deadline_status being present
  // so an older API response that omits the enrichment renders no badge.
  // not_applicable maps to a null variant and is likewise skipped.
  const deadlineStatus = report.deadline_status;
  const deadlineBadgeVariant = deadlineStatus
    ? deadlineVariant(deadlineStatus)
    : null;
  const remainingLabel =
    deadlineStatus === "pending" && report.deadline_at
      ? remainingTimeLabel(report.deadline_at, tDeadline)
      : null;

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
            {deadlineStatus && deadlineBadgeVariant && (
              <Badge
                variant={deadlineBadgeVariant}
                data-testid="cra-deadline-badge"
                data-deadline-status={deadlineStatus}
              >
                {safeT(tDeadline, deadlineLabelKey(deadlineStatus))}
                {remainingLabel && (
                  <span className="ml-1 font-normal opacity-90">
                    {remainingLabel}
                  </span>
                )}
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
        {/* Read-only awareness instant (M34). Shown when captured so the
            deadline verdict badge above is explainable — this is the Art.14
            clock start. Capture-at-generation only; not editable here. */}
        {report.awareness_time && (
          <p
            className="mt-1 text-xs text-muted-foreground"
            data-testid="cra-awareness-time"
          >
            {safeT(tDeadline, "awarenessTime")}:{" "}
            {formatTimestamp(report.awareness_time, locale)}
          </p>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Draft body — markdown */}
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {t("draftLabel")}
          </h4>
          {/*
            Deliberately rendered as plain text, not Markdown:
            react-markdown is not a dependency of apps/web (adding it
            would inflate bundle size without immediate UX value). The
            whitespace-pre-wrap <pre> preserves headings / lists / code
            blocks as text, which is acceptable for review-then-submit
            flows where the operator copies into the regulator's web
            form.
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
            {/* M33 (F420): record a human-attested submission to an
                authority. Enabled only for approved reports; otherwise it
                stays disabled with an explanatory tooltip. */}
            <Button
              size="sm"
              variant={canSubmit ? "default" : "ghost"}
              disabled={busy || !canSubmit}
              title={canSubmit ? undefined : t("submitDisabled")}
              onClick={() => setMode("submit")}
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

        {mode === "submit" && (
          <SubmitForm
            report={report}
            disabled={busy}
            onSubmit={async (values) => {
              await onRecordSubmission(report, values);
              setMode("view");
            }}
            onCancel={() => setMode("view")}
          />
        )}

        {/* Submission ledger (Art.14 timeline). Shown for approved reports
            — which may accumulate multiple submissions — and whenever a
            submission already exists, so a historical row is never hidden. */}
        {(canSubmit || submissions.length > 0) && (
          <SubmissionTimeline submissions={submissions} />
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

interface SubmitFormProps {
  report: CRAReport;
  disabled?: boolean;
  onSubmit: (values: ReportSubmitFormValues) => Promise<void> | void;
  onCancel: () => void;
}

/**
 * SubmitForm — record a human-attested submission of an approved CRA report
 * to an authority (M33 Wave C). Same react-hook-form + zod shape as
 * EditForm. authority is required; submitted_at defaults to now (operator
 * adjusts if the real submission happened earlier); reference_number / notes
 * are optional. Nothing here auto-submits — this only records the operator's
 * assertion that they submitted the report.
 */
function SubmitForm({ report, disabled, onSubmit, onCancel }: SubmitFormProps) {
  const t = useTranslations("CRAReports.ReportCard");

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ReportSubmitFormValues>({
    resolver: zodResolver(submitSchema),
    defaultValues: {
      authority: "",
      submitted_at: nowLocalDatetime(),
      reference_number: "",
      notes: "",
    },
  });

  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      className="space-y-3 border-t pt-4"
      data-testid="cra-submit-form"
    >
      <div>
        <label
          htmlFor={`submit-authority-${report.id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("authorityLabel")}
        </label>
        <Input
          id={`submit-authority-${report.id}`}
          type="text"
          {...register("authority")}
          disabled={disabled || isSubmitting}
          placeholder={t("authorityPlaceholder")}
        />
        {errors.authority && (
          <p className="mt-1 text-xs text-red-600">{errors.authority.message}</p>
        )}
      </div>

      <div>
        <label
          htmlFor={`submit-at-${report.id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("submittedAtLabel")}
        </label>
        <Input
          id={`submit-at-${report.id}`}
          type="datetime-local"
          {...register("submitted_at")}
          disabled={disabled || isSubmitting}
        />
      </div>

      <div>
        <label
          htmlFor={`submit-ref-${report.id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("referenceNumberLabel")}
        </label>
        <Input
          id={`submit-ref-${report.id}`}
          type="text"
          {...register("reference_number")}
          disabled={disabled || isSubmitting}
          placeholder={t("referenceNumberPlaceholder")}
        />
      </div>

      <div>
        <label
          htmlFor={`submit-notes-${report.id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("submissionNotesLabel")}
        </label>
        <Textarea
          id={`submit-notes-${report.id}`}
          rows={2}
          {...register("notes")}
          disabled={disabled || isSubmitting}
          placeholder={t("submissionNotesPlaceholder")}
        />
      </div>

      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={disabled || isSubmitting}>
          <Send className="mr-1 h-4 w-4" />
          {isSubmitting ? t("recording") : t("recordSubmit")}
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

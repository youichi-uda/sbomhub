"use client";

/**
 * DraftCard — one AI-drafted VEX statement awaiting human decision.
 *
 * Renders state / justification / detail / confidence + evidence list, plus
 * the four decision controls (Approve / Edit / Reject / Re-analyse) and a
 * disabled "CRA report に追加" affordance that hooks into M2.
 *
 * Backend wire shape: repository.VEXDraft serialised by Go's default JSON
 * marshalling (PascalCase fields) — see apps/api/internal/repository/vex_drafts.go.
 * Evidence items are triage.EvidencePointer (snake_case).
 *
 * Issue: #28 (M1 Wave M1-6). PRODUCT_REBOOT_PLAN.md §7.1.
 */

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useTranslations } from "next-intl";
import {
  CheckCircle2,
  Edit3,
  XCircle,
  RefreshCw,
  AlertTriangle,
  FileText,
  ChevronDown,
  ChevronUp,
  FilePlus2,
  Bot,
} from "lucide-react";

import {
  VexDraft,
  VexDraftState,
  VexDraftJustification,
  VexDraftEvidence,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";

/**
 * Default confidence threshold below which the UI surfaces a yellow warning
 * and forces an "under_investigation" badge regardless of the AI's chosen
 * state (issue #28 acceptance criterion). The backend already clamps to
 * under_investigation below `triage.ConfidenceThresholdFromEnv()`; this
 * client-side guard catches drift between server and UI and avoids leaking
 * "approved-looking" draft cards when the threshold env changes.
 * ※要確認: surface the server-side threshold through an API endpoint and
 *  prefer that over this constant.
 */
const DEFAULT_CONFIDENCE_THRESHOLD = 0.7;

const DETAIL_TRUNCATE_LENGTH = 240;

const STATE_OPTIONS: readonly VexDraftState[] = [
  "not_affected",
  "affected",
  "under_investigation",
  "resolved",
] as const;

const JUSTIFICATION_OPTIONS: readonly VexDraftJustification[] = [
  "",
  "code_not_present",
  "code_not_reachable",
  "requires_configuration",
  "requires_dependency",
  "requires_environment",
  "protected_by_compiler",
  "protected_at_perimeter",
  "protected_at_runtime",
  "inline_mitigations_already_exist",
] as const;

const editSchema = z.object({
  state: z.enum(["not_affected", "affected", "under_investigation", "resolved"]),
  justification: z.enum([
    "",
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_perimeter",
    "protected_at_runtime",
    "inline_mitigations_already_exist",
  ]),
  detail: z.string().max(4000),
  note: z.string().max(2000),
});

export type EditFormValues = z.infer<typeof editSchema>;

export interface DraftCardProps {
  draft: VexDraft;
  /** Optional override for the confidence threshold (defaults to 0.7). */
  threshold?: number;
  /** Disable controls while a sibling action is in-flight (optimistic update). */
  busy?: boolean;
  onApprove: (draft: VexDraft, note?: string) => Promise<void> | void;
  onEdit: (draft: VexDraft, values: EditFormValues) => Promise<void> | void;
  onReject: (draft: VexDraft, note?: string) => Promise<void> | void;
  onReanalyse: (draft: VexDraft) => Promise<void> | void;
}

/**
 * Map VEX state to badge variant. Confidence-clamped low-quality drafts get
 * the yellow "medium" variant per issue #28 (mirrors the backend behaviour
 * of forcing state=under_investigation under threshold).
 */
function stateVariant(
  state: VexDraftState,
  belowThreshold: boolean
): "default" | "secondary" | "destructive" | "outline" | "medium" {
  if (belowThreshold) return "medium";
  switch (state) {
    case "not_affected":
      return "secondary";
    case "affected":
      return "destructive";
    case "under_investigation":
      return "medium";
    case "resolved":
      return "default";
    default:
      return "outline";
  }
}

/** Convert evidence kind to a compact, locale-independent label. */
function evidenceKindLabel(kind: string): string {
  switch (kind) {
    case "import_path":
      return "import";
    case "symbol_ref":
      return "symbol";
    case "advisory_excerpt":
      return "advisory";
    case "llm_rationale":
      return "rationale";
    case "analyzer_error":
      return "analyzer-error";
    default:
      return kind;
  }
}

/** Build a `file:line` token for an evidence row (no anchor — we have no IDE wiring). */
function evidenceLocation(e: VexDraftEvidence): string {
  if (!e.file_path) return "";
  if (e.line && e.line > 0) {
    return `${e.file_path}:${e.line}`;
  }
  return e.file_path;
}

export function DraftCard({
  draft,
  threshold = DEFAULT_CONFIDENCE_THRESHOLD,
  busy = false,
  onApprove,
  onEdit,
  onReject,
  onReanalyse,
}: DraftCardProps) {
  const t = useTranslations("Triage.DraftCard");
  const tState = useTranslations("Triage.State");
  const tJust = useTranslations("Triage.Justification");

  const [mode, setMode] = useState<"view" | "edit" | "reject">("view");
  const [detailExpanded, setDetailExpanded] = useState(false);
  const [noteDraft, setNoteDraft] = useState("");

  const evidence = Array.isArray(draft.Evidence) ? draft.Evidence : [];

  // fail-safe: evidence 0 の draft は表示しない (issue #28 acceptance criterion).
  // Backend enforces this via vex_drafts.evidence CHECK + triage runner's
  // ValidateEvidence guard, but we re-check on the client so a backend bug
  // can't surface an evidence-less card.
  if (evidence.length === 0) {
    return null;
  }

  const confidence = typeof draft.Confidence === "number" ? draft.Confidence : 0;
  const belowThreshold = confidence < threshold;
  const confidencePct = Math.round(confidence * 100);

  const detail = draft.Detail ?? "";
  const detailTruncated = detail.length > DETAIL_TRUNCATE_LENGTH && !detailExpanded;
  const detailDisplay = detailTruncated
    ? `${detail.slice(0, DETAIL_TRUNCATE_LENGTH)}…`
    : detail;

  // Drafts that have already been decided (approved / edited / rejected) are
  // surfaced read-only — the triage page filters to decision=pending, but a
  // race between optimistic update and re-fetch can briefly render a decided
  // draft here. Lock the controls so a second decision can't be submitted.
  const alreadyDecided = draft.Decision !== "pending";
  const controlsDisabled = busy || alreadyDecided;

  return (
    <Card
      data-testid="triage-draft-card"
      data-cve-id={draft.CVEID}
      data-decision={draft.Decision}
      className={belowThreshold ? "border-yellow-400" : undefined}
    >
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle className="font-mono text-base">{draft.CVEID}</CardTitle>
            <Badge variant={stateVariant(draft.State, belowThreshold)}>
              {belowThreshold ? tState("under_investigation") : tState(draft.State)}
            </Badge>
            {draft.Justification && (
              <Badge variant="outline" className="font-normal">
                {tJust(draft.Justification)}
              </Badge>
            )}
            {alreadyDecided && (
              <Badge variant="outline" className="capitalize">
                {draft.Decision}
              </Badge>
            )}
            {draft.Provider && (
              <span
                className="inline-flex items-center gap-1 text-xs text-muted-foreground"
                title={draft.Model || undefined}
              >
                <Bot className="h-3 w-3" />
                {draft.Provider}
              </span>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Confidence */}
        <section>
          <div className="mb-1 flex items-center justify-between text-xs text-muted-foreground">
            <span>{t("confidenceLabel")}</span>
            <span className="font-mono">{confidencePct}%</span>
          </div>
          <Progress
            value={confidencePct}
            className={belowThreshold ? "bg-yellow-100" : undefined}
            data-testid="triage-confidence"
          />
          {belowThreshold && (
            <p className="mt-2 flex items-start gap-1 text-xs text-yellow-700">
              <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" />
              <span>{t("lowConfidence", { threshold: Math.round(threshold * 100) })}</span>
            </p>
          )}
        </section>

        {/* Detail */}
        {detail && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              {t("detailLabel")}
            </h4>
            <p className="whitespace-pre-wrap text-sm">{detailDisplay}</p>
            {detail.length > DETAIL_TRUNCATE_LENGTH && (
              <button
                type="button"
                onClick={() => setDetailExpanded((v) => !v)}
                className="mt-1 inline-flex items-center gap-1 text-xs text-blue-600 hover:underline"
              >
                {detailExpanded ? (
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
        )}

        {/* Evidence */}
        <section>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {t("evidenceLabel")} ({evidence.length})
          </h4>
          <ul className="space-y-2" data-testid="triage-evidence-list">
            {evidence.map((e, idx) => {
              const loc = evidenceLocation(e);
              return (
                <li
                  key={`${e.kind}-${idx}`}
                  className="rounded border bg-muted/40 p-2 text-xs"
                >
                  <div className="mb-1 flex flex-wrap items-center gap-2">
                    <Badge variant="outline" className="text-[10px]">
                      {evidenceKindLabel(e.kind)}
                    </Badge>
                    {loc && (
                      <code className="font-mono text-xs text-blue-700">
                        {loc}
                      </code>
                    )}
                    {e.symbol && (
                      <code className="font-mono text-xs text-muted-foreground">
                        {e.symbol}
                      </code>
                    )}
                    {e.source && (
                      <span className="text-[10px] uppercase text-muted-foreground">
                        {e.source}
                      </span>
                    )}
                  </div>
                  {e.description && (
                    <p className="text-muted-foreground">{e.description}</p>
                  )}
                  {e.raw_snippet && (
                    <pre className="mt-1 overflow-x-auto rounded bg-background p-1 font-mono text-[11px] text-foreground/80">
                      {e.raw_snippet}
                    </pre>
                  )}
                  {e.note && (
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
              onClick={() => onApprove(draft)}
              data-testid="triage-approve"
            >
              <CheckCircle2 className="mr-1 h-4 w-4" />
              {t("approve")}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={controlsDisabled}
              onClick={() => setMode("edit")}
              data-testid="triage-edit"
            >
              <Edit3 className="mr-1 h-4 w-4" />
              {t("edit")}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={controlsDisabled}
              onClick={() => setMode("reject")}
              data-testid="triage-reject"
            >
              <XCircle className="mr-1 h-4 w-4" />
              {t("reject")}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={controlsDisabled}
              onClick={() => onReanalyse(draft)}
              data-testid="triage-reanalyse"
            >
              <RefreshCw className="mr-1 h-4 w-4" />
              {t("reanalyse")}
            </Button>
            <div className="flex-1" />
            {/* M2 hook — disabled placeholder per issue #28 spec. */}
            <Button
              size="sm"
              variant="ghost"
              disabled
              title={t("addToCRADisabled")}
            >
              <FilePlus2 className="mr-1 h-4 w-4" />
              {t("addToCRA")}
            </Button>
          </div>
        )}

        {mode === "reject" && (
          <RejectControls
            disabled={busy}
            note={noteDraft}
            onNoteChange={setNoteDraft}
            onConfirm={async () => {
              await onReject(draft, noteDraft || undefined);
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
            draft={draft}
            disabled={busy}
            onSubmit={async (values) => {
              await onEdit(draft, values);
              setMode("view");
            }}
            onCancel={() => setMode("view")}
          />
        )}
      </CardContent>
    </Card>
  );
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
  const t = useTranslations("Triage.DraftCard");
  return (
    <div className="space-y-2 border-t pt-4" data-testid="triage-reject-controls">
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
  draft: VexDraft;
  disabled?: boolean;
  onSubmit: (values: EditFormValues) => Promise<void> | void;
  onCancel: () => void;
}

function EditForm({ draft, disabled, onSubmit, onCancel }: EditFormProps) {
  const t = useTranslations("Triage.DraftCard");
  const tState = useTranslations("Triage.State");
  const tJust = useTranslations("Triage.Justification");

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<EditFormValues>({
    resolver: zodResolver(editSchema),
    defaultValues: {
      state: draft.State,
      justification: draft.Justification ?? "",
      detail: draft.Detail ?? "",
      note: "",
    },
  });

  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      className="space-y-3 border-t pt-4"
      data-testid="triage-edit-form"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div>
          <label
            htmlFor={`edit-state-${draft.ID}`}
            className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
          >
            {t("stateLabel")}
          </label>
          <select
            id={`edit-state-${draft.ID}`}
            {...register("state")}
            className="w-full rounded border px-3 py-2 text-sm"
            disabled={disabled || isSubmitting}
          >
            {STATE_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {tState(s)}
              </option>
            ))}
          </select>
          {errors.state && (
            <p className="mt-1 text-xs text-red-600">{errors.state.message}</p>
          )}
        </div>
        <div>
          <label
            htmlFor={`edit-just-${draft.ID}`}
            className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
          >
            {t("justificationLabel")}
          </label>
          <select
            id={`edit-just-${draft.ID}`}
            {...register("justification")}
            className="w-full rounded border px-3 py-2 text-sm"
            disabled={disabled || isSubmitting}
          >
            {JUSTIFICATION_OPTIONS.map((j) => (
              <option key={j || "none"} value={j}>
                {j === "" ? t("justificationNone") : tJust(j)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div>
        <label
          htmlFor={`edit-detail-${draft.ID}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("detailLabel")}
        </label>
        <Textarea
          id={`edit-detail-${draft.ID}`}
          rows={4}
          {...register("detail")}
          disabled={disabled || isSubmitting}
        />
        {errors.detail && (
          <p className="mt-1 text-xs text-red-600">{errors.detail.message}</p>
        )}
      </div>

      <div>
        <label
          htmlFor={`edit-note-${draft.ID}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("noteLabel")}
        </label>
        <Textarea
          id={`edit-note-${draft.ID}`}
          rows={2}
          {...register("note")}
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

export default DraftCard;

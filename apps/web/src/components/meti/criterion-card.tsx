"use client";

/**
 * CriterionCard — one METI ver 2.0 self-assessment row.
 *
 * Wave M3-5 (issue #38). Renders the per-criterion verdict
 * (evaluator status + optional operator override), the evidence list
 * the evaluator (or operator) attached, the improvement action, and a
 * manual-override form (react-hook-form + zod).
 *
 * Wire shape: repository.MetiAssessment — snake_case json tags
 * declared at the struct level (apps/api/internal/repository/
 * meti_assessments.go), mirroring the CRA report design that locks
 * the JSON shape at the repository struct definition to prevent the
 * M1 #F28-class wire-shape drift between repository and handler.
 *
 * Locale handling: the catalog title / description live on the Go
 * Criterion struct as TitleJA / TitleEN / DescriptionJA /
 * DescriptionEN; the handler does not denormalise them onto every
 * MetiAssessment row (only ImprovementActions carries the title for
 * efficiency). The card receives the catalog entry as an optional
 * prop (page-level lookup) and picks the language by next-intl
 * useLocale. ※要確認: a future M4 task could add a /catalog endpoint
 * the UI fetches once and caches; for now the page renders title
 * fallback as `criterion_id` so a catalog miss stays inspectable.
 */

import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useLocale, useTranslations } from "next-intl";
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  CircleHelp,
  Edit3,
  Info,
  XCircle,
} from "lucide-react";

import {
  MetiAssessment,
  METIAssessmentEvidence,
  MetiAssessmentClearOverrideInput,
  MetiAssessmentOverrideInput,
  METIStatus,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/**
 * M11-3 (#78): title_ja was rewritten to be verbatim from primary METI
 * ver 2.0 PDF for 17/32 criteria, which makes titles up to ~75 chars
 * (the longest is sbom_operation.01). The list-view variant of the
 * card truncates titles past TITLE_TRUNCATE_CHARS with an ellipsis and
 * surfaces the full title via a hover tooltip. The detail variant
 * always renders full text. The component callsite (e.g. METI
 * dashboard accordion) does not pass a variant today; the default is
 * "list" so the accordion stays scannable. Future detail-drawer
 * callers can opt-in to "detail" to render full text inline.
 */
const TITLE_TRUNCATE_CHARS = 80;

/**
 * Pure helper: returns the truncated label (display) and whether the
 * full text was actually trimmed. Splitting it out keeps the JSX
 * branch readable and the assertion ("truncated only when needed")
 * testable in isolation.
 */
export function truncateTitle(full: string, max: number = TITLE_TRUNCATE_CHARS): {
  display: string;
  truncated: boolean;
} {
  if (!full) return { display: "", truncated: false };
  // Array.from handles surrogate pairs / non-BMP chars correctly so
  // an emoji or 𩸽-class CJK extension B char counts as 1, not 2.
  const codepoints = Array.from(full);
  if (codepoints.length <= max) {
    return { display: full, truncated: false };
  }
  return { display: codepoints.slice(0, max).join("") + "…", truncated: true };
}

/**
 * Optional catalog entry — fetched at page level. Mirrors a tiny subset
 * of metisvc.Criterion (TitleJA / TitleEN / DescriptionJA /
 * DescriptionEN). The card falls back to the raw criterion_id when
 * absent so the UI never crashes on a catalog miss.
 */
export interface MetiCatalogEntry {
  title_ja?: string;
  title_en?: string;
  description_ja?: string;
  description_en?: string;
}

/** zod schema for the override form. Mirrors handler.metiOverrideRequest. */
const overrideSchema = z.object({
  override_status: z.enum([
    "achieved",
    "not_achieved",
    "needs_review",
    "not_applicable",
  ]),
  override_note: z.string().max(2000),
  improvement_action: z.string().max(2000),
});

export type CriterionOverrideFormValues = z.infer<typeof overrideSchema>;

/**
 * zod schema for the clear-override form (M3 #F35). Mirrors
 * handler.metiClearOverrideRequest — the server enforces 1..4096 chars
 * AFTER trim, so we mirror the trim-then-length check here to keep the
 * UI validation aligned. The client-side cap is set to MAX 4096 to
 * surface the server bound; 2000 would silently truncate visually.
 */
const clearOverrideSchema = z.object({
  note: z
    .string()
    .transform((s) => s.trim())
    .refine((s) => s.length >= 1 && s.length <= 4096, {
      message: "note must be 1..4096 characters after trim",
    }),
});

export type CriterionClearOverrideFormValues = z.infer<typeof clearOverrideSchema>;

export interface CriterionCardProps {
  assessment: MetiAssessment;
  /** Optional catalog title / description for locale-aware rendering. */
  catalog?: MetiCatalogEntry;
  /** Disable controls while a sibling action is in-flight. */
  busy?: boolean;
  /**
   * Display variant. M11-3 (#78) introduced two render modes:
   *
   *   - "list" (default): list-view variant. Truncates title_ja past
   *     ~80 chars with an ellipsis and surfaces the full text via
   *     hover tooltip; description renders full. Used by the METI
   *     dashboard accordion where many cards stack vertically.
   *   - "detail": detail-drawer variant. Renders full title + full
   *     description without truncation. Reserved for a future
   *     per-criterion drawer / report view.
   *
   * Description is always rendered in full because the auditor needs
   * the full PDF-verbatim sentence to verify provenance; only the
   * title is truncated.
   */
  variant?: "list" | "detail";
  /**
   * Async handler invoked when the operator confirms an override. The
   * page is responsible for wiring this to api.meti.overrideCriterion
   * and surfacing flash errors on failure.
   */
  onOverride: (
    assessment: MetiAssessment,
    input: MetiAssessmentOverrideInput,
  ) => Promise<void> | void;
  /**
   * Async handler invoked when the operator confirms a clear-override
   * (M3 Codex review #F35). The page wires this to
   * api.meti.clearOverrideCriterion. When omitted the clear-override
   * UI is hidden — used by storybook / read-only host pages that do
   * not want write controls. Production callers (meti page) always
   * pass this.
   */
  onClearOverride?: (
    assessment: MetiAssessment,
    input: MetiAssessmentClearOverrideInput,
  ) => Promise<void> | void;
}

/**
 * Map a METI status to a badge variant. needs_review uses the yellow
 * `medium` variant carried over from DraftCard's low-confidence
 * highlight; not_applicable uses `outline` because the operator chose
 * to take it out of scope (less attention-grabbing than gray).
 */
function statusVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" | "medium" {
  switch (status) {
    case "achieved":
      return "default";
    case "not_achieved":
      return "destructive";
    case "needs_review":
      return "medium";
    case "not_applicable":
      return "outline";
    default:
      return "outline";
  }
}

/**
 * Status icon — mirrors the badge colour scheme. lucide-react icons
 * keep the badge readable without forcing the operator to learn the
 * colour mapping.
 */
function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "achieved":
      return <CheckCircle2 className="h-4 w-4 text-green-600" />;
    case "not_achieved":
      return <XCircle className="h-4 w-4 text-red-600" />;
    case "needs_review":
      return <AlertTriangle className="h-4 w-4 text-yellow-600" />;
    case "not_applicable":
      return <CircleDashed className="h-4 w-4 text-muted-foreground" />;
    default:
      return <CircleHelp className="h-4 w-4 text-muted-foreground" />;
  }
}

/** Effective status = override_status when set, otherwise status. */
function effectiveStatus(a: MetiAssessment): string {
  return a.override_status && a.override_status !== ""
    ? a.override_status
    : a.status;
}

/**
 * Stringify one evidence row for inline display. evidence shape is
 * open-ended jsonb; we pick the most common keys (value / ref /
 * description) and fall back to JSON.stringify so an unknown shape
 * stays inspectable rather than silently dropped.
 */
function evidenceText(e: METIAssessmentEvidence): string {
  if (typeof e.value === "string") return e.value;
  if (typeof e.value === "number" || typeof e.value === "boolean") {
    return String(e.value);
  }
  if (typeof e.ref === "string") return e.ref;
  if (typeof e.description === "string") return e.description;
  if (e.value !== undefined) {
    try {
      return JSON.stringify(e.value);
    } catch {
      return String(e.value);
    }
  }
  return "";
}

const STATUS_OPTIONS: METIStatus[] = [
  "achieved",
  "not_achieved",
  "needs_review",
  "not_applicable",
];

export function CriterionCard({
  assessment,
  catalog,
  busy = false,
  variant = "list",
  onOverride,
  onClearOverride,
}: CriterionCardProps) {
  const t = useTranslations("METIAssessment.CriterionCard");
  const tStatus = useTranslations("METIAssessment.Status");
  const locale = useLocale();
  // Three modes: idle "view", an open override form, or an open
  // clear-override confirm form (M3 #F35). Mutually exclusive — opening
  // one closes the other so the operator never has two write forms
  // racing on the same row.
  const [mode, setMode] = useState<"view" | "override" | "clear">("view");

  const evidence = Array.isArray(assessment.evidence) ? assessment.evidence : [];
  const eff = effectiveStatus(assessment);
  const isOverridden =
    !!assessment.override_status && assessment.override_status !== "";

  // Locale-aware title / description. next-intl uses ja / en here;
  // anything else falls back to en (and then to criterion_id).
  const title =
    (locale.startsWith("ja") ? catalog?.title_ja : catalog?.title_en) ||
    catalog?.title_en ||
    catalog?.title_ja ||
    assessment.criterion_id;
  const description =
    (locale.startsWith("ja")
      ? catalog?.description_ja
      : catalog?.description_en) ||
    catalog?.description_en ||
    catalog?.description_ja ||
    "";

  // M11-3 (#78): in list-view variant, primary-PDF-verbatim titles
  // (up to ~75 chars) get truncated with a hover tooltip so the
  // accordion stays scannable. In detail-view variant the full title
  // is rendered inline. The truncation is purely a display concern;
  // the backend serves the full string.
  const titleTrunc = truncateTitle(title);
  const showTitleTooltip = variant === "list" && titleTrunc.truncated;

  return (
    <Card
      data-testid="meti-criterion-card"
      data-criterion-id={assessment.criterion_id}
      data-phase={assessment.criterion_phase}
      data-status={assessment.status}
      data-effective-status={eff}
      data-overridden={isOverridden ? "true" : "false"}
      data-variant={variant}
    >
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              {showTitleTooltip ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <CardTitle
                      className="text-base cursor-help"
                      data-testid="meti-criterion-title-truncated"
                      data-full-title={title}
                    >
                      {titleTrunc.display}
                    </CardTitle>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xl whitespace-normal break-words text-left">
                    {title}
                  </TooltipContent>
                </Tooltip>
              ) : (
                <CardTitle
                  className="text-base"
                  data-testid="meti-criterion-title"
                >
                  {variant === "detail" ? title : titleTrunc.display}
                </CardTitle>
              )}
              <code className="font-mono text-xs text-muted-foreground">
                {assessment.criterion_id}
              </code>
            </div>
            {description && (
              <p className="mt-1 text-sm text-muted-foreground whitespace-pre-line">
                {description}
              </p>
            )}
          </div>
          <div className="flex flex-col items-end gap-1">
            <Badge variant={statusVariant(eff)} className="gap-1">
              <StatusIcon status={eff} />
              {safeT(tStatus, eff)}
            </Badge>
            {isOverridden && (
              <span className="inline-flex items-center gap-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                <Edit3 className="h-3 w-3" />
                {t("overrideBadge")}
              </span>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {/* Evaluator-side fields (always shown so the operator can
            audit what the auto-evaluation decided before/after an
            override). */}
        <section className="rounded border bg-muted/30 p-2 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="text-[10px] uppercase">
              {t("evaluatorBadge")}
            </Badge>
            <span className="font-semibold">{t("originalStatusLabel")}:</span>
            <Badge variant={statusVariant(assessment.status)} className="gap-1">
              {safeT(tStatus, assessment.status)}
            </Badge>
            {assessment.evaluator_version && (
              <span className="text-muted-foreground">
                v{assessment.evaluator_version}
              </span>
            )}
            <span className="ml-auto text-muted-foreground">
              {t("evaluatedAtLabel")}: {formatTimestamp(assessment.evaluated_at)}
            </span>
          </div>
        </section>

        {/* Evidence list */}
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {t("evidenceLabel")} ({evidence.length})
          </h4>
          {evidence.length === 0 ? (
            <p className="rounded border bg-muted/20 p-2 text-xs italic text-muted-foreground">
              {t("evidenceEmpty")}
            </p>
          ) : (
            <ul
              className="space-y-1"
              data-testid="meti-evidence-list"
            >
              {evidence.map((e, idx) => {
                const txt = evidenceText(e);
                const kind = typeof e.kind === "string" ? e.kind : "unknown";
                return (
                  <li
                    key={`${kind}-${idx}`}
                    className="flex items-start gap-2 rounded border bg-muted/40 p-2 text-xs"
                  >
                    <Badge variant="outline" className="shrink-0 text-[10px]">
                      {kind}
                    </Badge>
                    {txt && (
                      <span className="break-all font-mono text-xs">{txt}</span>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        {/* Improvement action */}
        <section>
          <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {t("improvementActionLabel")}
          </h4>
          {assessment.improvement_action && assessment.improvement_action !== "" ? (
            <p
              className="rounded border border-blue-200 bg-blue-50 p-2 text-sm text-blue-900"
              data-testid="meti-improvement-action"
            >
              {assessment.improvement_action}
            </p>
          ) : (
            <p className="rounded border bg-muted/20 p-2 text-xs italic text-muted-foreground">
              {t("improvementActionEmpty")}
            </p>
          )}
        </section>

        {/* Existing override breadcrumb */}
        {isOverridden && (
          <section className="rounded border border-amber-200 bg-amber-50 p-2 text-xs text-amber-900">
            <div className="flex items-start gap-2">
              <Info className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
              <div className="space-y-1">
                <p>
                  <span className="font-semibold">
                    {t("overrideStatusLabel")}:
                  </span>{" "}
                  {safeT(tStatus, assessment.override_status ?? "")}
                </p>
                {assessment.override_by && (
                  <p>
                    <span className="font-semibold">
                      {t("overrideByLabel")}:
                    </span>{" "}
                    <code className="font-mono">
                      {assessment.override_by}
                    </code>
                    {assessment.override_at &&
                      ` (${formatTimestamp(assessment.override_at)})`}
                  </p>
                )}
                {assessment.override_note &&
                  assessment.override_note !== "" && (
                    <p>
                      <span className="font-semibold">
                        {t("overrideNoteLabel")}:
                      </span>{" "}
                      {assessment.override_note}
                    </p>
                  )}
              </div>
            </div>
          </section>
        )}

        {/* Override controls.
            M3 Codex review #F35: an overridden row USED TO disable the
            override button entirely + show a "clear-override lands in M4"
            hint. Now that DELETE /override is wired (handler.ClearOverride
            + clearOverrideCriterion api client), the disabled-state +
            stale hint are replaced by an explicit "Clear override" button
            that opens an inline confirm form. The override button itself
            stays enabled so an operator can also re-trigger the override
            form, though the server-side F31 state-machine guard returns
            409 if the operator tries to re-override without clearing
            first — that path stays a flash error so the explicit
            clear-then-reoverride workflow is preserved. */}
        {mode === "view" && (
          <div className="flex flex-wrap items-center gap-2 border-t pt-3">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setMode("override")}
              disabled={busy}
              data-testid="meti-override-trigger"
            >
              <Edit3 className="mr-1 h-4 w-4" />
              {t("overrideButton")}
            </Button>
            {isOverridden && onClearOverride && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => setMode("clear")}
                disabled={busy}
                data-testid="meti-clear-override-trigger"
              >
                {t("clearOverrideButton")}
              </Button>
            )}
          </div>
        )}

        {mode === "override" && (
          <OverrideForm
            assessment={assessment}
            disabled={busy}
            onSubmit={async (values) => {
              // The handler treats improvement_action as pointer-nullable:
              // omit (undefined) preserves the existing value, set
              // (possibly "") overwrites. The form treats blank as
              // "omit"; a single space is the explicit "clear it"
              // escape per overrideFormImprovementHint.
              const improvement: string | null | undefined =
                values.improvement_action === ""
                  ? undefined
                  : values.improvement_action;
              await onOverride(assessment, {
                override_status: values.override_status,
                override_note: values.override_note || undefined,
                improvement_action: improvement,
              });
              setMode("view");
            }}
            onCancel={() => setMode("view")}
          />
        )}

        {mode === "clear" && onClearOverride && (
          <ClearOverrideForm
            assessment={assessment}
            disabled={busy}
            onSubmit={async (values) => {
              // values.note has already been trim-validated by
              // clearOverrideSchema (1..4096 chars) — forward verbatim.
              // The page wraps clearOverrideCriterion in handleError so
              // a 400 / 404 / 409 surfaces in the flash channel without
              // taking the row out of "clear" mode silently.
              await onClearOverride(assessment, { note: values.note });
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
// Helpers
// ---------------------------------------------------------------------------

/**
 * useTranslations throws on missing keys. Status / phase / kind allow-
 * lists are stable but a backend bump could ship a new value; fall
 * back to the raw string so an unknown badge label stays inspectable.
 */
function safeT(t: (key: string) => string, key: string): string {
  if (!key) return "";
  try {
    return t(key);
  } catch {
    return key;
  }
}

/**
 * Compact timestamp — locale-aware date + 24h time. Falls back to the
 * raw ISO string when Date parsing fails so a malformed timestamp
 * stays inspectable rather than silently rendering as "Invalid Date".
 */
function formatTimestamp(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "Z");
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface OverrideFormProps {
  assessment: MetiAssessment;
  disabled?: boolean;
  onSubmit: (values: CriterionOverrideFormValues) => Promise<void> | void;
  onCancel: () => void;
}

function OverrideForm({
  assessment,
  disabled,
  onSubmit,
  onCancel,
}: OverrideFormProps) {
  const t = useTranslations("METIAssessment.CriterionCard");
  const tStatus = useTranslations("METIAssessment.Status");

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<CriterionOverrideFormValues>({
    resolver: zodResolver(overrideSchema),
    defaultValues: {
      override_status: (assessment.status as METIStatus) ?? "needs_review",
      override_note: "",
      // Blank input = "preserve existing improvement_action" per the
      // pointer-nullable handler contract.
      improvement_action: "",
    },
  });

  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      className="space-y-3 border-t pt-3"
      data-testid="meti-override-form"
    >
      <div>
        <label
          htmlFor={`override-status-${assessment.criterion_id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("overrideFormStatusLabel")}
        </label>
        <select
          id={`override-status-${assessment.criterion_id}`}
          {...register("override_status")}
          disabled={disabled || isSubmitting}
          data-testid="meti-override-status-select"
          className="w-full rounded border px-3 py-2 text-sm"
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {safeT(tStatus, s)}
            </option>
          ))}
        </select>
        {errors.override_status && (
          <p className="mt-1 text-xs text-red-600">
            {t("overrideValidationStatus")}
          </p>
        )}
      </div>

      <div>
        <label
          htmlFor={`override-note-${assessment.criterion_id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("overrideFormNoteLabel")}
        </label>
        <Textarea
          id={`override-note-${assessment.criterion_id}`}
          rows={3}
          {...register("override_note")}
          disabled={disabled || isSubmitting}
          placeholder={t("overrideFormNotePlaceholder")}
        />
        {errors.override_note && (
          <p className="mt-1 text-xs text-red-600">
            {t("overrideValidationNote")}
          </p>
        )}
      </div>

      <div>
        <label
          htmlFor={`override-improvement-${assessment.criterion_id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("overrideFormImprovementLabel")}
        </label>
        <Textarea
          id={`override-improvement-${assessment.criterion_id}`}
          rows={2}
          {...register("improvement_action")}
          disabled={disabled || isSubmitting}
          placeholder={t("overrideFormImprovementPlaceholder")}
        />
        <p className="mt-1 text-xs text-muted-foreground">
          {t("overrideFormImprovementHint")}
        </p>
      </div>

      <div className="flex gap-2">
        <Button
          type="submit"
          size="sm"
          disabled={disabled || isSubmitting}
          data-testid="meti-override-submit"
        >
          {isSubmitting ? t("overrideSubmitting") : t("overrideSubmit")}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={disabled || isSubmitting}
          onClick={onCancel}
          data-testid="meti-override-cancel"
        >
          {t("overrideCancel")}
        </Button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// ClearOverrideForm (M3 Codex review #F35)
// ---------------------------------------------------------------------------

interface ClearOverrideFormProps {
  assessment: MetiAssessment;
  disabled?: boolean;
  onSubmit: (values: CriterionClearOverrideFormValues) => Promise<void> | void;
  onCancel: () => void;
}

/**
 * Inline confirm-form for the clear-override flow. We use an inline form
 * rather than a modal so the operator can see the criterion title +
 * current override metadata while writing the clear rationale — modals
 * would hide both. The submit button stays disabled until the trimmed
 * note is at least 1 char so a probe click cannot 400 the server.
 *
 * The note placeholder explicitly tells the operator the audit
 * implications ("recorded in audit_logs") so the rationale is treated
 * as an audit artifact rather than a UI nicety. The wording mirrors
 * the F33 server-side audit_action description.
 */
function ClearOverrideForm({
  assessment,
  disabled,
  onSubmit,
  onCancel,
}: ClearOverrideFormProps) {
  const t = useTranslations("METIAssessment.CriterionCard");

  const {
    register,
    handleSubmit,
    control,
    formState: { errors, isSubmitting },
  } = useForm<CriterionClearOverrideFormValues>({
    resolver: zodResolver(clearOverrideSchema),
    defaultValues: { note: "" },
  });

  // Watch the note field so the submit button only enables once the
  // trimmed value is >= 1 char. Mirrors the server-side trim contract
  // (validateMetiOverrideNote) so the operator doesn't see a 400 from
  // a whitespace-only submission.
  //
  // M14-4 (#96, F215): migrated from `watch("note")` to useWatch so
  // the React Compiler `react-hooks/incompatible-library` rule passes
  // without an inline suppression — the previous M12-5 workaround
  // (`eslint-disable react-hooks/incompatible-library`) is no longer
  // needed. useWatch subscribes to ONLY the note field so the rest of
  // the form does not re-render on keystroke; this also makes the
  // gate lint-clean once the rule is promoted to error in M14-4.
  const noteRaw = (useWatch({ control, name: "note" }) as string | undefined) ?? "";
  const noteValid = noteRaw.trim().length >= 1;

  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      className="space-y-3 border-t pt-3"
      data-testid="meti-clear-override-form"
    >
      <p
        className="rounded border border-amber-200 bg-amber-50 p-2 text-xs text-amber-900"
        data-testid="meti-clear-override-confirm"
      >
        {t("clearOverrideConfirm")}
      </p>

      <div>
        <label
          htmlFor={`clear-override-note-${assessment.criterion_id}`}
          className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground"
        >
          {t("clearOverrideNoteLabel")}
        </label>
        <Textarea
          id={`clear-override-note-${assessment.criterion_id}`}
          rows={3}
          {...register("note")}
          disabled={disabled || isSubmitting}
          placeholder={t("clearOverrideNotePlaceholder")}
          data-testid="meti-clear-override-note"
        />
        {errors.note && (
          <p className="mt-1 text-xs text-red-600">
            {t("clearOverrideValidationNote")}
          </p>
        )}
      </div>

      <div className="flex gap-2">
        <Button
          type="submit"
          size="sm"
          variant="destructive"
          disabled={disabled || isSubmitting || !noteValid}
          data-testid="meti-clear-override-submit"
        >
          {isSubmitting ? t("overrideSubmitting") : t("clearOverrideSubmit")}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={disabled || isSubmitting}
          onClick={onCancel}
          data-testid="meti-clear-override-cancel"
        >
          {t("clearOverrideCancel")}
        </Button>
      </div>
    </form>
  );
}

export default CriterionCard;

"use client";

/**
 * METI self-assessment page (M3 Wave M3-5, issue #38).
 *
 * Renders the project's per-criterion METI ver 2.0 self-assessment as
 * a 3-phase accordion (env_setup / sbom_creation / sbom_operation), a
 * summary strip (per-status counts), filters (phase / status /
 * has_override), an "improvement actions only" toggle, a re-evaluate
 * button (POST refresh), and a manual override controls per criterion
 * card.
 *
 * Pattern lift from /cra-reports (M2-5, issue #32):
 *   - flash error queue + handleError funnel
 *   - APIError.isAIDisabled() banner — M3 is AI-free by design, but
 *     the env may still surface upstream outages; the banner stays
 *     wired for graceful degradation parity with the other AI pages
 *   - PAGE_LIMIT mirrors handler.DefaultMetiAssessmentsListLimit (100)
 *     so the matrix view receives the full 32-criterion catalog in
 *     one shot; bounds exist purely for handler F24/F27 parity
 *   - truncation banner stays wired for forward compat (catalog could
 *     grow past 100; the banner silently disappears today)
 *
 * The "改善 actions のみ" toggle calls GET /improvement-actions and
 * filters the visible matrix to the returned criterion_id set. The
 * full assessment list still drives the summary counts so an operator
 * sees the achieved / not_achieved breakdown even while the toggle is
 * on.
 *
 * Client Component: every primitive on this page is interactive.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useTranslations } from "next-intl";
import { ArrowLeft, Info, RefreshCw } from "lucide-react";

import {
  api,
  APIError,
  MetiAssessment,
  MetiAssessmentClearOverrideInput,
  MetiAssessmentListFilter,
  MetiAssessmentOverrideInput,
  METIPhase,
  Project,
} from "@/lib/api";
import { AIDisabledBanner } from "@/components/triage/ai-disabled-banner";
import { CriterionCard } from "@/components/meti/criterion-card";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface FlashError {
  id: number;
  message: string;
}

let flashIdSeq = 0;

// Mirror handler.DefaultMetiAssessmentsListLimit. The catalog ships with
// 32 criteria today so this never paginates; the bounds exist for
// forward compatibility with handler.MaxMetiAssessmentsListLimit.
const PAGE_LIMIT = 100;

const PHASE_ORDER: METIPhase[] = [
  "env_setup",
  "sbom_creation",
  "sbom_operation",
];

const PHASE_OPTIONS = ["", ...PHASE_ORDER] as const;

const STATUS_OPTIONS = [
  "",
  "achieved",
  "not_achieved",
  "needs_review",
  "not_applicable",
] as const;

const HAS_OVERRIDE_OPTIONS = ["", "true", "false"] as const;

export default function METIAssessmentPage() {
  const params = useParams();
  const projectId = params.id as string;
  const t = useTranslations("METIAssessment.Page");
  const tFilter = useTranslations("METIAssessment.Filter");
  const tPhase = useTranslations("METIAssessment.Phase");
  const tStatus = useTranslations("METIAssessment.Status");
  const tc = useTranslations("Common");

  const [project, setProject] = useState<Project | null>(null);
  const [assessments, setAssessments] = useState<MetiAssessment[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [busyCriterionId, setBusyCriterionId] = useState<string | null>(null);
  const [aiDisabledReason, setAiDisabledReason] = useState<string | null>(null);
  const [flashErrors, setFlashErrors] = useState<FlashError[]>([]);

  const [filterPhase, setFilterPhase] = useState<string>("");
  const [filterStatus, setFilterStatus] = useState<string>("");
  const [filterHasOverride, setFilterHasOverride] = useState<string>("");
  const [improvementOnly, setImprovementOnly] = useState(false);
  const [improvementCriterionIds, setImprovementCriterionIds] = useState<
    Set<string>
  >(new Set());

  const pushError = useCallback((message: string) => {
    const id = ++flashIdSeq;
    setFlashErrors((prev) => [...prev, { id, message }]);
    setTimeout(() => {
      setFlashErrors((prev) => prev.filter((f) => f.id !== id));
    }, 6000);
  }, []);

  /**
   * Funnel every mutation through here so the AIDisabledBanner can be
   * raised consistently with the triage / CRA pages — even though M3
   * itself is AI-free, an env outage may surface upstream.
   */
  const handleError = useCallback(
    (err: unknown, fallbackMessage: string) => {
      if (err instanceof APIError) {
        if (err.isAIDisabled()) {
          setAiDisabledReason(err.disabledReason() ?? err.message);
          return;
        }
        pushError(`${fallbackMessage}: ${err.message}`);
        return;
      }
      pushError(
        fallbackMessage +
          (err instanceof Error && err.message ? `: ${err.message}` : ""),
      );
    },
    [pushError],
  );

  const loadProject = useCallback(async () => {
    try {
      const data = await api.projects.get(projectId);
      setProject(data);
    } catch (err) {
      handleError(err, t("loadProjectFailed"));
    }
  }, [projectId, t, handleError]);

  const buildFilter = useCallback((): MetiAssessmentListFilter => {
    const f: MetiAssessmentListFilter = { limit: PAGE_LIMIT };
    if (filterPhase) f.phase = filterPhase;
    if (filterStatus) f.status = filterStatus;
    if (filterHasOverride === "true") f.has_override = true;
    if (filterHasOverride === "false") f.has_override = false;
    return f;
  }, [filterPhase, filterStatus, filterHasOverride]);

  const loadAssessments = useCallback(async () => {
    try {
      const res = await api.meti.getAssessment(projectId, buildFilter());
      const rows = Array.isArray(res?.assessments) ? res.assessments : [];
      setAssessments(rows);
      // Truncation banner relies on the X-Total-Count header which the
      // current envelope-only getAssessment helper does not surface
      // (see api.meti.getAssessment comment). totalCount falls back to
      // the visible count, so the banner stays dormant — and it cannot
      // trigger today anyway: the production catalog is a fixed 32
      // criteria (criteria.Registry), well under PAGE_LIMIT (100). A
      // listWithMeta-style helper becomes necessary only if the
      // catalog ever grows past PAGE_LIMIT.
      setTotalCount(rows.length);
    } catch (err) {
      handleError(err, t("loadAssessmentFailed"));
    }
  }, [projectId, buildFilter, t, handleError]);

  const loadImprovementActions = useCallback(async () => {
    try {
      const filter = filterPhase ? { phase: filterPhase } : undefined;
      const res = await api.meti.getImprovementActions(projectId, filter);
      const ids = new Set(
        (res?.actions ?? []).map((a) => a.criterion_id),
      );
      setImprovementCriterionIds(ids);
    } catch (err) {
      // Improvement-actions is a secondary surface; treat failure as
      // flash error but do not block the matrix view. The toggle just
      // shows nothing in that case.
      handleError(err, t("loadAssessmentFailed"));
      setImprovementCriterionIds(new Set());
    }
  }, [projectId, filterPhase, t, handleError]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      await Promise.all([
        loadProject(),
        loadAssessments(),
        loadImprovementActions(),
      ]);
      if (!cancelled) setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [loadProject, loadAssessments, loadImprovementActions]);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      const res = await api.meti.refreshAssessment(projectId);
      // Re-pull through the filter path so the matrix view stays
      // consistent with the active filter set (refresh returns the
      // full unfiltered fan-out).
      await loadAssessments();
      await loadImprovementActions();
      pushError(
        t("refreshSuccess", {
          count: res.refreshed,
          version: res.evaluator_version || "n/a",
        }),
      );
    } catch (err) {
      handleError(err, t("refreshFailed"));
    } finally {
      setRefreshing(false);
    }
  }, [
    projectId,
    loadAssessments,
    loadImprovementActions,
    handleError,
    pushError,
    t,
  ]);

  const handleOverride = useCallback(
    async (
      assessment: MetiAssessment,
      input: MetiAssessmentOverrideInput,
    ) => {
      setBusyCriterionId(assessment.criterion_id);
      try {
        const fresh = await api.meti.overrideCriterion(
          projectId,
          assessment.criterion_id,
          input,
        );
        // Patch the local list in place — the override response is the
        // refreshed row, so we do not need to re-fetch the full matrix.
        setAssessments((prev) =>
          prev.map((a) =>
            a.criterion_id === fresh.criterion_id ? fresh : a,
          ),
        );
        // Improvement-actions set may shift (effective_status changed).
        // Re-pull in the background so the toggle stays accurate.
        loadImprovementActions();
      } catch (err) {
        handleError(err, t("overrideFailed"));
      } finally {
        setBusyCriterionId(null);
      }
    },
    [projectId, loadImprovementActions, handleError, t],
  );

  // M3 Codex review #F35 — clear-override wire-up. The card validates
  // the note (zod: trim then 1..4096 chars) before calling this, so a
  // failed validation never reaches the server. Failures returned by
  // the server (400/404/409 from the F33 state-machine guard / TOCTOU /
  // missing-override path) are funneled through handleError so the
  // operator sees a flash and the row stays in clear-mode for retry.
  const tCard = useTranslations("METIAssessment.CriterionCard");
  const handleClearOverride = useCallback(
    async (
      assessment: MetiAssessment,
      input: MetiAssessmentClearOverrideInput,
    ) => {
      setBusyCriterionId(assessment.criterion_id);
      try {
        const fresh = await api.meti.clearOverrideCriterion(
          projectId,
          assessment.criterion_id,
          input,
        );
        // Same in-place patch path as handleOverride. After a clear,
        // override_* are nulled and `effectiveStatus` falls back to
        // `status`, so the card immediately re-renders without the
        // override badge.
        setAssessments((prev) =>
          prev.map((a) =>
            a.criterion_id === fresh.criterion_id ? fresh : a,
          ),
        );
        // Re-pull improvement-actions: an `achieved` override that just
        // got cleared could resurface as a `not_achieved` evaluator
        // verdict (or vice versa).
        loadImprovementActions();
      } catch (err) {
        handleError(err, tCard("clearOverrideFailed"));
      } finally {
        setBusyCriterionId(null);
      }
    },
    [projectId, loadImprovementActions, handleError, tCard],
  );

  // Per-status / phase counts. Status counts use the EFFECTIVE status
  // (operator override wins) to match what the dashboard reports.
  const summary = useMemo(() => {
    const counts = {
      achieved: 0,
      not_achieved: 0,
      needs_review: 0,
      not_applicable: 0,
      overridden: 0,
    };
    for (const a of assessments) {
      const eff =
        a.override_status && a.override_status !== ""
          ? a.override_status
          : a.status;
      if (eff === "achieved") counts.achieved++;
      else if (eff === "not_achieved") counts.not_achieved++;
      else if (eff === "needs_review") counts.needs_review++;
      else if (eff === "not_applicable") counts.not_applicable++;
      if (a.override_status && a.override_status !== "") counts.overridden++;
    }
    return counts;
  }, [assessments]);

  const visibleAssessments = useMemo(() => {
    if (!improvementOnly) return assessments;
    return assessments.filter((a) =>
      improvementCriterionIds.has(a.criterion_id),
    );
  }, [assessments, improvementOnly, improvementCriterionIds]);

  // Group visible rows into phases for the accordion. Sort within each
  // phase by criterion_id for deterministic rendering — matches the
  // evaluator_test.go invariant.
  const grouped = useMemo(() => {
    const map = new Map<METIPhase, MetiAssessment[]>();
    for (const phase of PHASE_ORDER) map.set(phase, []);
    for (const a of visibleAssessments) {
      const phase = a.criterion_phase as METIPhase;
      if (!map.has(phase)) map.set(phase, []);
      map.get(phase)!.push(a);
    }
    for (const list of map.values()) {
      list.sort((x, y) =>
        x.criterion_id.localeCompare(y.criterion_id, "en"),
      );
    }
    return map;
  }, [visibleAssessments]);

  const truncated = totalCount > assessments.length;

  return (
    <div data-testid="meti-assessment-page">
      <div className="mb-6">
        <Link
          href={`/projects/${projectId}`}
          className="mb-2 inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="mr-1 h-4 w-4" />
          {t("backToProject")}
        </Link>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold">{t("title")}</h1>
            <p className="text-muted-foreground">
              {project ? project.name : ""}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {t("description", { total: assessments.length || 27 })}
            </p>
          </div>
          <Button
            variant="outline"
            onClick={handleRefresh}
            disabled={refreshing || loading}
            data-testid="meti-refresh"
          >
            <RefreshCw
              className={`mr-1 h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
            />
            {refreshing ? t("refreshing") : t("refresh")}
          </Button>
        </div>
      </div>

      {aiDisabledReason !== null && (
        <AIDisabledBanner reason={aiDisabledReason || undefined} />
      )}

      {/* Summary strip */}
      {assessments.length > 0 && (
        <Card className="mb-4" data-testid="meti-summary">
          <CardContent className="flex flex-wrap items-center gap-2 py-3">
            <Badge variant="default" className="gap-1">
              {t("summaryAchieved", { count: summary.achieved })}
            </Badge>
            <Badge variant="destructive" className="gap-1">
              {t("summaryNotAchieved", { count: summary.not_achieved })}
            </Badge>
            <Badge variant="medium" className="gap-1">
              {t("summaryNeedsReview", { count: summary.needs_review })}
            </Badge>
            <Badge variant="outline" className="gap-1">
              {t("summaryNotApplicable", { count: summary.not_applicable })}
            </Badge>
            <Badge variant="secondary" className="gap-1">
              {t("summaryOverridden", { count: summary.overridden })}
            </Badge>
            <div className="flex-1" />
            <label
              className="inline-flex cursor-pointer items-center gap-2 text-sm"
              data-testid="meti-improvement-toggle-label"
            >
              <input
                type="checkbox"
                checked={improvementOnly}
                onChange={(e) => setImprovementOnly(e.target.checked)}
                data-testid="meti-improvement-toggle"
                className="h-4 w-4"
              />
              {t("improvementOnlyToggle")}
              <span className="text-xs text-muted-foreground">
                ({t("improvementCount", { count: improvementCriterionIds.size })})
              </span>
            </label>
          </CardContent>
        </Card>
      )}

      {/* Filter row */}
      <Card className="mb-4" data-testid="meti-filters">
        <CardHeader>
          <CardTitle className="text-sm">{tFilter("title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <FilterSelect
              testid="filter-phase"
              label={tFilter("phase")}
              value={filterPhase}
              onChange={setFilterPhase}
              options={PHASE_OPTIONS as readonly string[]}
              renderOption={(v) => (v === "" ? tFilter("any") : safeT(tPhase, v))}
            />
            <FilterSelect
              testid="filter-status"
              label={tFilter("status")}
              value={filterStatus}
              onChange={setFilterStatus}
              options={STATUS_OPTIONS as readonly string[]}
              renderOption={(v) => (v === "" ? tFilter("any") : safeT(tStatus, v))}
            />
            <FilterSelect
              testid="filter-has-override"
              label={tFilter("hasOverride")}
              value={filterHasOverride}
              onChange={setFilterHasOverride}
              options={HAS_OVERRIDE_OPTIONS as readonly string[]}
              renderOption={(v) =>
                v === ""
                  ? tFilter("any")
                  : v === "true"
                    ? tFilter("overrideOnly")
                    : tFilter("noOverride")
              }
            />
          </div>
        </CardContent>
      </Card>

      {flashErrors.length > 0 && (
        <div className="mb-4 space-y-2" data-testid="meti-flash-errors">
          {flashErrors.map((e) => (
            <div
              key={e.id}
              role="alert"
              className="rounded border border-blue-300 bg-blue-50 px-3 py-2 text-sm text-blue-900"
            >
              {e.message}
            </div>
          ))}
        </div>
      )}

      {/* Dormant truncation banner — see PAGE_LIMIT note above. */}
      {truncated && (
        <div
          role="alert"
          data-testid="meti-truncation-banner"
          className="mb-4 flex items-start gap-2 rounded border border-yellow-300 bg-yellow-50 px-3 py-2 text-sm text-yellow-900"
        >
          <Info className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <span>
            Showing {assessments.length} of {totalCount} criteria.
          </span>
        </div>
      )}

      {loading ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          {tc("loading")}
        </div>
      ) : assessments.length === 0 ? (
        <Card data-testid="meti-empty-state">
          <CardHeader>
            <CardTitle>{t("emptyTitle")}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">{t("emptyDescription")}</p>
          </CardContent>
        </Card>
      ) : (
        <Accordion
          type="multiple"
          defaultValue={[...PHASE_ORDER]}
          data-testid="meti-phase-accordion"
        >
          {PHASE_ORDER.map((phase) => {
            const rows = grouped.get(phase) ?? [];
            return (
              <AccordionItem
                key={phase}
                value={phase}
                data-testid={`meti-phase-${phase}`}
              >
                <AccordionTrigger className="text-left">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="text-base font-semibold">
                      {safeT(tPhase, phase)}
                    </span>
                    <Badge variant="outline" className="text-xs">
                      {rows.length}
                    </Badge>
                  </span>
                </AccordionTrigger>
                <AccordionContent>
                  {rows.length === 0 ? (
                    <p className="px-1 py-2 text-sm italic text-muted-foreground">
                      {improvementOnly
                        ? t("improvementCount", { count: 0 })
                        : t("emptyDescription")}
                    </p>
                  ) : (
                    <div className="space-y-3" data-testid={`meti-list-${phase}`}>
                      {rows.map((a) => (
                        <CriterionCard
                          key={a.criterion_id}
                          assessment={a}
                          busy={busyCriterionId === a.criterion_id}
                          onOverride={handleOverride}
                          onClearOverride={handleClearOverride}
                        />
                      ))}
                    </div>
                  )}
                </AccordionContent>
              </AccordionItem>
            );
          })}
        </Accordion>
      )}
    </div>
  );
}

interface FilterSelectProps {
  testid: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: readonly string[];
  renderOption: (v: string) => string;
}

function FilterSelect({
  testid,
  label,
  value,
  onChange,
  options,
  renderOption,
}: FilterSelectProps) {
  return (
    <div>
      <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </label>
      <select
        data-testid={testid}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded border px-3 py-2 text-sm"
      >
        {options.map((o) => (
          <option key={o || "any"} value={o}>
            {renderOption(o)}
          </option>
        ))}
      </select>
    </div>
  );
}

/**
 * useTranslations throws on missing keys; the backend allow-lists are
 * stable but a schema bump should not crash the page. Fall back to the
 * raw value so unknown badges stay inspectable.
 */
function safeT(t: (key: string) => string, key: string): string {
  if (!key) return "";
  try {
    return t(key);
  } catch {
    return key;
  }
}


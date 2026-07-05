"use client";

/**
 * CRA reports page — AI report drafting queue for one project (issue
 * #32, M2 Wave M2-5).
 *
 * Lists cra_reports with optional filters (report_type / lang / state /
 * decision), renders ReportCard per row, and dispatches Approve /
 * Edit / Reject / Re-analyse to the Wave M2-4 endpoints
 * (apps/api/internal/handler/cra_reports.go).
 *
 * Pattern lift from /triage (M1-6, issue #28):
 *   - AI-disabled banner gating via APIError.isAIDisabled() (LLM_PROVIDER_DESIGN.md §4.1)
 *   - optimistic update — drop the decided row immediately, re-fetch on
 *     failure
 *   - evidence-less rows hidden client-side as defense-in-depth on top
 *     of the DB CHECK + runner ValidateEvidence (M1 #F4)
 *   - X-Total-Count truncation banner (M1 #F28) — the CRA queue page
 *     keeps the same banner shape as Vulnerabilities, so an operator
 *     who has internalised the M1 UX does not have to relearn it
 *
 * Client Component: every primitive in this page is interactive
 * (filter dropdowns, mutations, optimistic state).
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useTranslations } from "next-intl";
import { ArrowLeft, RefreshCw, Info } from "lucide-react";

import {
  api,
  APIError,
  CRAReport,
  CRAReportDecisionInput,
  CRAReportListFilter,
  CRASubmission,
  CRASubmissionInput,
  Project,
} from "@/lib/api";
import { AIDisabledBanner } from "@/components/triage/ai-disabled-banner";
import {
  ReportCard,
  ReportEditFormValues,
  ReportSubmitFormValues,
} from "@/components/cra-reports/report-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface FlashError {
  id: number;
  message: string;
}

let flashIdSeq = 0;

// Mirror the handler-side default (DefaultCRAReportsListLimit=100 in
// apps/api/internal/handler/cra_reports.go). The truncation banner
// triggers when totalCount > pageLimit. No API surfaces the server-side
// constant, so this mirror is pinned by hand; if the two drift the
// banner threshold desyncs, but the server clamps requests to
// MaxCRAReportsListLimit (500) regardless.
const PAGE_LIMIT = 100;

const REPORT_TYPE_OPTIONS = [
  "",
  "early_warning",
  "detailed_notification",
  "final_report",
] as const;

const LANG_OPTIONS = ["", "ja", "en"] as const;

const STATE_OPTIONS = [
  "",
  "draft",
  "approved",
  "submitted",
  "archived",
] as const;

const DECISION_OPTIONS = [
  "",
  "pending",
  "approved",
  "edited",
  "rejected",
] as const;

export default function CRAReportsPage() {
  const params = useParams();
  const projectId = params.id as string;
  const t = useTranslations("CRAReports.Page");
  const tFilter = useTranslations("CRAReports.Filter");
  const tType = useTranslations("CRAReports.ReportType");
  const tLang = useTranslations("CRAReports.Lang");
  const tState = useTranslations("CRAReports.State");
  const tDecision = useTranslations("CRAReports.Decision");
  const tc = useTranslations("Common");

  const [project, setProject] = useState<Project | null>(null);
  const [reports, setReports] = useState<CRAReport[]>([]);
  // Submission timelines keyed by report id. Fetched lazily for approved
  // reports only (non-approved reports cannot carry submissions — the
  // backend rejects them with 409).
  const [submissionsByReport, setSubmissionsByReport] = useState<
    Record<string, CRASubmission[]>
  >({});
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [busyReportId, setBusyReportId] = useState<string | null>(null);
  const [aiDisabledReason, setAiDisabledReason] = useState<string | null>(null);
  const [flashErrors, setFlashErrors] = useState<FlashError[]>([]);

  const [filterReportType, setFilterReportType] = useState<string>("");
  const [filterLang, setFilterLang] = useState<string>("");
  const [filterState, setFilterState] = useState<string>("");
  const [filterDecision, setFilterDecision] = useState<string>("");

  const pushError = useCallback((message: string) => {
    const id = ++flashIdSeq;
    setFlashErrors((prev) => [...prev, { id, message }]);
    setTimeout(() => {
      setFlashErrors((prev) => prev.filter((f) => f.id !== id));
    }, 6000);
  }, []);

  /**
   * Centralised error handler — every CRA mutation funnels here so the
   * AIDisabledBanner can be raised consistently. Mirrors the triage
   * page's handleError shape.
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

  const buildFilter = useCallback((): CRAReportListFilter => {
    const f: CRAReportListFilter = { limit: PAGE_LIMIT };
    if (filterReportType) f.report_type = filterReportType;
    if (filterLang) f.lang = filterLang;
    if (filterState) f.state = filterState;
    if (filterDecision)
      f.decision = filterDecision as CRAReportListFilter["decision"];
    return f;
  }, [filterReportType, filterLang, filterState, filterDecision]);

  /**
   * Fetch submission timelines for the approved reports in the current
   * page and merge them into submissionsByReport. Best-effort: a per-report
   * failure is swallowed (the timeline just stays empty) so one bad row does
   * not blank the whole queue. Only approved reports are queried since the
   * backend guarantees no submissions exist for any other decision.
   */
  const loadSubmissions = useCallback(
    async (rows: CRAReport[]) => {
      const approved = rows.filter((r) => r.decision === "approved");
      if (approved.length === 0) return;
      const results = await Promise.all(
        approved.map(async (r) => {
          try {
            const subs = await api.craSubmissions.list(projectId, r.id);
            return [r.id, subs] as const;
          } catch {
            return [r.id, [] as CRASubmission[]] as const;
          }
        }),
      );
      setSubmissionsByReport((prev) => {
        const next = { ...prev };
        for (const [id, subs] of results) next[id] = subs;
        return next;
      });
    },
    [projectId],
  );

  const loadReports = useCallback(async () => {
    try {
      const res = await api.craReports.listWithMeta(projectId, buildFilter());
      setReports(res.data);
      setTotalCount(res.totalCount);
      // Fire-and-forget: populate submission timelines for approved rows.
      void loadSubmissions(res.data);
    } catch (err) {
      handleError(err, t("loadReportsFailed"));
    }
  }, [projectId, buildFilter, t, handleError, loadSubmissions]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      await Promise.all([loadProject(), loadReports()]);
      if (!cancelled) setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [loadProject, loadReports]);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await loadReports();
    } finally {
      setRefreshing(false);
    }
  }, [loadReports]);

  /**
   * Optimistic update: drop the report from the visible list
   * immediately, then call the API. On failure re-fetch so the row
   * reappears in its real state (mirrors triage page's
   * decideOptimistically).
   */
  const decideOptimistically = useCallback(
    async (
      report: CRAReport,
      input: CRAReportDecisionInput,
      errorKey: string,
    ) => {
      setBusyReportId(report.id);
      const previous = reports;
      const previousTotal = totalCount;
      setReports((prev) => prev.filter((r) => r.id !== report.id));
      setTotalCount((n) => Math.max(0, n - 1));
      try {
        await api.craReports.decide(projectId, report.id, input);
        // background refresh so e.g. server-side state mutations land
        loadReports();
      } catch (err) {
        setReports(previous);
        setTotalCount(previousTotal);
        handleError(err, t(errorKey));
      } finally {
        setBusyReportId(null);
      }
    },
    [reports, totalCount, projectId, loadReports, handleError, t],
  );

  const handleApprove = useCallback(
    (report: CRAReport, note?: string) =>
      decideOptimistically(
        report,
        { decision: "approved", decision_note: note },
        "approveFailed",
      ),
    [decideOptimistically],
  );

  const handleEdit = useCallback(
    (report: CRAReport, values: ReportEditFormValues) =>
      decideOptimistically(
        report,
        {
          decision: "edited",
          decision_note: values.decision_note || undefined,
          edited_draft_text: values.draft_text,
        },
        "editFailed",
      ),
    [decideOptimistically],
  );

  const handleReject = useCallback(
    (report: CRAReport, note?: string) =>
      decideOptimistically(
        report,
        { decision: "rejected", decision_note: note },
        "rejectFailed",
      ),
    [decideOptimistically],
  );

  const handleReanalyse = useCallback(
    async (report: CRAReport) => {
      setBusyReportId(report.id);
      try {
        await api.craReports.reanalyse(projectId, report.id);
        // Reanalyse creates a NEW cra_reports row; refresh so the
        // newcomer shows up and the source row's age stamps move down.
        await loadReports();
      } catch (err) {
        handleError(err, t("reanalyseFailed"));
      } finally {
        setBusyReportId(null);
      }
    },
    [projectId, loadReports, handleError, t],
  );

  /**
   * Set / edit / clear a report's awareness_time (Art.14 clock start, M35).
   * Non-optimistic (mirrors handleReanalyse, not decideOptimistically): an
   * awareness edit never removes the row from any pending list, so we just
   * PATCH and refetch. The server recomputes deadline_status/deadline_at on
   * read (M34 compute-on-read), so loadReports() lands the recomputed verdict
   * along with the new awareness_time. Pass null to clear (unset to NULL).
   */
  const handleSetAwareness = useCallback(
    async (report: CRAReport, awarenessTime: string | null) => {
      setBusyReportId(report.id);
      try {
        await api.craReports.awareness(projectId, report.id, awarenessTime);
        await loadReports();
      } catch (err) {
        handleError(err, t("setAwarenessFailed"));
      } finally {
        setBusyReportId(null);
      }
    },
    [projectId, loadReports, handleError, t],
  );

  /**
   * Record a human-attested submission to an authority. On success the row
   * is optimistically flipped to state='submitted' (mirroring the backend's
   * one-tx side-effect) and the created submission is prepended to the
   * report's timeline, then a background refresh reconciles with the server.
   * On failure the optimistic state change is rolled back.
   */
  const handleRecordSubmission = useCallback(
    async (report: CRAReport, values: ReportSubmitFormValues) => {
      setBusyReportId(report.id);

      const input: CRASubmissionInput = { authority: values.authority };
      if (values.submitted_at) {
        // <input type="datetime-local"> yields a local, zoneless string;
        // normalise to RFC3339 UTC for the frozen contract. Omit on parse
        // failure so the server falls back to NOW().
        const parsed = new Date(values.submitted_at);
        if (!Number.isNaN(parsed.getTime())) {
          input.submitted_at = parsed.toISOString();
        }
      }
      if (values.reference_number)
        input.reference_number = values.reference_number;
      if (values.notes) input.notes = values.notes;

      const previous = reports;
      setReports((prev) =>
        prev.map((r) =>
          r.id === report.id ? { ...r, state: "submitted" } : r,
        ),
      );
      try {
        const created = await api.craSubmissions.record(
          projectId,
          report.id,
          input,
        );
        setSubmissionsByReport((prev) => ({
          ...prev,
          [report.id]: [created, ...(prev[report.id] ?? [])],
        }));
        // Background reconcile so the authoritative state lands.
        loadReports();
      } catch (err) {
        setReports(previous);
        handleError(err, t("recordSubmissionFailed"));
      } finally {
        setBusyReportId(null);
      }
    },
    [reports, projectId, loadReports, handleError, t],
  );

  // F4 carry-over: drop evidence-less reports from the visible queue,
  // surface a count of hidden rows so an operator can investigate.
  const visibleReports = useMemo(
    () =>
      reports.filter((r) => Array.isArray(r.evidence) && r.evidence.length > 0),
    [reports],
  );
  const hiddenCount = reports.length - visibleReports.length;
  const truncated = totalCount > reports.length;

  return (
    <div data-testid="cra-reports-page">
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
              {t("description")}
            </p>
          </div>
          <Button
            variant="outline"
            onClick={handleRefresh}
            disabled={refreshing || loading}
            data-testid="cra-reports-refresh"
          >
            <RefreshCw
              className={`mr-1 h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
            />
            {t("refresh")}
          </Button>
        </div>
      </div>

      {aiDisabledReason !== null && (
        <AIDisabledBanner reason={aiDisabledReason || undefined} />
      )}

      {/* Filter row — plain <select>s mirror the M1 DraftCard edit-form
          pattern so we do not pull in the shadcn Select primitive's
          context for what is otherwise a simple controlled dropdown. */}
      <Card className="mb-4" data-testid="cra-reports-filters">
        <CardHeader>
          <CardTitle className="text-sm">{tFilter("title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <FilterSelect
              testid="filter-report-type"
              label={tFilter("reportType")}
              value={filterReportType}
              onChange={setFilterReportType}
              options={REPORT_TYPE_OPTIONS as readonly string[]}
              renderOption={(v) => (v === "" ? tFilter("any") : safeT(tType, v))}
            />
            <FilterSelect
              testid="filter-lang"
              label={tFilter("lang")}
              value={filterLang}
              onChange={setFilterLang}
              options={LANG_OPTIONS as readonly string[]}
              renderOption={(v) => (v === "" ? tFilter("any") : safeT(tLang, v))}
            />
            <FilterSelect
              testid="filter-state"
              label={tFilter("state")}
              value={filterState}
              onChange={setFilterState}
              options={STATE_OPTIONS as readonly string[]}
              renderOption={(v) => (v === "" ? tFilter("any") : safeT(tState, v))}
            />
            <FilterSelect
              testid="filter-decision"
              label={tFilter("decision")}
              value={filterDecision}
              onChange={setFilterDecision}
              options={DECISION_OPTIONS as readonly string[]}
              renderOption={(v) =>
                v === "" ? tFilter("any") : safeT(tDecision, v)
              }
            />
          </div>
        </CardContent>
      </Card>

      {flashErrors.length > 0 && (
        <div className="mb-4 space-y-2" data-testid="cra-reports-flash-errors">
          {flashErrors.map((e) => (
            <div
              key={e.id}
              role="alert"
              className="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700"
            >
              {e.message}
            </div>
          ))}
        </div>
      )}

      {/* F28 carry-over: "more results than fit in one page" banner.
          The server-side total comes from the X-Total-Count header
          (handler/cra_reports.go.ListReports). When the header is
          absent (older API / CORS), listWithMeta() falls back to
          reports.length and this banner silently disappears, which is
          the visible regression signal. */}
      {truncated && (
        <div
          role="alert"
          data-testid="cra-reports-truncation-banner"
          className="mb-4 flex items-start gap-2 rounded border border-yellow-300 bg-yellow-50 px-3 py-2 text-sm text-yellow-900"
        >
          <Info className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <span>
            {t("truncated", {
              visible: reports.length,
              total: totalCount,
            })}
          </span>
        </div>
      )}

      {loading ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          {tc("loading")}
        </div>
      ) : visibleReports.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("emptyTitle")}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">{t("emptyDescription")}</p>
            {hiddenCount > 0 && (
              <p className="mt-2 text-xs text-yellow-700">
                {t("hiddenEvidenceless", { count: hiddenCount })}
              </p>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4" data-testid="cra-reports-list">
          {hiddenCount > 0 && (
            <p className="text-xs text-yellow-700">
              {t("hiddenEvidenceless", { count: hiddenCount })}
            </p>
          )}
          {visibleReports.map((report) => (
            <ReportCard
              key={report.id}
              report={report}
              projectId={projectId}
              busy={busyReportId === report.id}
              submissions={submissionsByReport[report.id] ?? []}
              onApprove={handleApprove}
              onEdit={handleEdit}
              onReject={handleReject}
              onReanalyse={handleReanalyse}
              onSetAwareness={handleSetAwareness}
              onRecordSubmission={handleRecordSubmission}
            />
          ))}
        </div>
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
 * useTranslations throws on missing keys; backend allow-list values are
 * stable but a future schema bump should not crash the queue. Fall
 * back to the raw string so unknown values stay inspectable.
 */
function safeT(t: (key: string) => string, key: string): string {
  try {
    return t(key);
  } catch {
    return key;
  }
}

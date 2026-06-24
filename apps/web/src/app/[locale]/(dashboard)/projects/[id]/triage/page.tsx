"use client";

/**
 * Triage page — AI VEX draft queue for one project (issue #28, M1 Wave M1-6).
 *
 * Lists vex_drafts with decision=pending, renders DraftCard per row, and
 * dispatches Approve / Edit / Reject / Re-analyse to the Wave M1-5 endpoints
 * (apps/api/internal/handler/vex_drafts.go). Optimistic update: drafts are
 * removed from the list immediately on a successful decision; a hard refresh
 * runs at the end so the page reflects any out-of-band changes.
 *
 * BYOK gate: any APIError whose body matches llm.DisabledError surfaces the
 * AIDisabledBanner with the backend-supplied reason (LLM_PROVIDER_DESIGN.md
 * §4.1). The banner is sticky for the rest of the session — until the
 * operator configures a provider in /settings/llm the buttons here all fail
 * with 503.
 *
 * Client Component: this whole page is interactive (forms, mutations,
 * optimistic state). Server-rendering it would still hydrate immediately
 * since every primitive section needs onClick/onChange.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useTranslations } from "next-intl";
import { ArrowLeft, RefreshCw } from "lucide-react";

import {
  api,
  APIError,
  Project,
  VexDraft,
  VexDraftDecisionInput,
} from "@/lib/api";
import { AIDisabledBanner } from "@/components/triage/ai-disabled-banner";
import { DraftCard, EditFormValues } from "@/components/triage/draft-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface FlashError {
  id: number;
  message: string;
}

let flashIdSeq = 0;

export default function TriagePage() {
  const params = useParams();
  const projectId = params.id as string;
  const t = useTranslations("Triage.Page");
  const tc = useTranslations("Common");

  const [project, setProject] = useState<Project | null>(null);
  const [drafts, setDrafts] = useState<VexDraft[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [busyDraftId, setBusyDraftId] = useState<string | null>(null);
  const [aiDisabledReason, setAiDisabledReason] = useState<string | null>(null);
  const [flashErrors, setFlashErrors] = useState<FlashError[]>([]);

  /** Push a transient toast-style error message. */
  const pushError = useCallback((message: string) => {
    const id = ++flashIdSeq;
    setFlashErrors((prev) => [...prev, { id, message }]);
    setTimeout(() => {
      setFlashErrors((prev) => prev.filter((f) => f.id !== id));
    }, 6000);
  }, []);

  /**
   * Centralised error handler — every triage mutation funnels here so the
   * AIDisabledBanner can be raised consistently and other errors land in a
   * single flash channel.
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
          (err instanceof Error && err.message ? `: ${err.message}` : "")
      );
    },
    [pushError]
  );

  const loadProject = useCallback(async () => {
    try {
      const data = await api.projects.get(projectId);
      setProject(data);
    } catch (err) {
      handleError(err, t("loadProjectFailed"));
    }
  }, [projectId, t, handleError]);

  const loadDrafts = useCallback(async () => {
    try {
      const res = await api.triage.listDrafts(projectId, { decision: "pending" });
      setDrafts(res.drafts ?? []);
    } catch (err) {
      handleError(err, t("loadDraftsFailed"));
    }
  }, [projectId, t, handleError]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      await Promise.all([loadProject(), loadDrafts()]);
      if (!cancelled) setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [loadProject, loadDrafts]);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await loadDrafts();
    } finally {
      setRefreshing(false);
    }
  }, [loadDrafts]);

  /**
   * Optimistic update: drop the draft from the pending list immediately, then
   * call the API. On failure, re-fetch so the row reappears in its real
   * state.
   */
  const decideOptimistically = useCallback(
    async (draft: VexDraft, input: VexDraftDecisionInput, errorKey: string) => {
      setBusyDraftId(draft.ID);
      const previous = drafts;
      setDrafts((prev) => prev.filter((d) => d.ID !== draft.ID));
      try {
        await api.triage.decide(projectId, draft.ID, input);
        // success — leave the optimistic state and trigger a background
        // refresh so e.g. confidence threshold changes show up.
        loadDrafts();
      } catch (err) {
        setDrafts(previous);
        handleError(err, t(errorKey));
      } finally {
        setBusyDraftId(null);
      }
    },
    [drafts, projectId, loadDrafts, handleError, t]
  );

  const handleApprove = useCallback(
    (draft: VexDraft, note?: string) =>
      decideOptimistically(
        draft,
        { decision: "approved", note },
        "approveFailed"
      ),
    [decideOptimistically]
  );

  const handleEdit = useCallback(
    (draft: VexDraft, values: EditFormValues) =>
      decideOptimistically(
        draft,
        {
          decision: "edited",
          edited_state: values.state,
          edited_justification: values.justification || undefined,
          edited_detail: values.detail || undefined,
          note: values.note || undefined,
        },
        "editFailed"
      ),
    [decideOptimistically]
  );

  const handleReject = useCallback(
    (draft: VexDraft, note?: string) =>
      decideOptimistically(
        draft,
        { decision: "rejected", note },
        "rejectFailed"
      ),
    [decideOptimistically]
  );

  const handleReanalyse = useCallback(
    async (draft: VexDraft) => {
      setBusyDraftId(draft.ID);
      try {
        await api.triage.reanalyse(projectId, draft.ID);
        // Reanalyse creates a *new* draft row — refresh so the new one shows
        // up and the old row's age stamp moves down the queue.
        await loadDrafts();
      } catch (err) {
        handleError(err, t("reanalyseFailed"));
      } finally {
        setBusyDraftId(null);
      }
    },
    [projectId, loadDrafts, handleError, t]
  );

  // Render evidence-less drafts as nothing (DraftCard does the actual guard);
  // surface a count of hidden rows so an operator can investigate.
  const visibleDrafts = useMemo(
    () => drafts.filter((d) => Array.isArray(d.Evidence) && d.Evidence.length > 0),
    [drafts]
  );
  const hiddenCount = drafts.length - visibleDrafts.length;

  return (
    <div data-testid="triage-page">
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
            data-testid="triage-refresh"
          >
            <RefreshCw className={`mr-1 h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
            {t("refresh")}
          </Button>
        </div>
      </div>

      {aiDisabledReason !== null && (
        <AIDisabledBanner reason={aiDisabledReason || undefined} />
      )}

      {flashErrors.length > 0 && (
        <div className="mb-4 space-y-2" data-testid="triage-flash-errors">
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

      {loading ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          {tc("loading")}
        </div>
      ) : visibleDrafts.length === 0 ? (
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
        <div className="space-y-4" data-testid="triage-draft-list">
          {hiddenCount > 0 && (
            <p className="text-xs text-yellow-700">
              {t("hiddenEvidenceless", { count: hiddenCount })}
            </p>
          )}
          {visibleDrafts.map((draft) => (
            <DraftCard
              key={draft.ID}
              draft={draft}
              busy={busyDraftId === draft.ID}
              onApprove={handleApprove}
              onEdit={handleEdit}
              onReject={handleReject}
              onReanalyse={handleReanalyse}
            />
          ))}
        </div>
      )}
    </div>
  );
}

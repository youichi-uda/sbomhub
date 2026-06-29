"use client";

/**
 * SBOM Diff page — M10-6 (#74).
 *
 * Surfaces the supply-chain churn observability stream for one project.
 * Two modes:
 *
 *   1. Timeline (default, no query string):
 *      lists every SBOM ingest newest-first, with diff badges against
 *      the previous SBOM (components added/removed/version_changed +
 *      vulnerabilities added/resolved + license violations added).
 *
 *   2. Detail (?from=<sbom_id>&to=<sbom_id>):
 *      three panels — components / vulnerabilities / licenses — each
 *      with the three sub-sections from the backend response shape.
 *
 * Both modes hit GET /api/v1/projects/:id/diff. The endpoint applies the
 * defaulting rules documented in apps/api/internal/service/diff/diff.go
 * (newest-two when no params, baseline when one SBOM exists, etc.).
 *
 * No AI is involved here — the diff is a mechanical comparison.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";
import Link from "next/link";
import { useTranslations, useLocale } from "next-intl";
import { ArrowLeft, GitCompareArrows } from "lucide-react";

import {
  api,
  ProjectDiffResponse,
  ProjectDiffComponentChange,
  ProjectDiffComponentVersionChange,
  ProjectDiffVulnerabilityAdded,
  ProjectDiffVulnerabilityResolved,
  ProjectDiffVulnerabilitySeverityChange,
  ProjectDiffLicenseViolation,
  Sbom,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AiSummaryPanel } from "@/components/diff/ai-summary";
import { ExportButtons } from "@/components/diff/export-buttons";
import { buildDiffQuery, normaliseSeverity } from "./diff-helpers";

// M10-6 #74 + Phase D F164 + M11-1 #76: the CI playwright run on
// commit d6f759c surfaced "Application error: a client-side exception
// has occurred while loading localhost" (heading level=2) in place of
// the timeline h1 (level=1). Root cause isolated in M11-1: the Go
// backend marshals a nil `[]LicensePolicyViolation` slice as JSON
// `null`, but the TypeScript ProjectDiffResponse declares each bucket
// as a non-nullable array. The `useMemo` below calls
// `diff.licenses.added_policy_violations.length` unconditionally,
// which throws TypeError on `null` at hydration and trips the
// generic Next.js error boundary. Fix lives in
// apps/web/src/lib/api.ts::api.projects.getDiff — it normalises every
// bucket to `[]` before returning, so this page can keep the
// invariant the type promises. The speculative Suspense wrap from
// commit e701737 (reverted in 957e6d2) was a red herring: useSearchParams
// in Next.js 15+ does not need an extra boundary when the parent route
// is already dynamic (`/<locale>/projects/<id>/diff` is server-rendered
// on demand per `next build` output).
export default function ProjectDiffPage() {
  const params = useParams();
  const searchParams = useSearchParams();
  const locale = useLocale();
  const projectId = params.id as string;

  const t = useTranslations("SbomDiff.Page");
  const tTimeline = useTranslations("SbomDiff.Timeline");
  const tDetail = useTranslations("SbomDiff.Detail");
  const tc = useTranslations("Common");

  const from = searchParams.get("from") ?? undefined;
  const to = searchParams.get("to") ?? undefined;
  const detailMode = Boolean(from || to);

  // Timeline mode state.
  const [sboms, setSboms] = useState<Sbom[]>([]);
  const [timelineDiffs, setTimelineDiffs] = useState<
    Record<string, ProjectDiffResponse>
  >({});
  const [sbomsLoading, setSbomsLoading] = useState(true);
  const [sbomsError, setSbomsError] = useState<string | null>(null);

  // Detail mode state.
  const [detail, setDetail] = useState<ProjectDiffResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>("components");

  // Load the SBOM list once for the timeline. Detail mode also benefits
  // from it (for the back-to-timeline navigation).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      setSbomsLoading(true);
      try {
        const list = await api.projects.getSboms(projectId);
        if (cancelled) return;
        setSboms(list ?? []);
      } catch (err) {
        if (cancelled) return;
        setSbomsError(
          err instanceof Error ? err.message : t("loadFailed"),
        );
      } finally {
        if (!cancelled) setSbomsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [projectId, t]);

  // Detail mode: fetch the diff for the (from, to) pair.
  useEffect(() => {
    if (!detailMode) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    (async () => {
      setDetailLoading(true);
      setDetailError(null);
      try {
        const res = await api.projects.getDiff(projectId, { from, to });
        if (!cancelled) setDetail(res);
      } catch (err) {
        if (!cancelled) {
          setDetailError(
            err instanceof Error ? err.message : t("diffLoadFailed"),
          );
        }
      } finally {
        if (!cancelled) setDetailLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [projectId, from, to, detailMode, t]);

  // Timeline mode: lazily fan out a diff per SBOM pair so each row gets
  // its "vs previous" badge counts. This is best-effort — failures on
  // individual rows are non-fatal and just leave the row without badges.
  useEffect(() => {
    if (detailMode) return;
    if (sboms.length === 0) return;

    let cancelled = false;
    (async () => {
      // Iterate sequentially to avoid blasting the API; per-row work is
      // small (3 set ops) and the typical project has <30 SBOMs.
      for (let i = 0; i < sboms.length; i++) {
        const current = sboms[i];
        const previous = i + 1 < sboms.length ? sboms[i + 1] : null;
        const cacheKey = current.id;
        if (timelineDiffs[cacheKey]) continue;

        try {
          const res = await api.projects.getDiff(projectId, {
            from: previous ? previous.id : undefined,
            to: current.id,
          });
          if (cancelled) return;
          setTimelineDiffs((prev) => ({ ...prev, [cacheKey]: res }));
        } catch {
          // Non-fatal — just leave the row unbadged.
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // We deliberately depend only on sboms identity + projectId so the
    // effect re-runs when the list reloads, not on every state change.
    // timelineDiffs is checked inside the loop for cache hits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sboms, projectId, detailMode]);

  const localePrefix = `/${locale}`;
  const backToProjectHref = `${localePrefix}/projects/${projectId}`;
  const backToTimelineHref = `${localePrefix}/projects/${projectId}/diff`;

  const formatDate = useCallback(
    (iso: string) => {
      try {
        return new Date(iso).toLocaleString(locale);
      } catch {
        return iso;
      }
    },
    [locale],
  );

  // ----- detail mode render -----
  if (detailMode) {
    return (
      <div>
        <div className="mb-6">
          <Link
            href={backToTimelineHref}
            className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-2"
          >
            <ArrowLeft className="h-4 w-4 mr-1" />
            {t("backToProject")}
          </Link>
          <h1 className="text-3xl font-bold">{tDetail("title")}</h1>
        </div>

        {detailLoading && (
          <p className="text-muted-foreground">{tc("loading")}</p>
        )}
        {detailError && (
          <Card className="border-red-200 bg-red-50/40 mb-4">
            <CardContent className="py-4 text-red-700">
              {detailError}
            </CardContent>
          </Card>
        )}

        {detail && (
          <>
            <DiffHeader
              detail={detail}
              labels={{
                from: tDetail("from"),
                to: tDetail("to"),
                fromBaseline: tDetail("fromBaseline"),
              }}
              formatDate={formatDate}
            />
            {/* M11-4 (#79): CSV + PDF export action row sits between the
                from/to header and the data tabs so it's visible regardless
                of which tab the user lands on. */}
            <div className="mt-4">
              <ExportButtons
                projectId={projectId}
                from={from}
                to={to}
                lang={locale}
              />
            </div>
            <Tabs value={activeTab} onValueChange={setActiveTab} className="mt-6">
              <TabsList>
                <TabsTrigger value="components">
                  {tDetail("componentsPanel")}
                </TabsTrigger>
                <TabsTrigger value="vulns">
                  {tDetail("vulnerabilitiesPanel")}
                </TabsTrigger>
                <TabsTrigger value="licenses">
                  {tDetail("licensesPanel")}
                </TabsTrigger>
                {/* M11-4 (#79): AI summary lives in its own tab so the
                    deterministic diff buckets remain the default landing
                    surface (the AI artefact is opt-in per the CLAUDE.md
                    "AI drafts only. Humans approve." discipline). */}
                <TabsTrigger value="ai-summary">
                  {tDetail("aiSummaryPanel")}
                </TabsTrigger>
              </TabsList>

              <TabsContent value="components" className="mt-4 space-y-4">
                <ComponentBucket
                  title={tDetail("added")}
                  empty={tDetail("noChanges")}
                  rows={detail.components.added}
                  labels={detailComponentLabels(tDetail)}
                />
                <ComponentBucket
                  title={tDetail("removed")}
                  empty={tDetail("noChanges")}
                  rows={detail.components.removed}
                  labels={detailComponentLabels(tDetail)}
                />
                <VersionChangeBucket
                  title={tDetail("versionChanged")}
                  empty={tDetail("noChanges")}
                  rows={detail.components.version_changed}
                  labels={{
                    name: tDetail("componentName"),
                    fromVersion: tDetail("fromVersion"),
                    toVersion: tDetail("toVersion"),
                    purl: tDetail("componentPurl"),
                  }}
                />
              </TabsContent>

              <TabsContent value="vulns" className="mt-4 space-y-4">
                <VulnAddedBucket
                  title={tDetail("vulnsAddedSection")}
                  empty={tDetail("noChanges")}
                  rows={detail.vulnerabilities.added}
                  labels={{
                    cveId: tDetail("cveId"),
                    severity: tDetail("severity"),
                    componentName: tDetail("componentName"),
                    componentVersion: tDetail("componentVersion"),
                  }}
                />
                <VulnResolvedBucket
                  title={tDetail("vulnsResolvedSection")}
                  empty={tDetail("noChanges")}
                  rows={detail.vulnerabilities.resolved}
                  labels={{
                    cveId: tDetail("cveId"),
                    severity: tDetail("severity"),
                  }}
                />
                <VulnSeverityBucket
                  title={tDetail("severityChanged")}
                  empty={tDetail("noChanges")}
                  rows={detail.vulnerabilities.severity_changed}
                  labels={{
                    cveId: tDetail("cveId"),
                    fromSeverity: tDetail("fromSeverity"),
                    toSeverity: tDetail("toSeverity"),
                  }}
                />
              </TabsContent>

              <TabsContent value="licenses" className="mt-4 space-y-4">
                <LicenseBucket
                  title={tDetail("violationsAdded")}
                  empty={tDetail("noChanges")}
                  rows={detail.licenses.added_policy_violations}
                  labels={{
                    componentName: tDetail("componentName"),
                    license: tDetail("componentLicense"),
                    policyName: tDetail("policyName"),
                  }}
                />
                <LicenseBucket
                  title={tDetail("violationsRemoved")}
                  empty={tDetail("noChanges")}
                  rows={detail.licenses.removed_policy_violations}
                  labels={{
                    componentName: tDetail("componentName"),
                    license: tDetail("componentLicense"),
                    policyName: tDetail("policyName"),
                  }}
                />
              </TabsContent>

              <TabsContent value="ai-summary" className="mt-4">
                <AiSummaryPanel
                  projectId={projectId}
                  from={from}
                  to={to}
                  lang={locale}
                />
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>
    );
  }

  // ----- timeline mode render -----
  return (
    <div>
      <div className="mb-6">
        <Link
          href={backToProjectHref}
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-2"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          {t("backToProject")}
        </Link>
        <h1 className="text-3xl font-bold">{t("title")}</h1>
        <p className="text-muted-foreground mt-1 max-w-2xl">
          {t("description")}
        </p>
      </div>

      {sbomsLoading && <p className="text-muted-foreground">{tc("loading")}</p>}
      {sbomsError && (
        <Card className="border-red-200 bg-red-50/40 mb-4">
          <CardContent className="py-4 text-red-700">{sbomsError}</CardContent>
        </Card>
      )}
      {!sbomsLoading && !sbomsError && sboms.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            {t("noSboms")}
          </CardContent>
        </Card>
      )}

      {!sbomsLoading && !sbomsError && sboms.length === 1 && (
        <Card className="border-blue-200 bg-blue-50/40 mb-4">
          <CardContent className="py-4 text-blue-900 text-sm">
            {t("singleSbomBanner")}
          </CardContent>
        </Card>
      )}

      {!sbomsLoading && !sbomsError && sboms.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{tTimeline("title")}</CardTitle>
            <p className="text-sm text-muted-foreground">
              {tTimeline("description")}
            </p>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{tTimeline("uploadedAt")}</TableHead>
                  <TableHead>{tTimeline("format")}</TableHead>
                  <TableHead>{tTimeline("diffWithPrevious")}</TableHead>
                  <TableHead className="w-[160px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sboms.map((s, i) => {
                  const previousSbom = i + 1 < sboms.length ? sboms[i + 1] : null;
                  const diff = timelineDiffs[s.id] ?? null;
                  return (
                    <TimelineRowView
                      key={s.id}
                      sbom={s}
                      previousSbom={previousSbom}
                      diff={diff}
                      formatDate={formatDate}
                      detailHref={(fromId, toId) =>
                        `${backToTimelineHref}${buildDiffQuery(fromId, toId)}`
                      }
                      labels={{
                        initialBaseline: tTimeline("initialBaseline"),
                        viewDiff: t("viewDiff"),
                        componentsAdded: (n: number) =>
                          tTimeline("componentsAdded", { count: n }),
                        componentsRemoved: (n: number) =>
                          tTimeline("componentsRemoved", { count: n }),
                        componentsChanged: (n: number) =>
                          tTimeline("componentsChanged", { count: n }),
                        vulnsAdded: (n: number) =>
                          tTimeline("vulnsAdded", { count: n }),
                        vulnsResolved: (n: number) =>
                          tTimeline("vulnsResolved", { count: n }),
                        vulnsSeverityChanged: (n: number) =>
                          tTimeline("vulnsSeverityChanged", { count: n }),
                        licensesAddedViolations: (n: number) =>
                          tTimeline("licensesAddedViolations", { count: n }),
                      }}
                    />
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ---------------- subcomponents ----------------

interface TimelineRowProps {
  sbom: Sbom;
  previousSbom: Sbom | null;
  diff: ProjectDiffResponse | null;
  formatDate: (iso: string) => string;
  detailHref: (from: string | undefined, to: string) => string;
  labels: {
    initialBaseline: string;
    viewDiff: string;
    componentsAdded: (n: number) => string;
    componentsRemoved: (n: number) => string;
    componentsChanged: (n: number) => string;
    vulnsAdded: (n: number) => string;
    vulnsResolved: (n: number) => string;
    vulnsSeverityChanged: (n: number) => string;
    licensesAddedViolations: (n: number) => string;
  };
}

function TimelineRowView({
  sbom,
  previousSbom,
  diff,
  formatDate,
  detailHref,
  labels,
}: TimelineRowProps) {
  const badges = useMemo(() => {
    if (!diff) return null;
    const out: { key: string; label: string; variant: "default" | "outline" | "destructive" | "secondary" }[] = [];
    const cAdd = diff.components.added.length;
    const cRem = diff.components.removed.length;
    const cChg = diff.components.version_changed.length;
    const vAdd = diff.vulnerabilities.added.length;
    const vRes = diff.vulnerabilities.resolved.length;
    const vSev = diff.vulnerabilities.severity_changed.length;
    const lAdd = diff.licenses.added_policy_violations.length;

    if (cAdd > 0) out.push({ key: "ca", label: labels.componentsAdded(cAdd), variant: "default" });
    if (cRem > 0) out.push({ key: "cr", label: labels.componentsRemoved(cRem), variant: "outline" });
    if (cChg > 0) out.push({ key: "cc", label: labels.componentsChanged(cChg), variant: "secondary" });
    if (vAdd > 0) out.push({ key: "va", label: labels.vulnsAdded(vAdd), variant: "destructive" });
    if (vRes > 0) out.push({ key: "vr", label: labels.vulnsResolved(vRes), variant: "outline" });
    if (vSev > 0) out.push({ key: "vs", label: labels.vulnsSeverityChanged(vSev), variant: "secondary" });
    if (lAdd > 0) out.push({ key: "la", label: labels.licensesAddedViolations(lAdd), variant: "destructive" });

    return out;
  }, [diff, labels]);

  return (
    <TableRow>
      <TableCell className="font-mono text-xs">
        {formatDate(sbom.created_at)}
      </TableCell>
      <TableCell>
        <Badge variant="outline">
          {sbom.format}
          {sbom.version ? ` ${sbom.version}` : ""}
        </Badge>
      </TableCell>
      <TableCell>
        {previousSbom === null ? (
          <span className="text-sm text-muted-foreground">
            {labels.initialBaseline}
          </span>
        ) : badges === null ? (
          <span className="text-sm text-muted-foreground">—</span>
        ) : badges.length === 0 ? (
          <span className="text-sm text-muted-foreground">—</span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {badges.map((b) => (
              <Badge key={b.key} variant={b.variant}>
                {b.label}
              </Badge>
            ))}
          </div>
        )}
      </TableCell>
      <TableCell>
        <Link
          href={detailHref(previousSbom?.id, sbom.id)}
          className="inline-flex items-center text-sm text-primary hover:underline"
        >
          <GitCompareArrows className="h-3 w-3 mr-1" />
          {labels.viewDiff}
        </Link>
      </TableCell>
    </TableRow>
  );
}

function DiffHeader({
  detail,
  labels,
  formatDate,
}: {
  detail: ProjectDiffResponse;
  labels: { from: string; to: string; fromBaseline: string };
  formatDate: (iso: string) => string;
}) {
  return (
    <div className="grid gap-3 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{labels.from}</CardTitle>
        </CardHeader>
        <CardContent className="text-sm">
          {detail.from === null ? (
            <p className="text-muted-foreground">{labels.fromBaseline}</p>
          ) : (
            <>
              <p className="font-mono text-xs">{detail.from.sbom_id}</p>
              <p className="text-muted-foreground">
                {formatDate(detail.from.created_at)} ·{" "}
                <span>{detail.from.format}</span>
                {detail.from.version ? ` ${detail.from.version}` : ""}
              </p>
            </>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{labels.to}</CardTitle>
        </CardHeader>
        <CardContent className="text-sm">
          {detail.to === null ? (
            <p className="text-muted-foreground">—</p>
          ) : (
            <>
              <p className="font-mono text-xs">{detail.to.sbom_id}</p>
              <p className="text-muted-foreground">
                {formatDate(detail.to.created_at)} ·{" "}
                <span>{detail.to.format}</span>
                {detail.to.version ? ` ${detail.to.version}` : ""}
              </p>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function detailComponentLabels(tDetail: (k: string) => string) {
  return {
    name: tDetail("componentName"),
    version: tDetail("componentVersion"),
    license: tDetail("componentLicense"),
    purl: tDetail("componentPurl"),
  };
}

function ComponentBucket({
  title,
  empty,
  rows,
  labels,
}: {
  title: string;
  empty: string;
  rows: ProjectDiffComponentChange[];
  labels: { name: string; version: string; license: string; purl: string };
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {title} ({rows.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{labels.name}</TableHead>
                <TableHead>{labels.version}</TableHead>
                <TableHead>{labels.license}</TableHead>
                <TableHead>{labels.purl}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r, i) => (
                <TableRow key={`${r.name}:${r.version}:${i}`}>
                  <TableCell className="font-medium">{r.name}</TableCell>
                  <TableCell className="font-mono text-xs">{r.version}</TableCell>
                  <TableCell className="text-xs">{r.license ?? ""}</TableCell>
                  <TableCell className="font-mono text-xs">{r.purl ?? ""}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function VersionChangeBucket({
  title,
  empty,
  rows,
  labels,
}: {
  title: string;
  empty: string;
  rows: ProjectDiffComponentVersionChange[];
  labels: { name: string; fromVersion: string; toVersion: string; purl: string };
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {title} ({rows.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{labels.name}</TableHead>
                <TableHead>{labels.fromVersion}</TableHead>
                <TableHead>{labels.toVersion}</TableHead>
                <TableHead>{labels.purl}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r, i) => (
                <TableRow key={`${r.name}:${r.from_version}->${r.to_version}:${i}`}>
                  <TableCell className="font-medium">{r.name}</TableCell>
                  <TableCell className="font-mono text-xs">{r.from_version}</TableCell>
                  <TableCell className="font-mono text-xs">{r.to_version}</TableCell>
                  <TableCell className="font-mono text-xs">{r.purl ?? ""}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function severityBadgeVariant(sev: string): "default" | "destructive" | "outline" | "secondary" {
  switch (normaliseSeverity(sev)) {
    case "critical":
    case "high":
      return "destructive";
    case "medium":
      return "default";
    case "low":
      return "secondary";
    default:
      return "outline";
  }
}

function VulnAddedBucket({
  title,
  empty,
  rows,
  labels,
}: {
  title: string;
  empty: string;
  rows: ProjectDiffVulnerabilityAdded[];
  labels: { cveId: string; severity: string; componentName: string; componentVersion: string };
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {title} ({rows.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{labels.cveId}</TableHead>
                <TableHead>{labels.severity}</TableHead>
                <TableHead>{labels.componentName}</TableHead>
                <TableHead>{labels.componentVersion}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r, i) => (
                <TableRow key={`${r.cve_id}:${r.component_name}:${r.component_version}:${i}`}>
                  <TableCell className="font-mono text-xs font-bold">{r.cve_id}</TableCell>
                  <TableCell>
                    <Badge variant={severityBadgeVariant(r.severity)}>{r.severity}</Badge>
                  </TableCell>
                  <TableCell>{r.component_name}</TableCell>
                  <TableCell className="font-mono text-xs">{r.component_version}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function VulnResolvedBucket({
  title,
  empty,
  rows,
  labels,
}: {
  title: string;
  empty: string;
  rows: ProjectDiffVulnerabilityResolved[];
  labels: { cveId: string; severity: string };
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {title} ({rows.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{labels.cveId}</TableHead>
                <TableHead>{labels.severity}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r, i) => (
                <TableRow key={`${r.cve_id}:${i}`}>
                  <TableCell className="font-mono text-xs font-bold">{r.cve_id}</TableCell>
                  <TableCell>
                    <Badge variant={severityBadgeVariant(r.severity)}>{r.severity}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function VulnSeverityBucket({
  title,
  empty,
  rows,
  labels,
}: {
  title: string;
  empty: string;
  rows: ProjectDiffVulnerabilitySeverityChange[];
  labels: { cveId: string; fromSeverity: string; toSeverity: string };
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {title} ({rows.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{labels.cveId}</TableHead>
                <TableHead>{labels.fromSeverity}</TableHead>
                <TableHead>{labels.toSeverity}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r, i) => (
                <TableRow key={`${r.cve_id}:${i}`}>
                  <TableCell className="font-mono text-xs font-bold">{r.cve_id}</TableCell>
                  <TableCell>
                    <Badge variant={severityBadgeVariant(r.from_severity)}>{r.from_severity}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={severityBadgeVariant(r.to_severity)}>{r.to_severity}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function LicenseBucket({
  title,
  empty,
  rows,
  labels,
}: {
  title: string;
  empty: string;
  rows: ProjectDiffLicenseViolation[];
  labels: { componentName: string; license: string; policyName: string };
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {title} ({rows.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{labels.componentName}</TableHead>
                <TableHead>{labels.license}</TableHead>
                <TableHead>{labels.policyName}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r, i) => (
                <TableRow key={`${r.component_name}:${r.license}:${i}`}>
                  <TableCell className="font-medium">{r.component_name}</TableCell>
                  <TableCell className="font-mono text-xs">{r.license}</TableCell>
                  <TableCell>
                    <Badge variant="destructive">{r.policy_name}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

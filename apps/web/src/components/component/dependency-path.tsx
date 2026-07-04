"use client";

/**
 * Dependency path-to-root panel — M29-B (F398, issue #137).
 *
 * Visualises how a (usually transitive) component is pulled into a
 * project's SBOM: the set of `root → … → target` dependency chains
 * returned by GET /api/v1/projects/:id/components/:component_id/paths
 * (Wave A / F397 backend). The point is actionable: for a vulnerable
 * transitive dependency, it answers "what do I upgrade?" — the direct
 * dependency at the start of each chain, highlighted below.
 *
 * Two surfaces:
 *   - list (primary):  each path as a textual chain with the direct
 *                      dependency and the target emphasised. This is the
 *                      answer a developer acts on.
 *   - graph (secondary, toggle): the @xyflow/react scaffolding from
 *                      components/diff/dependency-graph.tsx, replicated
 *                      (not shared — keeping the diff graph untouched)
 *                      as a layered left→right DAG of the union of all
 *                      path nodes, with root / direct-dep / target
 *                      colour-coded.
 *
 * Empty / degraded / truncated states are surfaced honestly:
 *   - degraded (SPDX, no dependency edges): informational empty state.
 *   - truncated (backend hit its path cap): a "showing first N" notice,
 *     never a silent drop.
 *   - no paths (component absent from the graph): neutral empty state.
 *
 * F164 (Go nil slice → JSON null) safety is enforced upstream by
 * api.projects.getComponentPaths (`paths` and every inner path are
 * `?? []`-normalised), so the .map / .length calls below are safe.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import { Loader2, Route, ChevronRight, Info, GitGraph, List } from "lucide-react";
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";

import {
  APIError,
  api,
  type ComponentPathsResponse,
  type ComponentPathNode,
} from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface DependencyPathPanelProps {
  projectId: string;
  componentId: string;
  /** Optional display fallbacks while the response is loading. */
  componentName?: string;
  componentVersion?: string;
  /** Optional SBOM id; omitted → backend uses the project's latest. */
  sbomId?: string;
}

/** Role of a node within a path, drives its colour + list emphasis. */
type PathNodeRole = "root" | "direct" | "intermediate" | "target";

// Local palette (hex literals so the @xyflow canvas renders without a
// Tailwind context lookup). Kept private to this component — we do NOT
// extract a shared style module, to avoid touching the diff graph.
const ROLE_STYLE: Record<
  PathNodeRole,
  { bg: string; border: string; text: string }
> = {
  root: { bg: "#e0e7ff", border: "#4f46e5", text: "#312e81" }, // indigo — the project / root
  direct: { bg: "#dbeafe", border: "#2563eb", text: "#1e3a8a" }, // blue — the direct dep to upgrade
  intermediate: { bg: "#f3f4f6", border: "#9ca3af", text: "#1f2937" }, // grey
  target: { bg: "#fee2e2", border: "#dc2626", text: "#7f1d1d" }, // red — the component in question
};

interface PathNodeData extends Record<string, unknown> {
  label: string;
  role: PathNodeRole;
}

/**
 * Classify a node's role given its index in a path and the path length.
 * root = index 0; target = last index; direct = index 1 (the direct
 * dependency of the root, i.e. the actionable upgrade target for a
 * transitive component). A length-1 path is the target being the root
 * itself; a length-2 path makes the target a direct dependency.
 */
function roleFor(index: number, length: number): PathNodeRole {
  if (index === length - 1) return "target";
  if (index === 0) return "root";
  if (index === 1) return "direct";
  return "intermediate";
}

/**
 * Build the layered graph (union of all path nodes) for the secondary
 * @xyflow view. Depth = the earliest index at which a node appears
 * across all paths, so the root sits at depth 0 on the left and the
 * target drifts rightward. Deterministic ordering (sorted ids per
 * depth) keeps layout stable across renders + tests. Role is taken from
 * the *target/root* semantics rather than per-path index so a node that
 * is a direct dep on one path and intermediate on another still reads
 * consistently.
 */
function buildFlow(
  paths: ComponentPathNode[][],
  targetId: string | null,
): { nodes: Node<PathNodeData>[]; edges: Edge[] } {
  const depthOf = new Map<string, number>();
  const info = new Map<string, ComponentPathNode>();
  const rootIds = new Set<string>();
  const directIds = new Set<string>();

  for (const path of paths) {
    path.forEach((n, i) => {
      info.set(n.id, n);
      const prev = depthOf.get(n.id);
      if (prev === undefined || i < prev) depthOf.set(n.id, i);
      if (i === 0) rootIds.add(n.id);
      if (i === 1 && path.length > 1) directIds.add(n.id);
    });
  }

  const byDepth = new Map<number, string[]>();
  for (const [id, d] of depthOf) {
    if (!byDepth.has(d)) byDepth.set(d, []);
    byDepth.get(d)!.push(id);
  }

  const nodes: Node<PathNodeData>[] = [];
  for (const [d, ids] of [...byDepth.entries()].sort((a, b) => a[0] - b[0])) {
    ids.sort();
    ids.forEach((id, row) => {
      const n = info.get(id)!;
      let role: PathNodeRole = "intermediate";
      if (id === targetId) role = "target";
      else if (rootIds.has(id)) role = "root";
      else if (directIds.has(id)) role = "direct";
      const style = ROLE_STYLE[role];
      nodes.push({
        id,
        position: { x: d * 240, y: row * 90 },
        data: {
          label: n.version ? `${n.name || n.id} ${n.version}` : n.name || n.id,
          role,
        },
        style: {
          background: style.bg,
          border: `2px solid ${style.border}`,
          color: style.text,
          borderRadius: 8,
          padding: 6,
          width: 190,
          fontSize: 11,
        },
      });
    });
  }

  const seen = new Set<string>();
  const edges: Edge[] = [];
  for (const path of paths) {
    for (let i = 0; i + 1 < path.length; i++) {
      const key = `${path[i].id}__${path[i + 1].id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push({
        id: `e-${key}`,
        source: path[i].id,
        target: path[i + 1].id,
        style: { stroke: "#6b7280", strokeWidth: 1.5 },
      });
    }
  }

  return { nodes, edges };
}

export function DependencyPathPanel({
  projectId,
  componentId,
  componentName,
  componentVersion,
  sbomId,
}: DependencyPathPanelProps) {
  const t = useTranslations("DependencyPath");

  const [data, setData] = useState<ComponentPathsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"list" | "graph">("list");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.projects.getComponentPaths(
        projectId,
        componentId,
        sbomId,
      );
      setData(res);
    } catch (err) {
      if (err instanceof APIError) {
        const msg =
          err.body && typeof err.body.error === "string"
            ? (err.body.error as string)
            : t("loadFailed");
        setError(msg);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError(t("loadFailed"));
      }
    } finally {
      setLoading(false);
    }
  }, [projectId, componentId, sbomId, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const targetId = useMemo(() => {
    if (!data || data.paths.length === 0) return null;
    // Every path terminates at the same target node; take it from the
    // first non-empty path's last element.
    for (const p of data.paths) {
      if (p.length > 0) return p[p.length - 1].id;
    }
    return null;
  }, [data]);

  const flow = useMemo(
    () => (data ? buildFlow(data.paths, targetId) : { nodes: [], edges: [] }),
    [data, targetId],
  );

  const heading = data?.component?.name || componentName || "";
  const headingVersion = data?.component?.version || componentVersion || "";

  return (
    <Card data-testid="dependency-path-panel">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Route className="h-4 w-4" />
          {t("title")}
          {heading && (
            <span className="font-normal text-muted-foreground">
              — {heading}
              {headingVersion ? ` ${headingVersion}` : ""}
            </span>
          )}
        </CardTitle>
        <p className="text-sm text-muted-foreground">{t("description")}</p>
      </CardHeader>
      <CardContent>
        {loading && (
          <div className="flex items-center gap-2 py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>{t("loading")}</span>
          </div>
        )}

        {error && (
          <div className="border border-red-200 bg-red-50/40 text-red-700 rounded p-4 text-sm">
            {error}
          </div>
        )}

        {!loading && !error && data && (
          <>
            {/* Direct vs transitive guidance — the "what do I do" line. */}
            {data.paths.length > 0 && (
              <div
                data-testid="dependency-path-guidance"
                className={
                  data.is_direct
                    ? "mb-4 rounded-md border border-blue-200 bg-blue-50/60 dark:border-blue-800 dark:bg-blue-950/30 p-3 text-sm"
                    : "mb-4 rounded-md border border-amber-200 bg-amber-50/60 dark:border-amber-800 dark:bg-amber-950/30 p-3 text-sm"
                }
              >
                <p className="font-semibold flex items-center gap-1.5">
                  <Info className="h-4 w-4 flex-shrink-0" />
                  {data.is_direct ? t("directTitle") : t("transitiveTitle")}
                </p>
                <p className="mt-1 text-muted-foreground">
                  {data.is_direct ? t("directHint") : t("transitiveHint")}
                </p>
              </div>
            )}

            {/* Truncation is reported honestly — never silently dropped. */}
            {data.truncated && (
              <div
                data-testid="dependency-path-truncated"
                className="mb-4 rounded-md border border-yellow-300 bg-yellow-50 dark:border-yellow-700 dark:bg-yellow-900/30 p-3 text-sm text-yellow-800 dark:text-yellow-200"
              >
                {t("truncated", { count: data.path_count })}
              </div>
            )}

            {/* Degraded (SPDX / no edges): informational, not an error. */}
            {data.degraded && (
              <div
                data-testid="dependency-path-degraded"
                className="rounded-md border border-muted bg-muted/40 p-4 text-sm text-muted-foreground"
              >
                {t("degraded")}
              </div>
            )}

            {/* No paths, but the SBOM does carry edges → not in graph. */}
            {!data.degraded && data.paths.length === 0 && (
              <div
                data-testid="dependency-path-empty"
                className="rounded-md border border-muted bg-muted/40 p-4 text-sm text-muted-foreground"
              >
                {t("empty")}
              </div>
            )}

            {data.paths.length > 0 && (
              <>
                <div className="flex items-center justify-between gap-2 mb-3">
                  <Badge variant="outline" data-testid="dependency-path-count">
                    {t("pathCount", { count: data.path_count })}
                  </Badge>
                  <div className="flex gap-1">
                    <Button
                      size="sm"
                      variant={view === "list" ? "default" : "outline"}
                      onClick={() => setView("list")}
                    >
                      <List className="h-3.5 w-3.5 mr-1" />
                      {t("listView")}
                    </Button>
                    <Button
                      size="sm"
                      variant={view === "graph" ? "default" : "outline"}
                      onClick={() => setView("graph")}
                    >
                      <GitGraph className="h-3.5 w-3.5 mr-1" />
                      {t("graphView")}
                    </Button>
                  </div>
                </div>

                {view === "list" ? (
                  <ol
                    className="space-y-3"
                    data-testid="dependency-path-list"
                  >
                    {data.paths.map((path, pi) => (
                      <li
                        key={`path-${pi}`}
                        data-testid="dependency-path-chain"
                        className="rounded-md border p-3"
                      >
                        <div className="flex flex-wrap items-center gap-1.5 text-sm">
                          {path.map((node, ni) => {
                            const role = roleFor(ni, path.length);
                            return (
                              <span
                                key={`${pi}-${ni}-${node.id}`}
                                className="inline-flex items-center gap-1.5"
                              >
                                <span
                                  data-role={role}
                                  className={pathNodeClass(role)}
                                >
                                  <span className="font-medium">
                                    {node.name || node.id}
                                  </span>
                                  {node.version && (
                                    <span className="font-mono text-xs opacity-80">
                                      {node.version}
                                    </span>
                                  )}
                                </span>
                                {ni < path.length - 1 && (
                                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                                )}
                              </span>
                            );
                          })}
                        </div>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <div
                    style={{ height: 420, width: "100%" }}
                    className="border rounded"
                    data-testid="dependency-path-graph"
                  >
                    <ReactFlow
                      nodes={flow.nodes}
                      edges={flow.edges}
                      fitView
                      proOptions={{ hideAttribution: true }}
                      nodesDraggable={false}
                      nodesConnectable={false}
                      elementsSelectable={false}
                    >
                      <Background />
                      <Controls />
                    </ReactFlow>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

/** Per-role pill styling for the textual chain nodes. */
function pathNodeClass(role: PathNodeRole): string {
  const base =
    "inline-flex items-center gap-1.5 rounded px-2 py-0.5 border text-xs";
  switch (role) {
    case "root":
      return `${base} border-indigo-300 bg-indigo-50 text-indigo-900 dark:border-indigo-700 dark:bg-indigo-950/40 dark:text-indigo-200`;
    case "direct":
      return `${base} border-blue-300 bg-blue-50 text-blue-900 dark:border-blue-700 dark:bg-blue-950/40 dark:text-blue-200`;
    case "target":
      return `${base} border-red-300 bg-red-50 text-red-900 font-semibold dark:border-red-700 dark:bg-red-950/40 dark:text-red-200`;
    default:
      return `${base} border-muted-foreground/30 bg-muted/50 text-foreground`;
  }
}

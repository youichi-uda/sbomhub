"use client";

/**
 * Dependency graph panel for the SBOM diff detail page — M12-3 (#84).
 *
 * Renders the merged dependency graph (nodes + edges) returned by
 * `getDiffGraph` with diff colours overlaid:
 *
 *   green   = added   (in `to`, not in `from`)
 *   red     = removed (in `from`, not in `to`)
 *   amber   = version_changed
 *   grey    = unchanged
 *
 * Uses @xyflow/react (formerly react-flow) for the layout + canvas
 * controls. The library is loaded eagerly on the client because this
 * component already sits under "use client"; the diff page only
 * imports it inside the corresponding tab content, so the bundle cost
 * is only paid by users who actually open the graph tab.
 *
 * F164 (Go nil slice → JSON null) safety is enforced by
 * `api.lib::getDiffGraph` (every slice field is `?? []`-normalised
 * before reaching this component), so the .map / .length calls below
 * are safe even on an empty / baseline response.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import { Loader2, GitGraph } from "lucide-react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";

import {
  APIError,
  getDiffGraph,
  type ProjectDiffGraphResponse,
} from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface DependencyGraphPanelProps {
  projectId: string;
  from?: string;
  to?: string;
}

/**
 * Diff status of a single node. `unchanged` is the default for any
 * node that did not appear in any of `added` / `removed` /
 * `version_changed`.
 */
type NodeDiffStatus = "added" | "removed" | "version_changed" | "unchanged";

/**
 * Index signature satisfies @xyflow/react's `Node<T extends
 * Record<string, unknown>>` constraint; the keys we actually read
 * (label / sub / status / etc.) are listed above for IDE assistance.
 */
interface NodeDataPayload extends Record<string, unknown> {
  /** displayed in the centre of the node */
  label: string;
  /** small subtitle line: type + version */
  sub: string;
  status: NodeDiffStatus;
  /** localised pill text — `Added`/`Removed`/etc. */
  statusLabel: string;
  /** for version_changed, shown alongside the sub line */
  versionChange?: { from: string; to: string };
}

// Node colour palette (Tailwind-style hex literals so the canvas
// renders without depending on a Tailwind context lookup).
const STATUS_STYLE: Record<
  NodeDiffStatus,
  { bg: string; border: string; text: string }
> = {
  added: { bg: "#dcfce7", border: "#16a34a", text: "#14532d" }, // green
  removed: { bg: "#fee2e2", border: "#dc2626", text: "#7f1d1d" }, // red
  version_changed: { bg: "#fef3c7", border: "#d97706", text: "#78350f" }, // amber
  unchanged: { bg: "#f3f4f6", border: "#9ca3af", text: "#1f2937" }, // grey
};

/**
 * Lay nodes out in a deterministic grid driven by their position in
 * the response. Pure layout (no force-directed simulation) so the
 * positions are stable across renders + tests, and so a 1000-node
 * graph does not pin the main thread on layout iteration.
 */
function gridLayout(count: number, idx: number): { x: number; y: number } {
  const columns = Math.max(1, Math.ceil(Math.sqrt(count)));
  const col = idx % columns;
  const row = Math.floor(idx / columns);
  // ~220px x ~110px cells; gives a readable grid for the typical
  // <100-node case + a navigable canvas for the 1000-node stress test.
  return { x: col * 220, y: row * 110 };
}

export function DependencyGraphPanel({
  projectId,
  from,
  to,
}: DependencyGraphPanelProps) {
  const t = useTranslations("SbomDiff.Graph");

  const [graph, setGraph] = useState<ProjectDiffGraphResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getDiffGraph(projectId, from, to);
      setGraph(res);
    } catch (err) {
      if (err instanceof APIError) {
        const msg =
          (err.body && typeof err.body.error === "string"
            ? (err.body.error as string)
            : null) ?? t("loadFailed");
        setError(msg);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError(t("loadFailed"));
      }
    } finally {
      setLoading(false);
    }
  }, [projectId, from, to, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const { nodes, edges, summary } = useMemo(() => {
    if (!graph) {
      return {
        nodes: [] as Node<NodeDataPayload>[],
        edges: [] as Edge[],
        summary: { added: 0, removed: 0, versionChanged: 0, unchanged: 0 },
      };
    }

    const addedSet = new Set(graph.diff_status.added);
    const removedSet = new Set(graph.diff_status.removed);
    const versionChangedMap = new Map<string, { from: string; to: string }>();
    for (const v of graph.diff_status.version_changed) {
      versionChangedMap.set(v.id, { from: v.old_version, to: v.new_version });
    }

    let added = 0;
    let removed = 0;
    let versionChanged = 0;
    let unchanged = 0;

    const total = graph.nodes.length;
    const flowNodes: Node<NodeDataPayload>[] = graph.nodes.map((n, i) => {
      let status: NodeDiffStatus = "unchanged";
      let versionChange: { from: string; to: string } | undefined;
      if (addedSet.has(n.id)) {
        status = "added";
        added++;
      } else if (removedSet.has(n.id)) {
        status = "removed";
        removed++;
      } else if (versionChangedMap.has(n.id)) {
        status = "version_changed";
        versionChange = versionChangedMap.get(n.id);
        versionChanged++;
      } else {
        unchanged++;
      }
      const style = STATUS_STYLE[status];
      return {
        id: n.id,
        position: gridLayout(total, i),
        data: {
          label: n.name || n.id,
          sub: [n.type, n.version].filter(Boolean).join(" · "),
          status,
          statusLabel: t(`Status.${status}`),
          versionChange,
        },
        style: {
          background: style.bg,
          border: `2px solid ${style.border}`,
          color: style.text,
          borderRadius: 8,
          padding: 6,
          width: 200,
          fontSize: 11,
        },
      };
    });

    const flowEdges: Edge[] = graph.edges.map((e, i) => ({
      id: `e-${i}-${e.from}-${e.to}`,
      source: e.from,
      target: e.to,
      style: { stroke: "#6b7280", strokeWidth: 1 },
    }));

    return {
      nodes: flowNodes,
      edges: flowEdges,
      summary: { added, removed, versionChanged, unchanged },
    };
  }, [graph, t]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <GitGraph className="h-4 w-4" />
          {t("title")}
        </CardTitle>
        <p className="text-sm text-muted-foreground">{t("description")}</p>
      </CardHeader>
      <CardContent>
        {loading && (
          <div className="flex items-center gap-2 py-12 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>{t("loading")}</span>
          </div>
        )}
        {error && (
          <div className="border border-red-200 bg-red-50/40 text-red-700 rounded p-4 text-sm">
            {error}
          </div>
        )}
        {!loading && !error && graph && (
          <>
            <div className="flex flex-wrap gap-2 mb-3">
              <Badge variant="default" data-graph-summary="added">
                {t("Status.added")} ({summary.added})
              </Badge>
              <Badge variant="outline" data-graph-summary="removed">
                {t("Status.removed")} ({summary.removed})
              </Badge>
              <Badge variant="secondary" data-graph-summary="version_changed">
                {t("Status.version_changed")} ({summary.versionChanged})
              </Badge>
              <Badge variant="outline" data-graph-summary="unchanged">
                {t("Status.unchanged")} ({summary.unchanged})
              </Badge>
              <Badge variant="outline">
                {t("totalNodes", { count: graph.nodes.length })}
              </Badge>
              <Badge variant="outline">
                {t("totalEdges", { count: graph.edges.length })}
              </Badge>
            </div>
            {graph.nodes.length === 0 ? (
              <p className="text-sm text-muted-foreground py-8">
                {t("empty")}
              </p>
            ) : (
              <div
                style={{ height: 520, width: "100%" }}
                className="border rounded"
                data-testid="dependency-graph-canvas"
              >
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  fitView
                  proOptions={{ hideAttribution: true }}
                  nodesDraggable={false}
                  nodesConnectable={false}
                  elementsSelectable={false}
                >
                  <Background />
                  <Controls />
                  <MiniMap pannable zoomable />
                </ReactFlow>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

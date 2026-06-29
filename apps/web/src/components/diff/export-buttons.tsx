"use client";

/**
 * CSV / PDF export buttons for the SBOM diff detail page — M11-4 (#79).
 *
 * Drives the GET /api/v1/projects/:id/diff.csv and /diff.pdf endpoints
 * via the authenticated `api.projects.fetchDiffExport` helper so the
 * Clerk JWT / org headers are attached. The returned blob is materialised
 * as an object URL and clicked through a hidden anchor.
 */

import { useState, useCallback } from "react";
import { useTranslations } from "next-intl";
import { Download, FileText, FileSpreadsheet, Loader2 } from "lucide-react";

import { api, APIError } from "@/lib/api";
import { Button } from "@/components/ui/button";

interface ExportButtonsProps {
  projectId: string;
  from?: string;
  to?: string;
  lang: string;
}

export function ExportButtons({
  projectId,
  from,
  to,
  lang,
}: ExportButtonsProps) {
  const t = useTranslations("SbomDiff.Export");
  const [busy, setBusy] = useState<"csv" | "pdf" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleExport = useCallback(
    async (format: "csv" | "pdf") => {
      setBusy(format);
      setError(null);
      try {
        const { blob, filename } = await api.projects.fetchDiffExport(
          projectId,
          format,
          { from, to, lang },
        );
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        // Async revoke so Firefox / WebKit keep the download alive long
        // enough for the user agent to start writing to disk.
        setTimeout(() => URL.revokeObjectURL(url), 5000);
      } catch (err) {
        if (err instanceof APIError) {
          setError(t("exportFailedStatus", { status: err.status }));
        } else {
          setError(t("exportFailed"));
        }
      } finally {
        setBusy(null);
      }
    },
    [projectId, from, to, lang, t],
  );

  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground mr-1 flex items-center gap-1">
          <Download className="h-3 w-3" />
          {t("label")}
        </span>
        <Button
          variant="outline"
          size="sm"
          onClick={() => handleExport("csv")}
          disabled={busy !== null}
        >
          {busy === "csv" ? (
            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
          ) : (
            <FileSpreadsheet className="h-3 w-3 mr-1" />
          )}
          {t("csv")}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => handleExport("pdf")}
          disabled={busy !== null}
        >
          {busy === "pdf" ? (
            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
          ) : (
            <FileText className="h-3 w-3 mr-1" />
          )}
          {t("pdf")}
        </Button>
      </div>
      {error && <p className="text-xs text-red-600 mt-1">{error}</p>}
    </div>
  );
}

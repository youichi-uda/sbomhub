"use client";

// Error state for a list whose GET failed (M65 bug 10).
//
// The list pages migrated to react-query in M64 caught a failed load and
// rendered their normal empty state ("No projects yet", "No API keys", ...),
// so an aborted request or an HTTP 500 looked exactly like an empty tenant.
// A failed load now renders this instead: the page's own "could not load"
// message plus a Retry button wired to the query's refetch. When the list
// already has rows (a later refetch failed), pass `compact` to show a banner
// above the rows that are still on screen.
//
// Pure presentational component; strings come from the caller (i18n).

import { AlertTriangle, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";

export interface LoadErrorProps {
  /** e.g. t("loadFailed") — must say that loading failed. */
  message: string;
  /** e.g. tc("retry") */
  retryLabel: string;
  onRetry: () => void;
  /** True while the retry is in flight (button disabled, icon spins). */
  retrying?: boolean;
  /** Banner above existing rows instead of the full-size empty-area card. */
  compact?: boolean;
  testId?: string;
}

export function LoadError({
  message,
  retryLabel,
  onRetry,
  retrying = false,
  compact = false,
  testId = "load-error",
}: LoadErrorProps) {
  return (
    <div
      role="alert"
      data-testid={testId}
      className={
        compact
          ? "mb-4 flex items-center justify-between gap-3 rounded-lg border border-destructive/50 px-4 py-3 text-sm text-destructive"
          : "flex flex-col items-center justify-center gap-4 rounded-lg border border-destructive/50 px-4 py-12 text-center"
      }
    >
      <div className={compact ? "flex items-center gap-2" : "flex flex-col items-center gap-3"}>
        <AlertTriangle className={compact ? "h-4 w-4 shrink-0" : "h-10 w-10 text-destructive"} />
        <p className={compact ? "" : "text-destructive"}>{message}</p>
      </div>
      <Button variant="outline" size="sm" onClick={onRetry} disabled={retrying}>
        <RefreshCw className={`mr-2 h-4 w-4 ${retrying ? "animate-spin" : ""}`} />
        {retryLabel}
      </Button>
    </div>
  );
}

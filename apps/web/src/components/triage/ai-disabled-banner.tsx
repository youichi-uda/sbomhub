"use client";

/**
 * AIDisabledBanner — surfaced on AI feature pages (/triage, /vex, /cra, ...)
 * when the backend reports llm.IsDisabled (provider unset, or no API key).
 *
 * Implements LLM_PROVIDER_DESIGN.md §4.1: "AI 機能 ... DisabledProvider の
 * 場合は banner 表示: AI 機能を使うには、 [設定 > LLM](/settings/llm) から
 * API キーを設定してください。"
 *
 * The banner takes an optional `reason` prop that mirrors the backend's
 * DisabledError.Reason (which itself is never a secret — checked in
 * apps/api/internal/service/llm/disabled.go). When omitted we fall back to
 * the generic localised message.
 */

import Link from "next/link";
import { useLocale, useTranslations } from "next-intl";
import { AlertTriangle } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

interface Props {
  /** Optional disable reason from the backend (e.g. "SBOMHUB_LLM_PROVIDER is not set"). */
  reason?: string;
  /** Override the destination link (defaults to /settings/llm). */
  settingsHref?: string;
}

export function AIDisabledBanner({ reason, settingsHref }: Props) {
  const t = useTranslations("Triage.AIDisabledBanner");
  const locale = useLocale();
  // Prefix the link with the active locale so next-intl routing resolves it
  // under the [locale] segment.
  const href = settingsHref ?? `/${locale}/settings/llm`;

  return (
    <Alert variant="destructive" className="mb-4">
      <AlertTriangle className="h-4 w-4" />
      <AlertTitle>{t("title")}</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>{t("description")}</p>
        {reason && (
          <p className="text-xs opacity-80">
            {t("reasonLabel")}: <code>{reason}</code>
          </p>
        )}
        <Button asChild size="sm" variant="outline">
          <Link href={href}>{t("ctaLabel")}</Link>
        </Button>
      </AlertDescription>
    </Alert>
  );
}

export default AIDisabledBanner;

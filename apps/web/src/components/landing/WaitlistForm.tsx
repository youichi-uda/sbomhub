"use client";

import { FormEvent, useState } from "react";
import { useLocale, useTranslations } from "next-intl";
import { AlertCircle, CheckCircle2, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

type Status = "idle" | "submitting" | "success" | "error";

interface Props {
  /**
   * Visual variant. `hero` centers the form for use under the hero CTA.
   * `section` aligns the form left for use inside a regular section.
   */
  variant?: "hero" | "section";
}

/**
 * Waitlist email capture form for the CRA / AI compliance evidence pivot.
 *
 * Submission strategy:
 *   - If NEXT_PUBLIC_WAITLIST_FORM_URL is set, POST as
 *     application/x-www-form-urlencoded (Formspree / Tally / Basin compatible).
 *   - Otherwise, fall back to a mailto: link to hello@sbomhub.app so the
 *     OSS / self-hosted deployment still has a working CTA without any
 *     external dependency.
 */
export function WaitlistForm({ variant = "section" }: Props) {
  const t = useTranslations("Landing.waitlist");
  const locale = useLocale();
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<Status>("idle");

  const formUrl = process.env.NEXT_PUBLIC_WAITLIST_FORM_URL;
  const useMailtoFallback = !formUrl;

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!email || status === "submitting") {
      return;
    }
    setStatus("submitting");

    if (useMailtoFallback) {
      const subject = encodeURIComponent("SBOMHub waitlist");
      const body = encodeURIComponent(
        `Email: ${email}\nLocale: ${locale}\n\nPlease add me to the SBOMHub waitlist. I would like to be notified when AI VEX MVP / CRA report drafting / METI self-assessment prefill are released.`,
      );
      window.location.href = `mailto:hello@sbomhub.app?subject=${subject}&body=${body}`;
      setStatus("success");
      return;
    }

    try {
      const response = await fetch(formUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          email,
          locale,
          source: "sbomhub-landing",
        }).toString(),
      });
      if (!response.ok) {
        throw new Error(`Waitlist submission failed: ${response.status}`);
      }
      setStatus("success");
      setEmail("");
    } catch (error) {
      console.error("[WaitlistForm] submission failed", error);
      setStatus("error");
    }
  };

  if (status === "success") {
    return (
      <div
        role="status"
        className={`flex items-start gap-2 rounded-md border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-700 ${
          variant === "hero" ? "max-w-md mx-auto" : "max-w-xl"
        }`}
      >
        <CheckCircle2 className="h-5 w-5 shrink-0 mt-0.5" />
        <p>{t("success")}</p>
      </div>
    );
  }

  return (
    <form
      onSubmit={handleSubmit}
      className={variant === "hero" ? "max-w-md mx-auto" : "max-w-xl"}
      noValidate
    >
      <div className="flex flex-col sm:flex-row gap-2">
        <Input
          type="email"
          inputMode="email"
          autoComplete="email"
          placeholder={t("placeholder")}
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          required
          aria-label="email"
          disabled={status === "submitting"}
          className="flex-1"
        />
        <Button
          type="submit"
          disabled={status === "submitting" || !email}
          className="gap-2"
        >
          {status === "submitting" ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              {t("submitting")}
            </>
          ) : (
            t("cta")
          )}
        </Button>
      </div>
      {status === "error" && (
        <p className="mt-2 flex items-center gap-2 text-sm text-red-600">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span>{t("error")}</span>
        </p>
      )}
      {useMailtoFallback && (
        <p className="mt-2 text-xs text-muted-foreground">{t("fallbackNote")}</p>
      )}
    </form>
  );
}

export default WaitlistForm;

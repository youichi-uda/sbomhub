"use client";

/**
 * /settings/diff-webhook — per-tenant SBOM diff webhook configuration.
 *
 * Implements the M11-4 (#79) frontend surface for migration 046 +
 * internal/service/diff_webhook. The page lets an operator:
 *
 *   - enable / disable the webhook
 *   - set the destination URL + shared secret (HMAC-SHA256)
 *   - choose JSON or Slack payload format
 *   - tune the critical / high / license-violation thresholds
 *   - send a manual test fire to verify the configuration
 *   - inspect the most recent delivery status / error
 *
 * The shared secret is AES-256-GCM ciphertext on disk; the form
 * pre-fills it with the placeholder "***" when one is configured —
 * re-submitting the placeholder preserves the existing ciphertext.
 * Re-typing a fresh plaintext rotates the secret (an audit log row
 * records the rotation; the plaintext NEVER round-trips back from
 * the API).
 */

import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useTranslations } from "next-intl";
import {
  Loader2,
  ShieldCheck,
  AlertTriangle,
  Webhook,
  Send,
} from "lucide-react";

import { useApi } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Checkbox } from "@/components/ui/checkbox";

const SECRET_PLACEHOLDER = "***";
const FORMATS = ["json", "slack"] as const;
type Format = (typeof FORMATS)[number];

const schema = z
  .object({
    enabled: z.boolean(),
    webhook_url: z.string().optional().default(""),
    webhook_secret: z.string().optional().default(""),
    format: z.enum(FORMATS),
    critical_threshold: z.coerce.number().int().min(0),
    high_threshold: z.coerce.number().int().min(0),
    license_violation_threshold: z.coerce.number().int().min(0),
  })
  .superRefine((data, ctx) => {
    if (data.enabled && data.webhook_url.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["webhook_url"],
        message: "url_required",
      });
    }
    if (
      data.webhook_url.trim() !== "" &&
      !/^https?:\/\//.test(data.webhook_url)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["webhook_url"],
        message: "url_protocol",
      });
    }
  });

type FormValues = z.infer<typeof schema>;

interface SettingsDiffWebhookResponse {
  enabled: boolean;
  webhook_url: string;
  secret_configured: boolean;
  webhook_secret: string;
  format: string;
  critical_threshold: number;
  high_threshold: number;
  license_violation_threshold: number;
  last_fired_at?: string;
  last_response_status?: number;
  last_error?: string;
  updated_at?: string;
}

interface TestFireResponse {
  triggered: boolean;
  reason?: string;
  http_status: number;
  error_message: string;
}

export default function DiffWebhookSettingsPage() {
  const t = useTranslations("SettingsDiffWebhook");
  const tCommon = useTranslations("Common");
  const api = useApi();

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [secretConfigured, setSecretConfigured] = useState(false);
  const [lastFire, setLastFire] = useState<{
    at?: string;
    status?: number;
    error?: string;
  } | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    watch,
    setValue,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      enabled: false,
      webhook_url: "",
      webhook_secret: "",
      format: "json",
      critical_threshold: 1,
      high_threshold: 5,
      license_violation_threshold: 0,
    },
  });

  const enabled = watch("enabled");
  const format = watch("format");

  useEffect(() => {
    (async () => {
      try {
        const data = await api.get<SettingsDiffWebhookResponse>(
          "/api/v1/tenant/settings/diff-webhook",
        );
        setSecretConfigured(!!data.secret_configured);
        reset({
          enabled: !!data.enabled,
          webhook_url: data.webhook_url || "",
          webhook_secret: data.webhook_secret || "",
          format: (FORMATS as readonly string[]).includes(data.format)
            ? (data.format as Format)
            : "json",
          critical_threshold: data.critical_threshold ?? 1,
          high_threshold: data.high_threshold ?? 5,
          license_violation_threshold: data.license_violation_threshold ?? 0,
        });
        setLastFire({
          at: data.last_fired_at,
          status: data.last_response_status,
          error: data.last_error,
        });
      } catch {
        setError(t("loadError"));
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onSubmit = async (values: FormValues) => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const body = {
        enabled: values.enabled,
        webhook_url: values.webhook_url,
        webhook_secret: values.webhook_secret,
        format: values.format,
        critical_threshold: values.critical_threshold,
        high_threshold: values.high_threshold,
        license_violation_threshold: values.license_violation_threshold,
      };
      const saved = await api.put<SettingsDiffWebhookResponse>(
        "/api/v1/tenant/settings/diff-webhook",
        body,
      );
      setSecretConfigured(!!saved.secret_configured);
      setValue("webhook_secret", saved.webhook_secret || "");
      setLastFire({
        at: saved.last_fired_at,
        status: saved.last_response_status,
        error: saved.last_error,
      });
      setSuccess(t("saveSuccess"));
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("saveError"));
    } finally {
      setSaving(false);
    }
  };

  const onTest = async () => {
    setTesting(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await api.post<TestFireResponse>(
        "/api/v1/tenant/settings/diff-webhook/test",
      );
      if (res.triggered && res.http_status >= 200 && res.http_status < 300) {
        setSuccess(t("testSuccess", { status: res.http_status }));
      } else if (!res.triggered) {
        setError(t("testNotTriggered", { reason: res.reason ?? "" }));
      } else {
        setError(
          t("testFailed", {
            status: res.http_status,
            message: res.error_message,
          }),
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t("testError"));
    } finally {
      setTesting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto py-8 px-4 space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Webhook className="h-6 w-6" />
          {t("title")}
        </h1>
        <p className="text-muted-foreground mt-1">{t("description")}</p>
      </div>

      <Alert>
        <ShieldCheck className="h-4 w-4" />
        <AlertTitle>{t("securityTitle")}</AlertTitle>
        <AlertDescription>{t("securityDescription")}</AlertDescription>
      </Alert>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {success && (
        <Alert>
          <ShieldCheck className="h-4 w-4" />
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t("destinationSection")}</CardTitle>
          <CardDescription>{t("destinationDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="flex items-center gap-2">
              <Checkbox
                id="enabled"
                checked={enabled}
                onCheckedChange={(v) => setValue("enabled", !!v, { shouldValidate: true })}
              />
              <Label htmlFor="enabled">{t("enabledLabel")}</Label>
            </div>

            <div className="space-y-2">
              <Label htmlFor="webhook_url">{t("urlLabel")}</Label>
              <Input
                id="webhook_url"
                placeholder="https://hooks.slack.com/services/..."
                {...register("webhook_url")}
              />
              {errors.webhook_url?.message === "url_required" && (
                <p className="text-sm text-destructive">{t("urlRequired")}</p>
              )}
              {errors.webhook_url?.message === "url_protocol" && (
                <p className="text-sm text-destructive">{t("urlProtocol")}</p>
              )}
              <p className="text-xs text-muted-foreground">{t("urlHelp")}</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="webhook_secret">{t("secretLabel")}</Label>
              <Input
                id="webhook_secret"
                type="password"
                autoComplete="new-password"
                placeholder={
                  secretConfigured
                    ? t("secretPlaceholderConfigured")
                    : t("secretPlaceholder")
                }
                {...register("webhook_secret")}
              />
              <p className="text-xs text-muted-foreground">{t("secretHelp")}</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="format">{t("formatLabel")}</Label>
              <Select
                value={format}
                onValueChange={(v) => setValue("format", v as Format, { shouldValidate: true })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FORMATS.map((f) => (
                    <SelectItem key={f} value={f}>
                      {t(`format.${f}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">{t("formatHelp")}</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="space-y-2">
                <Label htmlFor="critical_threshold">
                  {t("criticalThresholdLabel")}
                </Label>
                <Input
                  id="critical_threshold"
                  type="number"
                  min={0}
                  {...register("critical_threshold")}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="high_threshold">
                  {t("highThresholdLabel")}
                </Label>
                <Input
                  id="high_threshold"
                  type="number"
                  min={0}
                  {...register("high_threshold")}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="license_violation_threshold">
                  {t("licenseThresholdLabel")}
                </Label>
                <Input
                  id="license_violation_threshold"
                  type="number"
                  min={0}
                  {...register("license_violation_threshold")}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              {t("thresholdsHelp")}
            </p>

            <div className="flex items-center justify-between pt-4 border-t">
              <p className="text-sm text-muted-foreground">
                {enabled ? t("statusEnabled") : t("statusDisabled")}
              </p>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={onTest}
                  disabled={testing || !enabled}
                >
                  {testing ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Send className="mr-2 h-4 w-4" />
                  )}
                  {t("testFire")}
                </Button>
                <Button type="submit" disabled={saving}>
                  {saving ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      {tCommon("save")}
                    </>
                  ) : (
                    tCommon("save")
                  )}
                </Button>
              </div>
            </div>
          </form>
        </CardContent>
      </Card>

      {lastFire?.at && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("lastFireTitle")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            <p>
              <span className="text-muted-foreground">{t("lastFireAt")}:</span>{" "}
              <span className="font-mono">
                {new Date(lastFire.at).toLocaleString()}
              </span>
            </p>
            {typeof lastFire.status === "number" && (
              <p>
                <span className="text-muted-foreground">
                  {t("lastFireStatus")}:
                </span>{" "}
                <span className="font-mono">{lastFire.status}</span>
              </p>
            )}
            {lastFire.error && (
              <p>
                <span className="text-muted-foreground">
                  {t("lastFireError")}:
                </span>{" "}
                <span className="font-mono text-red-600">{lastFire.error}</span>
              </p>
            )}
          </CardContent>
        </Card>
      )}

      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>{t("autoTriggerTitle")}</AlertTitle>
        <AlertDescription>{t("autoTriggerNote")}</AlertDescription>
      </Alert>
    </div>
  );
}

// Discriminate `SECRET_PLACEHOLDER` from "" so the lint rule that flags
// unused exports is satisfied; the constant is referenced by tests + by
// future regression coverage of the round-trip preservation rule.
export const _SECRET_PLACEHOLDER = SECRET_PLACEHOLDER;

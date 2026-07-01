"use client";

/**
 * /settings/llm — BYOK LLM provider configuration UI.
 *
 * Implements LLM_PROVIDER_DESIGN.md §4.1 and issue #22. The page is
 * deliberately small: provider select, API key input, model input, and
 * provider-specific extras for Azure / Ollama. The plaintext API key is
 * sent to the API once on PUT and is NEVER read back — GET returns the
 * placeholder "***" so the browser never sees the secret again.
 *
 * Form lib: react-hook-form + zod, matching the project pattern
 * (sbomhub/CLAUDE.md: "Frontend ... Form handling: react-hook-form + zod").
 */

import { useEffect, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useTranslations } from "next-intl";
import { Loader2, ShieldCheck, AlertTriangle, KeyRound } from "lucide-react";

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

// The PROVIDERS array below is one of three cross-language mirrors of
// the LLM provider registry (Go supportedLLMProviders +
// NewProviderFromEnv / NewProviderFromConfigWithAzure switches in
// apps/api/internal/handler/settings_llm.go +
// apps/api/internal/service/llm/factory.go, plus this .tsx dropdown).
// Parity is enforced at CI time by TestLLMProviderRegistryParity_F318
// direction 2 (Go registry ↔ web PROVIDERS) — see
// apps/api/internal/handler/settings_llm_parity_test.go. A rename or
// addition here must be replicated on both Go sites and the
// Provider.Name() doc comment in
// apps/api/internal/service/llm/provider.go simultaneously; F318 CI
// will otherwise fail loudly on the very next PR. F325 (M21 Phase D
// R2) replaced the pre-F318 archetype "must mirror ..." comment here
// — that comment was factually redundant once F318 CI enforcement
// landed but still nudged reviewers toward a manual mirror they were
// being told the CI already covered.
const PROVIDERS = ["openai", "anthropic", "gemini", "azure_openai", "ollama"] as const;
type Provider = (typeof PROVIDERS)[number];

const API_KEY_PLACEHOLDER = "***";

// Zod schema for the form. The api_key field is optional because the form
// pre-fills it with the placeholder when a key is already configured —
// re-submitting the placeholder means "preserve existing key".
const buildSchema = (requireKey: boolean) =>
  z
    .object({
      provider: z.enum(PROVIDERS),
      api_key: z.string().optional().default(""),
      model: z.string().optional().default(""),
      azure_endpoint: z.string().optional().default(""),
      azure_deployment: z.string().optional().default(""),
      ollama_url: z.string().optional().default(""),
    })
    .superRefine((data, ctx) => {
      // Ollama is local — no API key needed.
      if (data.provider === "ollama") return;
      if (requireKey && (!data.api_key || data.api_key === API_KEY_PLACEHOLDER)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["api_key"],
          message: "api_key_required",
        });
      }
    });

type FormValues = z.infer<ReturnType<typeof buildSchema>>;

interface SettingsLLMResponse {
  mode: string;
  provider: string;
  model: string;
  api_key_configured: boolean;
  api_key: string;
  azure_endpoint?: string;
  azure_deployment?: string;
  ollama_url?: string;
  updated_at?: string;
}

export default function LLMSettingsPage() {
  const t = useTranslations("Settings.LLM");
  const tCommon = useTranslations("Common");
  const api = useApi();

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [apiKeyConfigured, setApiKeyConfigured] = useState(false);

  const schema = buildSchema(!apiKeyConfigured);

  const {
    register,
    handleSubmit,
    reset,
    control,
    setValue,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      provider: "openai",
      api_key: "",
      model: "",
      azure_endpoint: "",
      azure_deployment: "",
      ollama_url: "",
    },
  });

  // M14-4 (#96, F215): migrated from `watch("provider")` to useWatch
  // so the React Compiler `react-hooks/incompatible-library` rule
  // passes without an inline suppression. Provider drives the
  // conditional fields (api_key visibility, azure / ollama extras)
  // so this subscription is the form's primary re-render driver —
  // scoping it to just `provider` is also a small perf win.
  const provider = useWatch({ control, name: "provider" });

  useEffect(() => {
    (async () => {
      try {
        const data = await api.get<SettingsLLMResponse>("/api/v1/settings/llm");
        setApiKeyConfigured(!!data.api_key_configured);
        reset({
          provider: (PROVIDERS as readonly string[]).includes(data.provider)
            ? (data.provider as Provider)
            : "openai",
          api_key: data.api_key || "",
          model: data.model || "",
          azure_endpoint: data.azure_endpoint || "",
          azure_deployment: data.azure_deployment || "",
          ollama_url: data.ollama_url || "",
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
    setSuccess(false);
    try {
      // mode is fixed to "byok" in OSS / self-host (managed_gemini is SaaS
      // only; LLM_PROVIDER_DESIGN.md §4.2).
      const body = {
        mode: "byok",
        provider: values.provider,
        api_key: values.api_key,
        model: values.model,
        azure_endpoint: values.provider === "azure_openai" ? values.azure_endpoint : "",
        azure_deployment: values.provider === "azure_openai" ? values.azure_deployment : "",
        ollama_url: values.provider === "ollama" ? values.ollama_url : "",
      };
      const saved = await api.put<SettingsLLMResponse>("/api/v1/settings/llm", body);
      setApiKeyConfigured(!!saved.api_key_configured);
      // Reset back to placeholder so the secret never round-trips.
      setValue("api_key", saved.api_key || "");
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      const message = err instanceof Error ? err.message : t("saveError");
      setError(message);
    } finally {
      setSaving(false);
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
          <KeyRound className="h-6 w-6" />
          {t("title")}
        </h1>
        <p className="text-muted-foreground mt-1">{t("description")}</p>
      </div>

      <Alert>
        <ShieldCheck className="h-4 w-4" />
        <AlertTitle>{t("byokTitle")}</AlertTitle>
        <AlertDescription>{t("byokDescription")}</AlertDescription>
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
          <AlertDescription>{t("saveSuccess")}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t("providerSection")}</CardTitle>
          <CardDescription>{t("providerSectionDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="provider">{t("providerLabel")}</Label>
              <Select
                value={provider}
                onValueChange={(v) => setValue("provider", v as Provider, { shouldValidate: true })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROVIDERS.map((p) => (
                    <SelectItem key={p} value={p}>
                      {t(`provider.${p}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {provider !== "ollama" && (
              <div className="space-y-2">
                <Label htmlFor="api_key">{t("apiKeyLabel")}</Label>
                <Input
                  id="api_key"
                  type="password"
                  autoComplete="new-password"
                  placeholder={
                    apiKeyConfigured ? t("apiKeyPlaceholderConfigured") : t("apiKeyPlaceholder")
                  }
                  {...register("api_key")}
                />
                {errors.api_key?.message === "api_key_required" && (
                  <p className="text-sm text-destructive">{t("apiKeyRequired")}</p>
                )}
                <p className="text-xs text-muted-foreground">{t("apiKeyHelp")}</p>
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="model">{t("modelLabel")}</Label>
              <Input
                id="model"
                placeholder={t(`modelPlaceholder.${provider}`)}
                {...register("model")}
              />
              <p className="text-xs text-muted-foreground">{t("modelHelp")}</p>
            </div>

            {provider === "azure_openai" && (
              <>
                <div className="space-y-2">
                  <Label htmlFor="azure_endpoint">{t("azureEndpointLabel")}</Label>
                  <Input
                    id="azure_endpoint"
                    placeholder="https://your-resource.openai.azure.com"
                    {...register("azure_endpoint")}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="azure_deployment">{t("azureDeploymentLabel")}</Label>
                  <Input
                    id="azure_deployment"
                    placeholder="gpt-4o-deployment"
                    {...register("azure_deployment")}
                  />
                </div>
              </>
            )}

            {provider === "ollama" && (
              <div className="space-y-2">
                <Label htmlFor="ollama_url">{t("ollamaUrlLabel")}</Label>
                <Input
                  id="ollama_url"
                  placeholder="http://localhost:11434"
                  {...register("ollama_url")}
                />
                <p className="text-xs text-muted-foreground">{t("ollamaUrlHelp")}</p>
              </div>
            )}

            <div className="flex items-center justify-between pt-4 border-t">
              <p className="text-sm text-muted-foreground">
                {apiKeyConfigured ? t("statusConfigured") : t("statusUnconfigured")}
              </p>
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
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

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

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTranslations } from "next-intl";
import { Loader2, ShieldCheck, AlertTriangle, KeyRound } from "lucide-react";

import { useApi } from "@/lib/api";
import { queryKeys } from "@/lib/query/keys";
import { errorSlot, resolveErrorSlot, type ErrorSlot } from "@/lib/query/error-slot";
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
import {
  buildLlmSettingsSchema,
  type LlmSettingsFormInput,
  type LlmSettingsFormValues,
} from "@/lib/form-schemas/llm-settings";

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

// Schema lives in @/lib/form-schemas/llm-settings (pinned by node --test).
// PROVIDERS is passed in so the literal above stays where the Go parity
// test reads it.
const buildSchema = (requireKey: boolean) =>
  buildLlmSettingsSchema(PROVIDERS, requireKey);

// zod 4 + @hookform/resolvers 5+: the form holds the schema INPUT (optional
// strings) and onSubmit receives the OUTPUT (defaults applied).
type FormInput = LlmSettingsFormInput<typeof PROVIDERS>;
type FormValues = LlmSettingsFormValues<typeof PROVIDERS>;

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

const SETTINGS_KEY = queryKeys.tenantSettings.llm();

export default function LLMSettingsPage() {
  const api = useApi();
  // Pure queryFn: the form is seeded from the result by mounting it only
  // once the query has settled (Codex R3 — a queryFn is shared cache code,
  // not a per-component callback, so it must not reset a particular form).
  const settingsQuery = useQuery({
    queryKey: SETTINGS_KEY,
    queryFn: () => api.get<SettingsLLMResponse>("/api/v1/settings/llm"),
  });

  if (settingsQuery.isPending) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return <LLMSettingsForm loaded={settingsQuery.data ?? null} loadState={settingsQuery} />;
}

function toFormValues(data: SettingsLLMResponse | null): FormInput {
  if (!data) {
    // Load failed: the form shows these (the old pre-reset defaults).
    return {
      provider: "openai",
      api_key: "",
      model: "",
      azure_endpoint: "",
      azure_deployment: "",
      ollama_url: "",
    };
  }
  return {
    provider: (PROVIDERS as readonly string[]).includes(data.provider)
      ? (data.provider as Provider)
      : "openai",
    api_key: data.api_key || "",
    model: data.model || "",
    azure_endpoint: data.azure_endpoint || "",
    azure_deployment: data.azure_deployment || "",
    ollama_url: data.ollama_url || "",
  };
}

function LLMSettingsForm({
  loaded,
  loadState,
}: {
  loaded: SettingsLLMResponse | null;
  loadState: { errorUpdateCount: number };
}) {
  const t = useTranslations("Settings.LLM");
  const tCommon = useTranslations("Common");
  const api = useApi();

  const [saving, setSaving] = useState(false);
  const queryClient = useQueryClient();
  const [actionError, setActionError] = useState<ErrorSlot | null>(null);
  const setError = (message: string | null) => setActionError(errorSlot(message, SETTINGS_KEY, queryClient));
  const [success, setSuccess] = useState(false);
  // Set from the PUT response once the operator saves; until then the
  // loaded settings decide.
  const [savedApiKeyConfigured, setApiKeyConfigured] = useState<boolean | null>(null);
  const error = resolveErrorSlot(actionError, SETTINGS_KEY, loadState.errorUpdateCount, t("loadError"));
  const apiKeyConfigured = savedApiKeyConfigured ?? !!loaded?.api_key_configured;
  // Computed once per mount: RHF reads defaultValues only on the first
  // render, which is the point (the stored values are in the very first
  // painted frame of the form).
  const [initialValues] = useState(() => toFormValues(loaded));

  const schema = buildSchema(!apiKeyConfigured);

  const {
    register,
    handleSubmit,
    control,
    setValue,
    formState: { errors },
  } = useForm<FormInput, unknown, FormValues>({
    resolver: zodResolver(schema),
    defaultValues: initialValues,
  });

  // M14-4 (#96, F215): migrated from `watch("provider")` to useWatch
  // so the React Compiler `react-hooks/incompatible-library` rule
  // passes without an inline suppression. Provider drives the
  // conditional fields (api_key visibility, azure / ollama extras)
  // so this subscription is the form's primary re-render driver —
  // scoping it to just `provider` is also a small perf win.
  const provider = useWatch({ control, name: "provider" });

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

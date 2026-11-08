// Form schema for /settings/llm
// (src/app/[locale]/(dashboard)/settings/llm/page.tsx). See cra-report.ts
// for why schemas live in zod-only modules.
//
// The provider list is a PARAMETER, not a constant here: the PROVIDERS
// literal must stay in page.tsx, where the Go parity test
// (TestLLMProviderRegistryParity_F318) reads it.
//
// azure_endpoint / ollama_url are free text on purpose (no client-side URL
// format check, before or after the zod 4 migration); the backend owns
// endpoint validation and its egress policy.
import { z } from "zod";

import { enumError } from "./v3-messages.ts";

export const API_KEY_PLACEHOLDER = "***";

// The api_key field is optional because the form pre-fills it with the
// placeholder when a key is already configured — re-submitting the
// placeholder means "preserve existing key".
export const buildLlmSettingsSchema = <P extends readonly [string, ...string[]]>(
  providers: P,
  requireKey: boolean,
) =>
  z
    .object({
      provider: z.enum(providers as unknown as [P[number], ...P[number][]], enumError(providers)),
      api_key: z.string().optional().default(""),
      model: z.string().optional().default(""),
      azure_endpoint: z.string().optional().default(""),
      azure_deployment: z.string().optional().default(""),
      ollama_url: z.string().optional().default(""),
    })
    .superRefine((data, ctx) => {
      // Ollama is local — no API key needed. Under zod 4 (as under zod 3)
      // this does not run when `provider` itself failed, the only field
      // here that can fail.
      if (data.provider === "ollama") return;
      if (requireKey && (!data.api_key || data.api_key === API_KEY_PLACEHOLDER)) {
        ctx.addIssue({
          code: "custom",
          path: ["api_key"],
          message: "api_key_required",
        });
      }
    });

type LlmSchema<P extends readonly [string, ...string[]]> = ReturnType<
  typeof buildLlmSettingsSchema<P>
>;
export type LlmSettingsFormInput<P extends readonly [string, ...string[]]> = z.input<LlmSchema<P>>;
export type LlmSettingsFormValues<P extends readonly [string, ...string[]]> = z.output<LlmSchema<P>>;

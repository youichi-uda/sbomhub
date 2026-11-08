// Form schemas for the METI criterion card (src/components/meti/criterion-card.tsx).
// See cra-report.ts for why schemas live in zod-only modules. The UI renders
// i18n strings keyed on the presence of an error, not the zod message.
import { z } from "zod";

import { enumError, maxChars, stringError } from "./v3-messages.ts";

const OVERRIDE_STATUSES = [
  "achieved",
  "not_achieved",
  "needs_review",
  "not_applicable",
] as const;

/** zod schema for the override form. Mirrors handler.metiOverrideRequest. */
export const criterionOverrideSchema = z.object({
  override_status: z.enum(OVERRIDE_STATUSES, enumError(OVERRIDE_STATUSES)),
  override_note: z.string(stringError).max(2000, maxChars(2000)),
  improvement_action: z.string(stringError).max(2000, maxChars(2000)),
});

export type CriterionOverrideFormValues = z.infer<typeof criterionOverrideSchema>;

/**
 * zod schema for the clear-override form (M3 #F35). Mirrors
 * handler.metiClearOverrideRequest — the server enforces 1..4096 chars
 * AFTER trim, so we mirror the trim-then-length check here to keep the
 * UI validation aligned. The client-side cap is set to MAX 4096 to
 * surface the server bound; 2000 would silently truncate visually.
 *
 * The transform makes input and output distinct types under zod 4's
 * resolver typing; both are `{ note: string }`.
 */
export const criterionClearOverrideSchema = z.object({
  note: z.string(stringError)
    .transform((s) => s.trim())
    .refine((s) => s.length >= 1 && s.length <= 4096, {
      error: "note must be 1..4096 characters after trim",
    }),
});

export type CriterionClearOverrideFormValues = z.infer<typeof criterionClearOverrideSchema>;

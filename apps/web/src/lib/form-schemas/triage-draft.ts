// Form schema for the triage draft edit form (src/components/triage/draft-card.tsx).
// See cra-report.ts for why schemas live in zod-only modules. `state` and
// `detail` messages are rendered verbatim in the UI.
import { z } from "zod";

import { enumError, maxChars, stringError } from "./v3-messages.ts";

const STATES = ["not_affected", "affected", "under_investigation", "resolved"] as const;
const JUSTIFICATIONS = [
  "",
  "code_not_present",
  "code_not_reachable",
  "requires_configuration",
  "requires_dependency",
  "requires_environment",
  "protected_by_compiler",
  "protected_at_perimeter",
  "protected_at_runtime",
  "inline_mitigations_already_exist",
] as const;

export const triageEditSchema = z.object({
  state: z.enum(STATES, enumError(STATES)),
  justification: z.enum(JUSTIFICATIONS, enumError(JUSTIFICATIONS)),
  detail: z.string(stringError).max(4000, maxChars(4000)),
  note: z.string(stringError).max(2000, maxChars(2000)),
});

export type TriageEditFormValues = z.infer<typeof triageEditSchema>;

// Form schema for the triage draft edit form (src/components/triage/draft-card.tsx).
// See cra-report.ts for why schemas live in zod-only modules. `state` and
// `detail` messages are rendered verbatim in the UI.
import { z } from "zod";

export const triageEditSchema = z.object({
  state: z.enum(["not_affected", "affected", "under_investigation", "resolved"]),
  justification: z.enum([
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
  ]),
  detail: z.string().max(4000),
  note: z.string().max(2000),
});

export type TriageEditFormValues = z.infer<typeof triageEditSchema>;

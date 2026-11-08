// Form schemas for the CRA report card (src/components/cra-reports/report-card.tsx).
//
// Kept in a module that imports nothing but zod (and the sibling message
// helpers) so the accept/reject behaviour and the exact error messages can be
// pinned by a plain `node --test` run (./__tests__/form-schemas.test.mjs) —
// apps/web has no component test runner. The messages below are rendered
// verbatim in the UI (`errors.<field>.message`), so they are part of the
// user-visible contract.
import { z } from "zod";

import { maxChars } from "./v3-messages.ts";

export const reportEditSchema = z.object({
  draft_text: z.string().min(1, { error: "draft_text is required" }).max(50000, maxChars(50000)),
  decision_note: z.string().max(2000, maxChars(2000)),
});

export type ReportEditFormValues = z.infer<typeof reportEditSchema>;

// SubmitForm schema. authority is required (backend rejects empty with 400)
// and free-text VARCHAR(255) (Wave A: no enum). submitted_at is a
// datetime-local value that page.tsx converts to RFC3339 before POST; an
// empty value lets the server default to NOW(). reference_number is
// VARCHAR(255); notes is TEXT (kept generous but bounded client-side).
export const reportSubmitSchema = z.object({
  authority: z.string().min(1, { error: "authority is required" }).max(255, maxChars(255)),
  submitted_at: z.string(),
  reference_number: z.string().max(255, maxChars(255)),
  notes: z.string().max(5000, maxChars(5000)),
});

export type ReportSubmitFormValues = z.infer<typeof reportSubmitSchema>;

// Form schema for /settings/diff-webhook
// (src/app/[locale]/(dashboard)/settings/diff-webhook/page.tsx). See
// cra-report.ts for why schemas live in zod-only modules. The page maps the
// `url_required` / `url_protocol` message KEYS to next-intl strings, so the
// keys are the contract, not English text.
//
// The URL check is deliberately a prefix regex (`^https?://`), not zod's
// url() format: it refuses javascript:, data:, file:, ftp:, scheme-relative
// and scheme-less values, and is unchanged by the zod 4 migration. The
// backend egress policy is the authority on destinations; this is the
// first, user-facing line.
import { z } from "zod";

import { enumError } from "./v3-messages.ts";

export const DIFF_WEBHOOK_FORMATS = ["json", "slack"] as const;
export type DiffWebhookFormat = (typeof DIFF_WEBHOOK_FORMATS)[number];

// A non-negative integer threshold, coerced from the input's string.
//
// zod 4 notes:
//   - coerce INPUT is typed `unknown` (the form holds strings, onSubmit gets
//     numbers), hence the separate DiffWebhookFormInput type below.
//   - The integer check is a refinement, not `.int()`, for two zod 3 parity
//     reasons. (1) zod 4's int() reports a fractional value as an ABORTING
//     issue, which skips the url_required / url_protocol refinement below;
//     zod 3 treated it as non-aborting and showed both errors together.
//     Refinement issues are non-aborting, so fractional and negative values
//     leave the URL check running, as in zod 3 (see v3RefinementGate).
//     (2) zod 4's int() is Number.isSafeInteger and refuses e.g. 2^53;
//     zod 3's was Number.isInteger.
//   - z.number() itself refuses NaN and, new in zod 4, ±Infinity; both were
//     already rejected under zod 3 (NaN by the type check, ±Infinity by int()).
//     The refinement gate below keeps zod 3's "±Infinity is a value failure".
//   - The messages are zod 3's; the page does not render threshold errors.
const threshold = () =>
  z.coerce
    .number()
    .refine((n) => Number.isInteger(n), { error: "Expected integer, received float" })
    .refine((n) => n >= 0, { error: "Number must be greater than or equal to 0" });

// When the URL refinement runs: exactly when zod 3 ran it.
//
// zod 3 skipped an object refinement after a TYPE failure (a non-boolean
// `enabled`, a non-string url, NaN from a threshold, an unknown `format`)
// and ran it after VALUE failures. zod 4's default gating matches that for
// every issue here except one: z.number() now rejects ±Infinity as a type
// failure, where zod 3 accepted the number and failed it in int() (a value
// failure). So the gate is "no type failure other than an infinite
// THRESHOLD". Restricting the exception to the threshold paths matters: an
// infinite `webhook_url` is a real type failure, and letting it through
// would reach `webhook_url.trim()` (Codex R3). The gate therefore also
// guarantees `enabled` is a boolean and `webhook_url` a string.
const THRESHOLD_FIELDS = new Set([
  "critical_threshold",
  "high_threshold",
  "license_violation_threshold",
]);
function v3RefinementGate(payload: {
  issues: readonly { code?: string; input?: unknown; path?: readonly PropertyKey[] }[];
}) {
  return payload.issues.every((issue) => {
    if (issue.code === "invalid_value") return false;
    if (issue.code !== "invalid_type") return true;
    return (
      issue.path?.length === 1 &&
      THRESHOLD_FIELDS.has(String(issue.path[0])) &&
      typeof issue.input === "number" &&
      Math.abs(issue.input) === Infinity
    );
  });
}

export const diffWebhookSchema = z
  .object({
    enabled: z.boolean(),
    webhook_url: z.string().optional().default(""),
    webhook_secret: z.string().optional().default(""),
    format: z.enum(DIFF_WEBHOOK_FORMATS, enumError(DIFF_WEBHOOK_FORMATS)),
    critical_threshold: threshold(),
    high_threshold: threshold(),
    license_violation_threshold: threshold(),
  })
  .superRefine((data, ctx) => {
    if (data.enabled && data.webhook_url.trim() === "") {
      ctx.addIssue({
        code: "custom",
        path: ["webhook_url"],
        message: "url_required",
      });
    }
    if (
      data.webhook_url.trim() !== "" &&
      !/^https?:\/\//.test(data.webhook_url)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["webhook_url"],
        message: "url_protocol",
      });
    }
  }, { when: v3RefinementGate });

export type DiffWebhookFormInput = z.input<typeof diffWebhookSchema>;
export type DiffWebhookFormValues = z.output<typeof diffWebhookSchema>;

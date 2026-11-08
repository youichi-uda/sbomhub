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
//     Refinement issues are non-aborting, so the default refinement gating
//     now matches zod 3: type failures (NaN, a bad `format`) abort and skip
//     the URL check, value failures (fractional, negative) do not.
//     (2) zod 4's int() is Number.isSafeInteger and refuses e.g. 2^53;
//     zod 3's was Number.isInteger.
//   - z.number() itself refuses NaN and, new in zod 4, ±Infinity; both were
//     already rejected under zod 3 (NaN by the type check, ±Infinity by int()).
//   - The messages are zod 3's; the page does not render threshold errors.
const threshold = () =>
  z.coerce
    .number()
    .refine((n) => Number.isInteger(n), { error: "Expected integer, received float" })
    .refine((n) => n >= 0, { error: "Number must be greater than or equal to 0" });

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
  });

export type DiffWebhookFormInput = z.input<typeof diffWebhookSchema>;
export type DiffWebhookFormValues = z.output<typeof diffWebhookSchema>;

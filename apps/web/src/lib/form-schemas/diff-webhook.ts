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
//   - The integer check is a refinement, not `.int()`: zod 4's int() reports
//     a fractional value as an ABORTING issue, which would also suppress the
//     url_required / url_protocol refinement below — zod 3 showed both
//     errors together. The refinement keeps zod 3's message.
//   - Number.isSafeInteger also refuses values beyond 2^53 that zod 3's
//     int() accepted (e.g. "1e20"); no Go int threshold can hold those, so
//     this tightens rather than loosens. z.number() itself refuses NaN and
//     (new in zod 4) ±Infinity — both were already rejected by zod 3, via
//     NaN / int().
const threshold = () =>
  z.coerce
    .number()
    .refine((n) => Number.isSafeInteger(n), { error: "Expected integer, received float" })
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
  .superRefine(
    (data, ctx) => {
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
    },
    {
      // zod 4 skips an object refinement once ANY field has failed; zod 3 ran
      // it after non-aborting failures (a negative or fractional threshold),
      // so the form showed the URL error alongside the threshold error. The
      // check only reads `enabled` and `webhook_url`, so run it whenever
      // those two are well-typed.
      when: (payload) => {
        const v = payload.value as { enabled?: unknown; webhook_url?: unknown };
        return typeof v?.enabled === "boolean" && typeof v?.webhook_url === "string";
      },
    },
  );

export type DiffWebhookFormInput = z.input<typeof diffWebhookSchema>;
export type DiffWebhookFormValues = z.output<typeof diffWebhookSchema>;

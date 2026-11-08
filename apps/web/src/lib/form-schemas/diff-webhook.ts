// Form schema for /settings/diff-webhook
// (src/app/[locale]/(dashboard)/settings/diff-webhook/page.tsx). See
// cra-report.ts for why schemas live in zod-only modules. The page maps the
// `url_required` / `url_protocol` message KEYS to next-intl strings, so the
// keys are the contract, not English text.
import { z } from "zod";

export const DIFF_WEBHOOK_FORMATS = ["json", "slack"] as const;
export type DiffWebhookFormat = (typeof DIFF_WEBHOOK_FORMATS)[number];

export const diffWebhookSchema = z
  .object({
    enabled: z.boolean(),
    webhook_url: z.string().optional().default(""),
    webhook_secret: z.string().optional().default(""),
    format: z.enum(DIFF_WEBHOOK_FORMATS),
    critical_threshold: z.coerce.number().int().min(0),
    high_threshold: z.coerce.number().int().min(0),
    license_violation_threshold: z.coerce.number().int().min(0),
  })
  .superRefine((data, ctx) => {
    if (data.enabled && data.webhook_url.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["webhook_url"],
        message: "url_required",
      });
    }
    if (
      data.webhook_url.trim() !== "" &&
      !/^https?:\/\//.test(data.webhook_url)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["webhook_url"],
        message: "url_protocol",
      });
    }
  });

export type DiffWebhookFormValues = z.infer<typeof diffWebhookSchema>;

// What counts as an IPA settings answer from GET /api/v1/settings/ipa (M71,
// Codex R3 Medium). Anything else — empty (204 / null), an array, an object
// without the flags — is a load failure: the page shows an error with Retry
// instead of a form of defaults whose Save would send an empty object.
import type { IPASyncSettings } from "./api";

export function parseIPASyncSettings(value: unknown): IPASyncSettings | null {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.enabled !== "boolean" || typeof v.notify_on_new !== "boolean") return null;
  const sev = v.notify_severity;
  // The API's Go nil slice arrives as null: no severity selected.
  if (sev != null && !(Array.isArray(sev) && sev.every((s) => typeof s === "string"))) return null;
  return { ...(v as unknown as IPASyncSettings), notify_severity: (sev as string[] | null | undefined) ?? [] };
}

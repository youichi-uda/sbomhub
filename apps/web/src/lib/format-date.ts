// Timestamp display shared by the web UI (M71). Was a private copy in
// cra-reports/submission-timeline.tsx and cra-reports/report-card.tsx.

/** Date and minutes, e.g. "Nov 9, 2026, 9:00 AM" / "2026/11/09 9:00". */
export const TIMESTAMP: Intl.DateTimeFormatOptions = { dateStyle: "medium", timeStyle: "short" };

/**
 * Date and time with the time zone, e.g. "Nov 9, 2026, 9:00:00 AM GMT+9",
 * for evidence timestamps whose zone matters (they are stored in UTC).
 */
export const TIMESTAMP_WITH_ZONE: Intl.DateTimeFormatOptions = { dateStyle: "medium", timeStyle: "long" };

/**
 * Formats an RFC 3339 timestamp for the given locale. An unparseable value
 * is returned as is, so a malformed backend value stays inspectable instead
 * of rendering "Invalid Date".
 */
export function formatTimestamp(
  value: string,
  locale: string,
  options: Intl.DateTimeFormatOptions = TIMESTAMP,
): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(locale, options);
}

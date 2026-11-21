// JVN iPedia (JVNDB) advisories attached to a vulnerability (migration 072,
// API field `jvndb`). They come from the JVNDB RSS feeds and are
// SUPPLEMENTARY: matched to the CVE by id, they never detected anything and
// are not a JVN check. This module validates the API value before it is
// rendered; the link is always rebuilt from the id, so no server-supplied
// string becomes an href.

export interface JvndbAdvisory {
  id: string;
  title: string;
  url: string;
  published?: string;
}

const JVNDB_ID = /^JVNDB-(\d{4})-\d{6,12}$/;
const MAX_ADVISORIES = 5;
const MAX_TITLE = 1000;

/** The canonical JVN iPedia (Japanese) page of a JVNDB id, or null. */
export function jvndbAdvisoryUrl(id: unknown): string | null {
  if (typeof id !== "string") return null;
  const m = JVNDB_ID.exec(id);
  if (!m) return null;
  return `https://jvndb.jvn.jp/ja/contents/${m[1]}/${id}.html`;
}

/**
 * The advisories to show, in API order: entries with a malformed id or an
 * empty title are dropped, duplicates removed, at most five kept. Anything
 * that is not an array yields [].
 */
export function parseJvndbAdvisories(raw: unknown): JvndbAdvisory[] {
  if (!Array.isArray(raw)) return [];
  const out: JvndbAdvisory[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (out.length >= MAX_ADVISORIES) break;
    if (!item || typeof item !== "object") continue;
    const { id, title, published } = item as Record<string, unknown>;
    const url = jvndbAdvisoryUrl(id);
    if (!url || seen.has(id as string)) continue;
    if (typeof title !== "string" || title.trim() === "") continue;
    seen.add(id as string);
    // By code point, like the API's limit, never inside a surrogate pair.
    const capped = Array.from(title.trim()).slice(0, MAX_TITLE).join("");
    const advisory: JvndbAdvisory = { id: id as string, title: capped, url };
    if (typeof published === "string" && !Number.isNaN(new Date(published).getTime())) {
      advisory.published = published;
    }
    out.push(advisory);
  }
  return out;
}

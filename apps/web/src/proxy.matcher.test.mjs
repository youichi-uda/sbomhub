// M10-4 #72: regression fixtures for the proxy matcher in proxy.ts.
//
// Why this exists:
//   The matcher excludes paths from middleware invocation. A too-broad
//   exclusion (e.g. the pre-M10-4 `.*\\..*` that matched any path with
//   a dot) lets `/secret.json`, `/leak.txt`, etc. bypass auth defensively
//   if they ever land under apps/web/public/. This fixture pins the
//   tightened allowlist and fails fast if a future edit re-broadens it.
//
// Run:
//   node apps/web/src/proxy.matcher.test.mjs
//
// CI: wired into .github/workflows/frontend-ci.yml (M10-4 #72).
//
// This is intentionally a plain ESM script that uses node:assert so we
// don't have to add a unit-test framework dependency just to assert one
// regex.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const proxySrc = readFileSync(join(__dirname, "proxy.ts"), "utf8");

// Pull the matcher string literal out of proxy.ts so the test sees the
// same pattern Next.js compiles at build time. Format guarded:
//   matcher: ["<pattern>"]
//
// The captured group is the *raw* source-level string (e.g.
// `favicon\\.ico$`); JSON.parse turns the JS-source string literal into
// the runtime string (`favicon\.ico$`) that Next.js / RegExp actually see.
const matcherMatch = proxySrc.match(/matcher:\s*\[\s*("[^"]+")\s*\]/);
assert.ok(
  matcherMatch,
  "could not extract `matcher: [\"...\"]` from proxy.ts; refactor of the export literal broke this fixture",
);
const matcherPattern = JSON.parse(matcherMatch[1]);

// Build a JS RegExp that approximates Next.js' middleware matcher.
// Next.js anchors the matcher at the start of the pathname; we mirror
// that with `^` here. The matcher decides INCLUSION (i.e. middleware
// runs when the path matches). If the path does NOT match the matcher,
// middleware is skipped entirely.
const re = new RegExp("^" + matcherPattern + "$");

const cases = [
  // Paths that MUST invoke middleware (i.e. the matcher MUST match):
  { path: "/", expectInvokes: true, why: "landing page goes through proxy" },
  { path: "/ja", expectInvokes: true, why: "locale root goes through proxy" },
  { path: "/ja/dashboard", expectInvokes: true, why: "auth-required route" },
  { path: "/secret.json", expectInvokes: true, why: "static-extension file at root MUST NOT bypass auth (M10-4)" },
  { path: "/leak.txt", expectInvokes: true, why: "arbitrary .txt at root MUST NOT bypass auth (M10-4)" },
  { path: "/dump.csv", expectInvokes: true, why: "arbitrary .csv at root MUST NOT bypass auth (M10-4)" },
  { path: "/anything.config.yaml", expectInvokes: true, why: "multi-dot path MUST NOT bypass auth (M10-4)" },
  { path: "/public/file.txt", expectInvokes: true, why: "public path goes through proxy (which short-circuits in proxy.ts itself)" },

  // Paths that MUST be excluded (matcher MUST NOT match):
  { path: "/api/v1/projects", expectInvokes: false, why: "API routes bypass middleware" },
  { path: "/api/webhooks/clerk", expectInvokes: false, why: "webhook routes bypass middleware" },
  { path: "/_next/static/chunks/main.js", expectInvokes: false, why: "Next.js asset chunks" },
  { path: "/_next/image", expectInvokes: false, why: "Next.js image optimization" },
  { path: "/_vercel/insights/script.js", expectInvokes: false, why: "Vercel analytics" },
  { path: "/favicon.ico", expectInvokes: false, why: "favicon convention" },
  { path: "/robots.txt", expectInvokes: false, why: "robots convention" },
  { path: "/sitemap.xml", expectInvokes: false, why: "sitemap convention" },
];

let failures = 0;
for (const c of cases) {
  const matches = re.test(c.path);
  const ok = matches === c.expectInvokes;
  if (ok) {
    console.log(`[ok] ${c.path} -> matcher=${matches} (${c.why})`);
  } else {
    failures++;
    console.error(
      `[FAIL] ${c.path}: expected matcher=${c.expectInvokes}, got ${matches} -- ${c.why}`,
    );
  }
}

console.log("---");
console.log(`pattern: ${matcherPattern}`);
console.log(`total: ${cases.length}, failures: ${failures}`);

if (failures > 0) {
  process.exit(1);
}

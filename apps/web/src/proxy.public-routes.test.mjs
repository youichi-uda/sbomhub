// Clerk 7 upgrade: pins which paths proxy.ts's `isPublicRoute` treats as
// public (no sign-in redirect in Clerk mode), using the REAL
// `createRouteMatcher` from the installed @clerk/nextjs.
//
// Why this exists:
//   proxy.matcher.test.mjs pins `config.matcher` (which requests reach the
//   proxy at all). It does not cover the second gate — the public-route
//   allowlist passed to Clerk's `createRouteMatcher`, whose semantics come
//   from @clerk/shared's path matcher and therefore change with Clerk
//   majors. The @clerk/nextjs 6 -> 7 bump moved that matcher from
//   @clerk/shared 3.48 to 4.x; a differential run over this table showed
//   identical results. This fixture makes the next bump prove the same:
//   any path flipping from "protected" to "public" fails here.
//
//   Clerk 7 deprecates createRouteMatcher ("Middleware-based auth checks
//   rely on path matching, which can diverge from how Next.js routes
//   requests"). The rows marked `quirk` record existing over-broad matches
//   (`/:locale` matches any single segment, `/public(.*)` matches
//   `/publicity`). They are pinned as-is so a change in EITHER direction is
//   noticed; tightening them is a separate, tracked change.
//
// Run:
//   node apps/web/src/proxy.public-routes.test.mjs

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const proxySrc = readFileSync(join(__dirname, "proxy.ts"), "utf8");

const block = proxySrc.match(/const isPublicRoute = createRouteMatcher\(\[([\s\S]*?)\]\);/);
assert.ok(block, "could not extract the isPublicRoute createRouteMatcher([...]) list from proxy.ts");
const patterns = [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);

// Silence the Clerk 7 deprecation banner for createRouteMatcher (printed
// once per process) so the test output stays readable.
const origWarn = console.warn;
console.warn = () => {};
const { createRouteMatcher } = require("@clerk/nextjs/server");
const isPublicRoute = createRouteMatcher(patterns);
console.warn = origWarn;

const isPublic = (pathname) => {
  try {
    return isPublicRoute({ nextUrl: { pathname } });
  } catch (e) {
    return `throws ${e && e.name}`;
  }
};

const cases = [
  // Public: landing, auth, legal pages, webhooks, public share links.
  ["/", true],
  ["/ja", true],
  ["/ja/", true],
  ["/en", true],
  ["/public/x", true],
  ["/ja/public/abc", true],
  ["/sign-in", true],
  ["/sign-in/factor-one", true],
  ["/ja/sign-in", true],
  ["/ja/sign-up/verify", true],
  ["/pricing", true],
  ["/ja/pricing", true],
  ["/privacy", true],
  ["/terms", true],
  ["/legal", true],
  ["/ja/privacy", true],
  ["/ja/privacy/", true],
  ["/ja/terms", true],
  ["/ja/legal", true],
  ["/api/webhooks", true],
  ["/api/webhooks/clerk", true],
  // Protected: everything that holds tenant data.
  ["/ja/dashboard", false],
  ["/en/dashboard", false],
  ["/ja/projects/1", false],
  ["/ja/settings", false],
  ["/ja/settings/apikeys", false],
  ["/ja/pricing/x", false],
  ["/ja/privacy/x", false],
  ["/api/other", false],
  ["/api/v1/projects", false],
  ["/JA/dashboard", false],
  ["/ja//dashboard", false],
  ["//ja/dashboard", false],
  ["/ja/%2e%2e/dashboard", false],
  ["/ja/dashboard%00", false],
  ["/ja;/dashboard", false],
  // Malformed percent-encoding is rejected, never treated as public.
  ["/%E0%A4%A", "throws MalformedURLError"],
  // quirk (pre-existing, unchanged by Clerk 7): see header.
  ["/dashboard", true],
  ["/publicity", true],
  ["/ja/publicx", true],
  ["/sign-upx", true],
];

test("isPublicRoute classification is unchanged (Clerk createRouteMatcher)", () => {
  assert.equal(patterns.length, 17, "isPublicRoute pattern count changed — review this table");
  const mismatches = cases
    .map(([path, want]) => [path, want, isPublic(path)])
    .filter(([, want, got]) => want !== got);
  assert.deepEqual(mismatches, [], "public/protected classification drifted: [path, expected, actual]");
});

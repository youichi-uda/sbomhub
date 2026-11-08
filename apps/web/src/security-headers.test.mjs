// Pins apps/web/security-headers.mjs (M65 bug 9): the headers next.config
// sends on every route. The browser-level check (no CSP violations on the
// main pages, self-host and Clerk builds) is the E2E / manual production
// check; this pins the policy text so a later edit is a visible diff.
//
// Run: node --test src/security-headers.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildContentSecurityPolicy,
  buildSecurityHeaders,
  clerkFrontendApiOrigin,
  originOf,
  securityHeadersFromProcessEnv,
} from "../security-headers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pk = (host) => `pk_test_${Buffer.from(`${host}$`).toString("base64")}`;
const directives = (csp) =>
  Object.fromEntries(csp.split("; ").map((d) => [d.split(" ")[0], d.split(" ").slice(1)]));

describe("clerkFrontendApiOrigin", () => {
  test("decodes the Frontend API host from a publishable key", () => {
    assert.equal(clerkFrontendApiOrigin(pk("example-app-12.clerk.accounts.dev")), "https://example-app-12.clerk.accounts.dev");
    assert.equal(
      clerkFrontendApiOrigin(`pk_live_${Buffer.from("clerk.sbomhub.app$").toString("base64")}`),
      "https://clerk.sbomhub.app",
    );
  });
  test("placeholder / malformed keys decode to nothing", () => {
    for (const k of ["pk_test_placeholder", "", undefined, "sk_test_x", pk("not a host"), pk("evil.com/path"), `pk_test_${Buffer.from("a.b.c").toString("base64")}`]) {
      assert.equal(clerkFrontendApiOrigin(k), null, String(k));
    }
  });
});

test("originOf keeps only http(s) origins", () => {
  assert.equal(originOf("http://localhost:8080/x?y"), "http://localhost:8080");
  assert.equal(originOf("https://api.example.com"), "https://api.example.com");
  assert.equal(originOf("javascript:alert(1)"), null);
  assert.equal(originOf("not a url"), null);
  assert.equal(originOf(undefined), null);
});

describe("self-host production policy", () => {
  const csp = buildContentSecurityPolicy({ apiUrl: "http://localhost:8080", dev: false });
  const d = directives(csp);
  test("exact policy", () => {
    assert.equal(
      csp,
      [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "font-src 'self' data:",
        "connect-src 'self' http://localhost:8080",
        "frame-src 'self'",
        "worker-src 'self' blob:",
        "manifest-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join("; "),
    );
  });
  test("no eval, no Clerk, no websocket in production", () => {
    assert.ok(!d["script-src"].includes("'unsafe-eval'"));
    assert.ok(!csp.includes("clerk"));
    assert.ok(!d["connect-src"].includes("ws:"));
  });
});

test("dev adds eval (React Refresh) and HMR websockets only", () => {
  const d = directives(buildContentSecurityPolicy({ apiUrl: "http://localhost:8080", dev: true }));
  assert.ok(d["script-src"].includes("'unsafe-eval'"));
  assert.ok(d["connect-src"].includes("ws:"));
});

test("Clerk mode allows the decoded Frontend API and Clerk's documented hosts", () => {
  const d = directives(
    buildContentSecurityPolicy({ apiUrl: "https://api.sbomhub.app", clerkPublishableKey: pk("clerk.sbomhub.app"), dev: false }),
  );
  assert.deepEqual(d["script-src"], ["'self'", "'unsafe-inline'", "https://clerk.sbomhub.app", "https://challenges.cloudflare.com"]);
  assert.deepEqual(d["connect-src"], ["'self'", "https://api.sbomhub.app", "https://clerk.sbomhub.app", "https://clerk-telemetry.com"]);
  assert.ok(d["img-src"].includes("https://img.clerk.com"));
  assert.ok(d["frame-src"].includes("https://challenges.cloudflare.com"));
  assert.deepEqual(d["frame-ancestors"], ["'none'"]);
});

test("an undecodable Clerk key falls back to Clerk's hosted dev domains", () => {
  const d = directives(buildContentSecurityPolicy({ clerkPublishableKey: "pk_test_placeholder", dev: false }));
  assert.ok(d["script-src"].includes("https://*.clerk.accounts.dev"));
  assert.ok(d["connect-src"].includes("http://localhost:8080"), "API defaults like lib/api.ts does");
});

test("waitlist form endpoint is reachable when configured", () => {
  const d = directives(
    buildContentSecurityPolicy({ apiUrl: "http://localhost:8080", waitlistFormUrl: "https://formspree.io/f/abc", dev: false }),
  );
  assert.ok(d["connect-src"].includes("https://formspree.io"));
});

test("header set, and report-only switch", () => {
  const h = Object.fromEntries(buildSecurityHeaders({ dev: false }).map(({ key, value }) => [key, value]));
  assert.equal(h["X-Content-Type-Options"], "nosniff");
  assert.equal(h["X-Frame-Options"], "DENY");
  assert.equal(h["Referrer-Policy"], "strict-origin-when-cross-origin");
  assert.match(h["Permissions-Policy"], /camera=\(\)/);
  assert.ok(h["Content-Security-Policy"]);
  const ro = buildSecurityHeaders({ dev: false, reportOnly: true }).map((x) => x.key);
  assert.ok(ro.includes("Content-Security-Policy-Report-Only"));
  assert.ok(!ro.includes("Content-Security-Policy"));
  assert.ok(ro.includes("X-Frame-Options"), "framing stays denied in report-only mode");
});

test("process env mapping", () => {
  const h = securityHeadersFromProcessEnv({ NODE_ENV: "production", NEXT_PUBLIC_API_URL: "http://localhost:18480", SBOMHUB_CSP_REPORT_ONLY: "true" });
  const csp = h.find((x) => x.key === "Content-Security-Policy-Report-Only").value;
  assert.match(csp, /connect-src 'self' http:\/\/localhost:18480(;|$)/);
});

test("next.config wires it in and turns X-Powered-By off", () => {
  const cfg = readFileSync(join(here, "..", "next.config.mjs"), "utf8");
  assert.match(cfg, /poweredByHeader:\s*false/);
  assert.match(cfg, /source:\s*'\/:path\*',\s*headers:\s*securityHeadersFromProcessEnv\(process\.env\)/);
});

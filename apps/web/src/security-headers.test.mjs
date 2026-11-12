// Pins apps/web/security-headers.mjs (M65 bug 9, M71 nonce): the static
// headers next.config sends on every route and the per-request CSP the proxy
// sets. The browser-level check (no CSP violations on the main pages,
// self-host and Clerk builds) is e2e/security.spec.ts / the manual Clerk
// check; this pins the policy text so a later edit is a visible diff.
//
// Run: node --test src/security-headers.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  FALLBACK_CSP,
  applyNonceCsp,
  buildContentSecurityPolicy,
  buildSecurityHeaders,
  clerkFrontendApiOrigin,
  nextConfigHeaders,
  cspEnvFromProcessEnv,
  cspHeaderName,
  generateNonce,
  nonceRequestHeaders,
  originOf,
} from "../security-headers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pk = (host) => `pk_test_${Buffer.from(`${host}$`).toString("base64")}`;
const N = "AAAAAAAAAAAAAAAAAAAAAA==";
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
  const csp = buildContentSecurityPolicy({ nonce: N, apiUrl: "http://localhost:8080", dev: false });
  const d = directives(csp);
  test("exact policy", () => {
    assert.equal(
      csp,
      [
        "default-src 'self'",
        `script-src 'self' 'nonce-${N}' 'strict-dynamic'`,
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
  test("no inline script without the nonce (M71)", () => {
    assert.ok(!d["script-src"].includes("'unsafe-inline'"));
    assert.ok(d["script-src"].includes(`'nonce-${N}'`));
    assert.ok(d["script-src"].includes("'strict-dynamic'"));
  });
  test("no eval, no Clerk, no websocket in production", () => {
    assert.ok(!d["script-src"].includes("'unsafe-eval'"));
    assert.ok(!csp.includes("clerk"));
    assert.ok(!d["connect-src"].includes("ws:"));
  });
});

test("dev adds eval (React Refresh) and HMR websockets only", () => {
  const d = directives(buildContentSecurityPolicy({ nonce: N, apiUrl: "http://localhost:8080", dev: true }));
  assert.ok(d["script-src"].includes("'unsafe-eval'"));
  assert.ok(d["connect-src"].includes("ws:"));
});

test("Clerk mode allows the decoded Frontend API and Clerk's documented hosts", () => {
  const d = directives(
    buildContentSecurityPolicy({ nonce: N, apiUrl: "https://api.sbomhub.app", clerkPublishableKey: pk("clerk.sbomhub.app"), dev: false }),
  );
  // Clerk's manual CSP (clerk.com/docs/guides/secure/best-practices/csp-headers):
  // FAPI, Turnstile, and abuse/fraud protection (*.protect.clerk.com, served
  // on non-443 ports, hence ":*" in connect-src). Codex R1 High.
  assert.deepEqual(d["script-src"], [
    "'self'", `'nonce-${N}'`, "'strict-dynamic'", "https://clerk.sbomhub.app", "https://challenges.cloudflare.com", "https://*.protect.clerk.com",
  ]);
  assert.deepEqual(d["connect-src"], [
    "'self'", "https://api.sbomhub.app", "https://clerk.sbomhub.app", "https://*.protect.clerk.com:*", "https://clerk-telemetry.com",
  ]);
  assert.ok(d["img-src"].includes("https://img.clerk.com"));
  assert.deepEqual(d["frame-src"], ["'self'", "https://challenges.cloudflare.com", "https://*.protect.clerk.com"]);
  assert.deepEqual(d["form-action"], ["'self'"]);
  assert.deepEqual(d["frame-ancestors"], ["'none'"]);
});

test("an undecodable Clerk key falls back to Clerk's hosted dev domains", () => {
  const d = directives(buildContentSecurityPolicy({ nonce: N, clerkPublishableKey: "pk_test_placeholder", dev: false }));
  assert.ok(d["script-src"].includes("https://*.clerk.accounts.dev"));
  assert.ok(d["connect-src"].includes("http://localhost:8080"), "API defaults like lib/api.ts does");
});

test("waitlist form endpoint is reachable when configured", () => {
  const d = directives(
    buildContentSecurityPolicy({ nonce: N, apiUrl: "http://localhost:8080", waitlistFormUrl: "https://formspree.io/f/abc", dev: false }),
  );
  assert.ok(d["connect-src"].includes("https://formspree.io"));
});

test("a policy without a valid nonce is refused, never 'unsafe-inline'", () => {
  for (const nonce of [undefined, "", "short", "has space AAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAA'; script-src *", "<AAAAAAAAAAAAAAAAAAAAAAA>"]) {
    assert.throws(() => buildContentSecurityPolicy({ nonce, dev: false }), /nonce is required/, String(nonce));
  }
});

test("generateNonce: 128-bit base64, fresh every call", () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i++) {
    const n = generateNonce();
    assert.match(n, /^[A-Za-z0-9+/]{22}==$/);
    assert.equal(Buffer.from(n, "base64").length, 16);
    seen.add(n);
  }
  assert.equal(seen.size, 1000);
  // and it is accepted by the policy builder
  assert.match(buildContentSecurityPolicy({ nonce: generateNonce() }), /'nonce-[A-Za-z0-9+/]{22}=='/);
});

test("static header set: no CSP (the proxy sets it per request)", () => {
  const h = Object.fromEntries(buildSecurityHeaders().map(({ key, value }) => [key, value]));
  assert.equal(h["X-Content-Type-Options"], "nosniff");
  assert.equal(h["X-Frame-Options"], "DENY", "framing stays denied in report-only mode too");
  assert.equal(h["Referrer-Policy"], "strict-origin-when-cross-origin");
  assert.match(h["Permissions-Policy"], /camera=\(\)/);
  assert.equal(h["Content-Security-Policy"], undefined);
  assert.equal(h["Content-Security-Policy-Report-Only"], undefined);
});

test("report-only switch and process env mapping", () => {
  assert.equal(cspHeaderName(false), "Content-Security-Policy");
  assert.equal(cspHeaderName(true), "Content-Security-Policy-Report-Only");
  const env = cspEnvFromProcessEnv({ NODE_ENV: "production", NEXT_PUBLIC_API_URL: "http://localhost:18480", SBOMHUB_CSP_REPORT_ONLY: "true" });
  assert.equal(env.reportOnly, true);
  assert.equal(env.dev, false);
  assert.match(buildContentSecurityPolicy({ ...env, nonce: N }), /connect-src 'self' http:\/\/localhost:18480(;|$)/);
  assert.equal(cspEnvFromProcessEnv({ NODE_ENV: "production" }).reportOnly, false);
  assert.equal(cspEnvFromProcessEnv({ NODE_ENV: "development" }).dev, true);
});

describe("nonce request headers (client cannot supply its own nonce)", () => {
  const csp = buildContentSecurityPolicy({ nonce: N });
  test("incoming CSP / x-nonce headers are dropped, ours set", () => {
    const incoming = new Headers({
      accept: "text/html",
      "content-security-policy": "script-src 'nonce-attacker'",
      "content-security-policy-report-only": "script-src 'nonce-attacker'",
      "x-nonce": "attacker",
    });
    const h = nonceRequestHeaders(incoming, { nonce: N, csp, headerName: "Content-Security-Policy" });
    assert.equal(h.get("accept"), "text/html");
    assert.equal(h.get("content-security-policy"), csp);
    assert.equal(h.get("content-security-policy-report-only"), null);
    assert.equal(h.get("x-nonce"), N);
    assert.equal(incoming.get("x-nonce"), "attacker", "input not mutated");
  });
  test("report-only mode forwards the policy under the report-only name", () => {
    const h = nonceRequestHeaders(new Headers({ "content-security-policy": "x" }), {
      nonce: N, csp, headerName: "Content-Security-Policy-Report-Only",
    });
    assert.equal(h.get("content-security-policy"), null);
    assert.equal(h.get("content-security-policy-report-only"), csp);
  });
});

describe("applyNonceCsp: every rendered response forwards the nonce", () => {
  const csp = buildContentSecurityPolicy({ nonce: N });
  const opts = { csp, headerName: "Content-Security-Policy" };
  const req = nonceRequestHeaders(new Headers({ accept: "text/html", cookie: "a=b" }), { nonce: N, ...opts });
  const forwarded = (res) =>
    Object.fromEntries(
      res.get("x-middleware-override-headers").split(",").map((k) => [k, res.get(`x-middleware-request-${k}`)]),
    );

  test("bare NextResponse.next() (forwarded nothing): forwards the whole request", () => {
    const res = new Headers({ "x-middleware-next": "1" });
    applyNonceCsp(res, req, opts);
    assert.equal(res.get("content-security-policy"), csp);
    assert.deepEqual(forwarded(res), { accept: "text/html", cookie: "a=b", "content-security-policy": csp, "x-nonce": N });
  });

  test("next-intl style forward of a stale set: values replaced, other headers kept", () => {
    const res = new Headers({
      "x-middleware-rewrite": "http://x/en",
      "x-middleware-override-headers": "accept,x-next-intl-locale,content-security-policy-report-only,x-nonce",
      "x-middleware-request-accept": "text/html",
      "x-middleware-request-x-next-intl-locale": "en",
      "x-middleware-request-content-security-policy-report-only": "script-src 'nonce-attacker'",
      "x-middleware-request-x-nonce": "attacker",
    });
    applyNonceCsp(res, req, opts);
    const f = forwarded(res);
    assert.deepEqual(f, { accept: "text/html", "x-next-intl-locale": "en", "content-security-policy": csp, "x-nonce": N });
    assert.equal(res.get("x-middleware-request-content-security-policy-report-only"), null);
  });

  test("a redirect gets the response header only", () => {
    const res = new Headers({ location: "/en/sign-in" });
    applyNonceCsp(res, req, opts);
    assert.equal(res.get("content-security-policy"), csp);
    assert.equal(res.get("x-middleware-override-headers"), null);
  });
});

describe("paths the proxy never sees get a no-script CSP from next.config (Codex M71 R1 Low)", () => {
  // Next renders its HTML 404 for e.g. /api/x or /_next/x; those paths are
  // outside the proxy matcher, so they would otherwise carry no CSP at all.
  const rules = nextConfigHeaders({ reportOnly: false });
  const cspRules = rules.filter((r) => r.headers.some((h) => h.key === "Content-Security-Policy"));
  const toRe = (source) =>
    // path-to-regexp subset used here: ":path*" and ":path(<regex>)"
    new RegExp("^" + source.replace(/:path\*/g, ".*").replace(/:path\((.*)\)$/, "$1") + "$");
  // Unconditional rules only; the /_next/static rules are gated on a request
  // header (pinned separately below).
  const covered = (p) => cspRules.some((r) => !r.has && !r.missing && toRe(r.source).test(p));

  test("static headers on every route", () => {
    assert.deepEqual(rules[0], { source: "/:path*", headers: buildSecurityHeaders() });
  });
  test("fallback policy runs nothing", () => {
    assert.equal(FALLBACK_CSP, "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  });
  for (const p of ["/api", "/api/does-not-exist", "/api/webhooks/x", "/_next", "/_next/nope", "/_next/image", "/_next/data/x.json", "/_vercel", "/_vercel/insights"]) {
    test(`covers ${p}`, () => assert.ok(covered(p), p));
  }
  // Pages get the nonce CSP from the proxy; a second, stricter CSP here would
  // block them. /_next/static is not covered unconditionally, so a worker
  // script is not restricted by a document policy.
  for (const p of ["/", "/en", "/en/projects", "/apisomething", "/public/x", "/_next/static/chunks/a.js"]) {
    test(`leaves ${p} alone`, () => assert.ok(!covered(p), p));
  }
  test("/_next/static gets it only for document / frame loads (Codex M71 R2 Low)", () => {
    const r = cspRules.find((x) => x.source === "/_next/static/:path*");
    assert.ok(r, "rule present");
    assert.deepEqual(r.has, [{ type: "header", key: "sec-fetch-dest", value: "(document|iframe|frame|embed|object)" }]);
    // A worker / script fetch (sec-fetch-dest: worker / script) does not match.
    const re = new RegExp(`^${r.has[0].value}$`);
    for (const d of ["document", "iframe"]) assert.ok(re.test(d), d);
    for (const d of ["worker", "sharedworker", "serviceworker", "script", "style", "image", "empty"]) assert.ok(!re.test(d), d);
  });
  test("/_next/static also gets it when the client sends no Fetch Metadata (Codex M71 R3 Low)", () => {
    const r = cspRules.find((x) => x.source === "/_next/static/:path*" && x.missing);
    assert.ok(r, "rule present");
    assert.deepEqual(r.missing, [{ type: "header", key: "sec-fetch-dest" }]);
  });
  test("report-only switch applies to the fallback too", () => {
    const ro = nextConfigHeaders({ reportOnly: true });
    assert.ok(ro.some((r) => r.headers.some((h) => h.key === "Content-Security-Policy-Report-Only")));
    assert.ok(!ro.some((r) => r.headers.some((h) => h.key === "Content-Security-Policy")));
  });
  test("the excluded prefixes match proxy.ts's matcher", () => {
    const src = readFileSync(join(here, "proxy.ts"), "utf8");
    for (const prefix of ["api", "_next", "_vercel"]) {
      assert.match(src, new RegExp(`\\b${prefix}/\\|${prefix}\\$`), prefix);
    }
  });
});

test("next.config wires the headers in and turns X-Powered-By off", () => {
  const cfg = readFileSync(join(here, "..", "next.config.mjs"), "utf8");
  assert.match(cfg, /poweredByHeader:\s*false/);
  assert.match(cfg, /return nextConfigHeaders\(\{\s*reportOnly:/);
  assert.match(cfg, /SBOMHUB_CSP_REPORT_ONLY:\s*process\.env\.SBOMHUB_CSP_REPORT_ONLY/);
});

test("proxy.ts sets the nonce CSP on every response it returns", () => {
  const src = readFileSync(join(here, "proxy.ts"), "utf8");
  assert.match(src, /const nonce = generateNonce\(\);/);
  assert.match(src, /buildContentSecurityPolicy\(\{ \.\.\.CSP_ENV, nonce \}\)/);
  assert.match(src, /applyNonceCsp\(response\.headers, reqHeaders/);
  // Build-time inlining needs literal member accesses, not the env object.
  assert.doesNotMatch(src, /cspEnvFromProcessEnv\(process\.env\)/);
});

// HTTP security headers for every page the web app serves (M65 bug 9 / E2E
// "should have appropriate security headers"). Pure so node:test can pin it
// (src/security-headers.test.mjs).
//
// Before M65, pages carried no security headers at all and advertised
// `X-Powered-By: Next.js`.
//
// Two halves:
//   - buildSecurityHeaders(): the static headers (nosniff, frame denial,
//     Referrer-Policy, Permissions-Policy). next.config.mjs sends them on
//     every route.
//   - buildContentSecurityPolicy({ nonce }): the CSP. It carries a fresh
//     nonce per request, so it is set by the proxy (src/proxy.ts), not by
//     next.config (M71; M66 shipped a build-time policy with
//     script-src 'unsafe-inline').
//
// Content-Security-Policy
// -----------------------
//   - script-src is 'nonce-<per request>' 'strict-dynamic'. Next.js reads
//     the nonce from the request's CSP header and puts it on every script it
//     renders (framework, page chunks, the inline RSC payload); scripts
//     those load are trusted through 'strict-dynamic'. The Clerk script tag
//     gets the nonce from <ClerkProvider nonce>. 'self' and the Clerk hosts
//     stay listed for CSP2-only browsers (CSP3 browsers ignore them next to
//     'strict-dynamic'). There is no 'unsafe-inline'. 'unsafe-eval' is
//     added for `next dev` only (React Refresh).
//   - style-src keeps 'unsafe-inline': React `style={...}` attributes are
//     used across the app and by its UI libraries (e.g. @xyflow/react), and
//     Clerk injects its styles at runtime. A nonce cannot cover style
//     attributes; only 'unsafe-inline' (or 'unsafe-hashes' per value) can.
//     Inline style cannot run script.
//   - connect-src is the API origin (NEXT_PUBLIC_API_URL, inlined at build
//     time), the optional waitlist form endpoint, and, in Clerk mode, the
//     Clerk Frontend API.
//   - Clerk mode adds what Clerk documents for a manual CSP: its Frontend
//     API host for scripts / XHR, img.clerk.com, Cloudflare Turnstile
//     (challenges.cloudflare.com), abuse / fraud protection
//     (*.protect.clerk.com), blob: workers.
//   - frame-ancestors 'none' (and X-Frame-Options: DENY for old browsers):
//     no route is designed to be embedded. Public share links
//     (/[locale]/public/[token]) are full pages, not widgets, and there is
//     no badge route in the web app.
// SBOMHUB_CSP_REPORT_ONLY=true at build time sends the CSP as
// Content-Security-Policy-Report-Only instead (escape hatch for a deployment
// that loads something this policy does not know about); framing stays
// denied through X-Frame-Options either way.

/**
 * Clerk publishable keys are `pk_(test|live)_<base64("<frontend-api-host>$")>`.
 * Returns the Frontend API origin, or null when the key does not decode to
 * a plausible host (e.g. CI's `pk_test_placeholder`).
 */
export function clerkFrontendApiOrigin(publishableKey) {
  const m = /^pk_(?:test|live)_([A-Za-z0-9+/=_-]+)$/.exec(publishableKey ?? "");
  if (!m) return null;
  let decoded;
  try {
    decoded = Buffer.from(m[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  } catch {
    return null;
  }
  const host = decoded.endsWith("$") ? decoded.slice(0, -1) : "";
  // A DNS host name: labels of [a-z0-9-], at least one dot, no scheme/path.
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(host)) return null;
  return `https://${host.toLowerCase()}`;
}

/** Origin of an absolute http(s) URL, or null. */
export function originOf(url) {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u.origin : null;
  } catch {
    return null;
  }
}

/** A CSP nonce is base64 (RFC 4648 §4), 128 bits or more. */
const NONCE_RE = /^[A-Za-z0-9+/]{22,}={0,2}$/;

/** A fresh nonce: 16 random bytes, base64. Web Crypto (Node >= 19, edge). */
export function generateNonce() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/**
 * @param {{
 *   nonce: string,
 *   apiUrl?: string,
 *   clerkPublishableKey?: string,
 *   waitlistFormUrl?: string,
 *   dev?: boolean,
 *   reportOnly?: boolean,
 * }} env
 * @returns {string} the Content-Security-Policy value
 */
export function buildContentSecurityPolicy(env) {
  // No nonce means no way to run the App Router's inline scripts. Refuse
  // rather than fall back to 'unsafe-inline'.
  if (typeof env.nonce !== "string" || !NONCE_RE.test(env.nonce)) {
    throw new Error("buildContentSecurityPolicy: a base64 nonce is required");
  }
  const clerkEnabled = !!env.clerkPublishableKey;
  // A key that does not decode (placeholder / malformed) still gets Clerk's
  // default hosted domains, so a dev instance keeps working.
  const clerkFapi = clerkEnabled
    ? (clerkFrontendApiOrigin(env.clerkPublishableKey) ?? "https://*.clerk.accounts.dev")
    : null;
  const api = originOf(env.apiUrl || "http://localhost:8080");
  const waitlist = originOf(env.waitlistFormUrl);

  const script = ["'self'", `'nonce-${env.nonce}'`, "'strict-dynamic'"];
  if (env.dev) script.push("'unsafe-eval'");
  const connect = ["'self'"];
  if (api) connect.push(api);
  if (waitlist && waitlist !== api) connect.push(waitlist);
  if (env.dev) connect.push("ws:", "wss:");
  const img = ["'self'", "data:", "blob:"];
  const frame = ["'self'"];
  const worker = ["'self'", "blob:"];
  if (clerkFapi) {
    // Clerk's documented manual CSP: Frontend API, Cloudflare Turnstile
    // (bot protection) and abuse / fraud protection (*.protect.clerk.com,
    // served on non-443 ports, hence ":*" in connect-src). Telemetry is
    // from Clerk middleware's default policy.
    script.push(clerkFapi, "https://challenges.cloudflare.com", "https://*.protect.clerk.com");
    connect.push(clerkFapi, "https://*.protect.clerk.com:*", "https://clerk-telemetry.com");
    img.push("https://img.clerk.com");
    frame.push("https://challenges.cloudflare.com", "https://*.protect.clerk.com");
  }

  const directives = [
    ["default-src", ["'self'"]],
    ["script-src", script],
    ["style-src", ["'self'", "'unsafe-inline'"]],
    ["img-src", img],
    ["font-src", ["'self'", "data:"]],
    ["connect-src", connect],
    ["frame-src", frame],
    ["worker-src", worker],
    ["manifest-src", ["'self'"]],
    ["object-src", ["'none'"]],
    ["base-uri", ["'self'"]],
    ["form-action", ["'self'"]],
    ["frame-ancestors", ["'none'"]],
  ];
  return directives.map(([name, values]) => `${name} ${values.join(" ")}`).join("; ");
}

/** The header the CSP travels in (request and response). */
export function cspHeaderName(reportOnly) {
  return reportOnly ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy";
}

/**
 * Static headers applied to every route (next.config `headers()`). The CSP
 * is not among them: it carries a per-request nonce and is set by the proxy.
 */
export function buildSecurityHeaders() {
  return [
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "X-Frame-Options", value: "DENY" },
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    {
      key: "Permissions-Policy",
      value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
    },
  ];
}

/**
 * CSP for the paths the proxy never sees (its matcher skips /api, /_next,
 * /_vercel). Nothing the app serves there is a page, but Next answers an
 * unknown path there with its HTML 404, and without this it would carry no
 * CSP at all (Codex M71 R1 Low). It runs nothing.
 */
export const FALLBACK_CSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/**
 * next.config `headers()`: the static headers on every route, plus
 * FALLBACK_CSP on the prefixes outside the proxy matcher. /_next/static gets
 * it only on document loads (a worker script's own CSP would restrict that
 * worker); pages must not get it either, since two CSPs are both enforced.
 */
export function nextConfigHeaders({ reportOnly }) {
  const csp = [{ key: cspHeaderName(reportOnly), value: FALLBACK_CSP }];
  return [
    { source: "/:path*", headers: buildSecurityHeaders() },
    { source: "/api", headers: csp },
    { source: "/api/:path*", headers: csp },
    { source: "/_vercel", headers: csp },
    { source: "/_vercel/:path*", headers: csp },
    { source: "/_next", headers: csp },
    { source: "/_next/:path((?!static/).*)", headers: csp },
    // A missing /_next/static file is answered with the HTML 404 too. Only
    // when it is loaded as a document / frame (Codex M71 R2 Low), so a
    // worker script's fetch never picks up this policy.
    {
      source: "/_next/static/:path*",
      has: [{ type: "header", key: "sec-fetch-dest", value: "(document|iframe|frame|embed|object)" }],
      headers: csp,
    },
    // ...or by a client that sends no Fetch Metadata at all (Codex M71 R3
    // Low). Such a client is not a current browser loading a worker.
    { source: "/_next/static/:path*", missing: [{ type: "header", key: "sec-fetch-dest" }], headers: csp },
  ];
}

/**
 * The CSP inputs. src/proxy.ts passes `process.env.X` member accesses
 * (not the process.env object), so Next inlines the NEXT_PUBLIC_* values
 * and SBOMHUB_CSP_REPORT_ONLY (next.config.mjs `env`) at build time and a
 * running image keeps the policy it was built with, as before.
 */
export function cspEnvFromProcessEnv(processEnv) {
  return {
    apiUrl: processEnv.NEXT_PUBLIC_API_URL,
    clerkPublishableKey: processEnv.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY,
    waitlistFormUrl: processEnv.NEXT_PUBLIC_WAITLIST_FORM_URL,
    dev: processEnv.NODE_ENV !== "production",
    reportOnly: /^(1|true)$/i.test(processEnv.SBOMHUB_CSP_REPORT_ONLY ?? ""),
  };
}

// Request headers that carry the nonce to the renderer. Next.js and Clerk
// read the nonce from whichever of these the request has, so a client must
// not be able to supply its own: the proxy deletes them all and sets only
// the ones it minted.
export const NONCE_REQUEST_HEADERS = [
  "content-security-policy",
  "content-security-policy-report-only",
  "x-nonce",
];

/**
 * Request headers for the renderer: the incoming ones minus any
 * client-supplied CSP / x-nonce, plus this request's policy and nonce.
 * @param {Headers} incoming
 * @param {{ nonce: string, csp: string, headerName: string }} p
 * @returns {Headers}
 */
export function nonceRequestHeaders(incoming, { nonce, csp, headerName }) {
  const h = new Headers(incoming);
  for (const k of NONCE_REQUEST_HEADERS) h.delete(k);
  h.set(headerName, csp);
  h.set("x-nonce", nonce);
  return h;
}

const OVERRIDE = "x-middleware-override-headers";
const REQ_PREFIX = "x-middleware-request-";

/**
 * Makes a proxy response carry the CSP to the browser and the nonce to the
 * renderer.
 *
 * The renderer only sees request headers the response forwards (Next's
 * `x-middleware-override-headers` protocol, which NextResponse.next({
 * request: { headers } }) writes). next-intl and Clerk forward the request
 * they were given; this also covers a response that forwarded nothing (a
 * bare NextResponse.next()) or an older header set, so a page can never
 * render with a policy whose nonce it does not know.
 *
 * @param {Headers} res response headers (mutated)
 * @param {Headers} req the request headers from nonceRequestHeaders()
 * @param {{ csp: string, headerName: string }} p
 */
export function applyNonceCsp(res, req, { csp, headerName }) {
  res.set(headerName, csp);
  const forwards = res.has("x-middleware-next") || res.has("x-middleware-rewrite");
  const override = res.get(OVERRIDE);
  if (override === null && !forwards) return; // redirect / direct response: nothing renders
  let keys;
  if (override === null) {
    // Nothing forwarded yet: forward the whole request, as NextResponse.next
    // would have.
    keys = [...req.keys()];
    req.forEach((v, k) => res.set(REQ_PREFIX + k, v));
  } else {
    keys = override.split(",").map((k) => k.trim().toLowerCase()).filter(Boolean);
  }
  keys = keys.filter((k) => !NONCE_REQUEST_HEADERS.includes(k));
  for (const k of NONCE_REQUEST_HEADERS) res.delete(REQ_PREFIX + k);
  for (const k of NONCE_REQUEST_HEADERS) {
    const v = req.get(k);
    if (v !== null) {
      keys.push(k);
      res.set(REQ_PREFIX + k, v);
    }
  }
  res.set(OVERRIDE, keys.join(","));
}

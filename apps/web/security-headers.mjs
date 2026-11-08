// HTTP security headers for every page the web app serves (M65 bug 9 / E2E
// "should have appropriate security headers"). Imported by next.config.mjs;
// pure so node:test can pin it (src/security-headers.test.mjs).
//
// Before this, pages carried no security headers at all and advertised
// `X-Powered-By: Next.js`.
//
// Content-Security-Policy
// -----------------------
// The policy is the one the app actually passes (checked in a real
// production build, self-host and Clerk, with no console violations):
//   - script-src keeps 'unsafe-inline': the App Router streams its RSC
//     payload in inline <script> tags, and removing that needs a per-request
//     nonce (middleware + fully dynamic rendering). 'unsafe-eval' is added
//     for `next dev` only (React Refresh).
//   - connect-src is the API origin (NEXT_PUBLIC_API_URL, inlined at build
//     time like everything else here), the optional waitlist form endpoint,
//     and, in Clerk mode, the Clerk Frontend API.
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

/**
 * @param {{
 *   apiUrl?: string,
 *   clerkPublishableKey?: string,
 *   waitlistFormUrl?: string,
 *   dev?: boolean,
 *   reportOnly?: boolean,
 * }} env
 * @returns {string} the Content-Security-Policy value
 */
export function buildContentSecurityPolicy(env) {
  const clerkEnabled = !!env.clerkPublishableKey;
  // A key that does not decode (placeholder / malformed) still gets Clerk's
  // default hosted domains, so a dev instance keeps working.
  const clerkFapi = clerkEnabled
    ? (clerkFrontendApiOrigin(env.clerkPublishableKey) ?? "https://*.clerk.accounts.dev")
    : null;
  const api = originOf(env.apiUrl || "http://localhost:8080");
  const waitlist = originOf(env.waitlistFormUrl);

  const script = ["'self'", "'unsafe-inline'"];
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

/** Headers applied to every route (next.config `headers()`). */
export function buildSecurityHeaders(env) {
  return [
    {
      key: env.reportOnly ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy",
      value: buildContentSecurityPolicy(env),
    },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "X-Frame-Options", value: "DENY" },
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    {
      key: "Permissions-Policy",
      value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
    },
  ];
}

/** Reads the build environment the way next.config.mjs sees it. */
export function securityHeadersFromProcessEnv(processEnv) {
  return buildSecurityHeaders({
    apiUrl: processEnv.NEXT_PUBLIC_API_URL,
    clerkPublishableKey: processEnv.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY,
    waitlistFormUrl: processEnv.NEXT_PUBLIC_WAITLIST_FORM_URL,
    dev: processEnv.NODE_ENV !== "production",
    reportOnly: /^(1|true)$/i.test(processEnv.SBOMHUB_CSP_REPORT_ONLY ?? ""),
  });
}

import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import createIntlMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";
import { NextResponse } from "next/server";
import type { NextRequest, NextFetchEvent } from "next/server";
import {
  applyNonceCsp,
  buildContentSecurityPolicy,
  cspEnvFromProcessEnv,
  cspHeaderName,
  generateNonce,
  nonceRequestHeaders,
} from "../security-headers.mjs";

const intlMiddleware = createIntlMiddleware(routing);

// Routes that don't require authentication
const isPublicRoute = createRouteMatcher([
  "/",
  "/:locale",
  "/public(.*)",
  "/:locale/public(.*)",
  "/sign-in(.*)",
  "/sign-up(.*)",
  "/:locale/sign-in(.*)",
  "/:locale/sign-up(.*)",
  "/:locale/pricing",
  "/pricing",
  "/:locale/privacy",
  "/:locale/terms",
  "/:locale/legal",
  "/privacy",
  "/terms",
  "/legal",
  "/api/webhooks(.*)",
]);

// Check if Clerk is configured (SaaS mode) at build time
const CLERK_ENABLED = !!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;

// Clerk middleware handler for SaaS mode
const clerkHandler = clerkMiddleware(
  async (auth, req) => {
    const { userId } = await auth();
    const pathname = req.nextUrl.pathname;
    const localeMatch = pathname.match(/^\/([a-z]{2})(\/|$)/);
    const locale = localeMatch ? localeMatch[1] : "ja";

    // Redirect authenticated users from landing page to dashboard
    if (userId && (pathname === "/" || pathname === `/${locale}` || pathname === `/${locale}/`)) {
      const dashboardUrl = req.nextUrl.clone();
      dashboardUrl.pathname = `/${locale}/dashboard`;
      return NextResponse.redirect(dashboardUrl);
    }

    // Check if route requires auth
    if (!isPublicRoute(req)) {
      if (!userId) {
        // Redirect to sign-in page with redirect_url
        const signInUrl = req.nextUrl.clone();
        signInUrl.pathname = `/${locale}/sign-in`;
        signInUrl.searchParams.set("redirect_url", req.nextUrl.pathname);
        return NextResponse.redirect(signInUrl);
      }
    }

    // Run i18n middleware
    return intlMiddleware(req);
  },
  {
    signInUrl: "/ja/sign-in",
    signUpUrl: "/ja/sign-up",
  }
);

// M71: Content-Security-Policy with a per-request nonce (security-headers.mjs).
// `process.env.X` member accesses so Next inlines them at build time.
const CSP_ENV = cspEnvFromProcessEnv({
  NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL,
  NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY,
  NEXT_PUBLIC_WAITLIST_FORM_URL: process.env.NEXT_PUBLIC_WAITLIST_FORM_URL,
  NODE_ENV: process.env.NODE_ENV,
  SBOMHUB_CSP_REPORT_ONLY: process.env.SBOMHUB_CSP_REPORT_ONLY,
});
const CSP_HEADER = cspHeaderName(CSP_ENV.reportOnly);

async function route(request: NextRequest): Promise<Response> {
  if (request.nextUrl.pathname.startsWith("/public/")) {
    return NextResponse.next();
  }

  if (!CLERK_ENABLED) {
    // Self-hosted mode: just use i18n middleware
    return intlMiddleware(request);
  }

  // SaaS mode: use Clerk middleware
  return (await clerkHandler(request, {} as NextFetchEvent)) ?? NextResponse.next();
}

// Main proxy - conditionally use Clerk
export default async function proxy(request: NextRequest) {
  // Next.js puts the nonce from the request's CSP header on the scripts it
  // renders; Clerk reads x-nonce. The request headers are replaced here,
  // before next-intl / Clerk copy them into the headers they forward, and
  // applyNonceCsp makes sure every rendered response forwards them.
  const nonce = generateNonce();
  const csp = buildContentSecurityPolicy({ ...CSP_ENV, nonce });
  const reqHeaders = nonceRequestHeaders(request.headers, { nonce, csp, headerName: CSP_HEADER });
  for (const k of [...request.headers.keys()]) {
    if (!reqHeaders.has(k)) request.headers.delete(k);
  }
  reqHeaders.forEach((v, k) => request.headers.set(k, v));

  let response = await route(request);
  try {
    applyNonceCsp(response.headers, reqHeaders, { csp, headerName: CSP_HEADER });
  } catch {
    // Immutable headers (a Response.redirect from a library): copy first.
    response = new NextResponse(response.body, response);
    applyNonceCsp(response.headers, reqHeaders, { csp, headerName: CSP_HEADER });
  }
  return response;
}

// M10-4 #72 + M10-Phase-D F160: matcher invariant — every request goes
// through the proxy EXCEPT the explicit allowlist below. The previous
// `.*\\..*` exclusion allowed any path containing a dot to bypass
// middleware entirely, which is defensively risky if someone
// accidentally drops a sensitive file under apps/web/public/.
// Tightened to an explicit allowlist of:
//   * Next.js / Vercel internals (api/, _next/, _vercel/)
//   * Conventional static endpoints (favicon.ico, robots.txt, sitemap.xml)
//   * Known root public assets shipped by apps/web/public/ that MUST
//     stay unauthenticated for crawlers / link-unfurls to fetch them:
//       - llms.txt / llms-full.txt (LLM crawler contract, referenced
//         from robots.txt as explicitly allowed)
//       - og-image.png (OpenGraph / Twitter card unfurls)
//       - apple-touch-icon.png + android-chrome-*.png +
//         favicon-{16x16,32x32}.png (web app manifest icon set)
// New static-extension files at the root WILL still invoke the proxy
// and go through the public-route check (so `/secret.json` /
// `/leak.txt` etc. cannot bypass auth in SaaS mode). The fixture in
// proxy.matcher.test.mjs holds the regression cases.
export const config = {
  matcher: [
    "/((?!api/|api$|_next/|_next$|_vercel/|_vercel$|favicon\\.ico$|robots\\.txt$|sitemap\\.xml$|llms\\.txt$|llms-full\\.txt$|og-image\\.png$|apple-touch-icon\\.png$|android-chrome-192x192\\.png$|android-chrome-512x512\\.png$|favicon-16x16\\.png$|favicon-32x32\\.png$).*)",
  ],
};

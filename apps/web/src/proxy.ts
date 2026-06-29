import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import createIntlMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";
import { NextResponse } from "next/server";
import type { NextRequest, NextFetchEvent } from "next/server";

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

// Main proxy - conditionally use Clerk
export default async function proxy(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith("/public/")) {
    return NextResponse.next();
  }

  if (!CLERK_ENABLED) {
    // Self-hosted mode: just use i18n middleware
    return intlMiddleware(request);
  }

  // SaaS mode: use Clerk middleware
  return clerkHandler(request, {} as NextFetchEvent);
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

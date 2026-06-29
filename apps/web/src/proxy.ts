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

// M10-4 #72: matcher invariant — every request goes through the proxy
// EXCEPT the explicit allowlist below. The previous `.*\\..*` exclusion
// allowed any path containing a dot (e.g. `/secret.json`, `/leak.txt`,
// `/anything.csv`) to bypass middleware entirely, which is defensively
// risky if someone accidentally drops a sensitive file under apps/web/public/.
// Tightened to an explicit allowlist of Next.js / Vercel internals and
// the conventional static endpoints (favicon, robots.txt, sitemap.xml).
// New static-extension files at the root WILL now invoke the proxy and
// go through the public-route check. proxy.matcher.test.mjs holds the
// regression fixtures asserting `/secret.json` / `/leak.txt` do not
// bypass the matcher.
export const config = {
  matcher: ["/((?!api/|api$|_next/|_next$|_vercel/|_vercel$|favicon\\.ico$|robots\\.txt$|sitemap\\.xml$).*)"],
};

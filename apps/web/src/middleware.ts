import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import createIntlMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";
import { NextResponse } from "next/server";
import type { NextRequest, NextFetchEvent } from "next/server";

const intlMiddleware = createIntlMiddleware(routing);

// Routes that don't require authentication
const isPublicRoute = createRouteMatcher([
  "/",
  "/public(.*)",
  "/sign-in(.*)",
  "/sign-up(.*)",
  "/:locale/sign-in(.*)",
  "/:locale/sign-up(.*)",
  "/:locale/pricing",
  "/pricing",
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

// Main middleware - conditionally use Clerk
export default async function middleware(request: NextRequest) {
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

export const config = {
  matcher: ["/((?!api|_next|_vercel|.*\\..*).*)"],
};

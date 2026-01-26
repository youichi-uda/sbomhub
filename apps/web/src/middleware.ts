import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import createIntlMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const intlMiddleware = createIntlMiddleware(routing);

// Routes that don't require authentication
const isPublicRoute = createRouteMatcher([
  "/",
  "/:locale",
  "/:locale/sign-in(.*)",
  "/:locale/sign-up(.*)",
  "/sign-in(.*)",
  "/sign-up(.*)",
  "/api/webhooks(.*)",
  "/:locale/pricing",
  "/pricing",
]);

// Check if Clerk is configured (SaaS mode)
const isClerkEnabled = () => {
  return !!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
};

export default clerkMiddleware(async (auth, req) => {
  // If Clerk is not configured (self-hosted mode), skip auth check
  if (!isClerkEnabled()) {
    return intlMiddleware(req);
  }

  // Check if route requires auth
  if (!isPublicRoute(req)) {
    const { userId } = await auth();
    if (!userId) {
      // Get the locale from the URL or default to 'ja'
      const pathname = req.nextUrl.pathname;
      const localeMatch = pathname.match(/^\/([a-z]{2})(\/|$)/);
      const locale = localeMatch ? localeMatch[1] : "ja";

      // Redirect to sign-in page with redirect_url
      const signInUrl = new URL(`/${locale}/sign-in`, req.url);
      signInUrl.searchParams.set("redirect_url", req.url);
      return NextResponse.redirect(signInUrl);
    }
  }

  // Run i18n middleware
  return intlMiddleware(req);
});

export const config = {
  matcher: ["/((?!api|_next|_vercel|.*\\..*).*)"],
};

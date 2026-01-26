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

export default async function middleware(request: NextRequest) {
  // If Clerk is not configured, just use i18n middleware (self-hosted mode)
  if (!isClerkEnabled()) {
    return intlMiddleware(request);
  }

  // SaaS mode: Use Clerk middleware with i18n
  const clerkHandler = clerkMiddleware(
    async (auth, req) => {
      // Check if route requires auth
      if (!isPublicRoute(req)) {
        await auth.protect();
      }

      // Run i18n middleware
      return intlMiddleware(req);
    },
    { debug: false }
  );

  return clerkHandler(request, {} as any);
}

export const config = {
  matcher: ["/((?!api|_next|_vercel|.*\\..*).*)"],
};

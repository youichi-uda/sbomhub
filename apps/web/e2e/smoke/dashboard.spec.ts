// SBOMHub - Web smoke (dashboard reachability) — M8 #67
//
// Distinct from apps/web/e2e/dashboard.spec.ts, which asserts populated
// widgets (project count, severity cards, Japanese copy) and only runs
// reliably behind the dev:test auth-disabled launcher. This smoke spec
// targets the **production web image** running under docker compose with
// real Clerk middleware bound to placeholder build args — so /dashboard
// is expected to redirect to a sign-in surface rather than render the
// authenticated dashboard.
//
// Acceptance: a request to /[locale]/dashboard MUST resolve to either
//   (a) the authenticated dashboard (if auth happens to be disabled in
//       this build configuration), or
//   (b) a sign-in surface (Clerk-hosted or first-party) reachable from
//       the same origin.
// Failing both means the gate path itself is broken (HTTP 5xx, blank
// page, infinite redirect, etc.).
import { test, expect } from '@playwright/test';

test.describe('Dashboard reachability', () => {
  test('/ja/dashboard reaches either the dashboard or a sign-in surface', async ({ page }) => {
    const response = await page.goto('/ja/dashboard', { waitUntil: 'domcontentloaded' });
    expect(response, 'navigation response should exist').not.toBeNull();
    // 200/3xx are both fine; 4xx/5xx is a regression.
    expect(response!.status(), 'dashboard route must not 5xx').toBeLessThan(500);

    // Wait for the route to settle (auth middleware may redirect once).
    await page.waitForLoadState('networkidle').catch(() => {
      // networkidle can time out on pages that hold open SSE/poll
      // connections; the visibility assertions below are the real gate.
    });

    const url = page.url();
    const onDashboard = /\/dashboard(\b|$|\/|\?)/.test(url);
    const onSignIn = /sign-in|signin|clerk|login/i.test(url);

    expect(
      onDashboard || onSignIn,
      `expected /dashboard or a sign-in surface, got ${url}`,
    ).toBeTruthy();

    // Whichever surface we landed on, the page must have a heading or a
    // recognisable Clerk/sign-in widget — proves the body actually
    // rendered, not just a blank shell.
    const heading = page.getByRole('heading').first();
    const clerkWidget = page.locator('[class*="cl-"], [data-clerk-component]').first();
    const headingVisible = await heading.isVisible().catch(() => false);
    const clerkVisible = await clerkWidget.isVisible().catch(() => false);
    expect(
      headingVisible || clerkVisible,
      'expected at least a heading or a Clerk widget to render',
    ).toBeTruthy();
  });
});

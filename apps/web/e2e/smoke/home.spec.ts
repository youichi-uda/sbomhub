// SBOMHub - Web smoke (home / landing) — M8 #67
//
// Sibling specs in apps/web/e2e/ exercise feature-level flows behind the
// dev:test auth-disabled launcher (see playwright.config.ts webServer
// block). The specs under e2e/smoke/ are the **CI-runnable** subset:
// they are the only ones .github/workflows/web-e2e.yml runs against a
// production docker compose stack (real web image, no dev:test bypass).
//
// Acceptance: the public landing page at `/` (which redirects to the
// browser's default locale or to `/ja`) must render the SBOMHub header
// brand and a non-empty <h1> hero. That proves the production web image
// boots, Next.js routing + next-intl middleware reach a 200 page, and
// the layout chunks are served.
import { test, expect } from '@playwright/test';

test.describe('Home / landing page', () => {
  test('root redirects to a locale and renders the SBOMHub brand', async ({ page }) => {
    const response = await page.goto('/', { waitUntil: 'domcontentloaded' });

    // The landing page lives under /[locale]; the root is redirected to a
    // localised variant by next-intl middleware. Either the redirect
    // happened (status 200 on the destination) or the initial response
    // was already a 2xx.
    expect(response, 'navigation response should exist').not.toBeNull();
    expect(response!.status(), 'landing page must respond 2xx').toBeLessThan(400);
    await expect(page).toHaveURL(/\/(ja|en)(\/|$|\?)/);

    // <title> is set from messages/{ja,en}.json — both locales contain "SBOMHub".
    await expect(page).toHaveTitle(/SBOMHub/i);

    // Header brand link is the canonical landmark across both locales.
    const brand = page.getByRole('link', { name: 'SBOMHub' }).first();
    await expect(brand).toBeVisible();

    // Hero heading exists and is non-empty (we do not pin the exact copy
    // because messages/{ja,en}.json can be re-translated without breaking
    // the smoke).
    const hero = page.getByRole('heading', { level: 1 }).first();
    await expect(hero).toBeVisible();
    const heroText = (await hero.innerText()).trim();
    expect(heroText.length, 'hero heading must not be empty').toBeGreaterThan(0);
  });

  test('Japanese landing exposes the header navigation', async ({ page }) => {
    await page.goto('/ja');
    await expect(page).toHaveTitle(/SBOMHub/i);

    // Header is sticky on the landing page (see src/app/[locale]/page.tsx).
    const header = page.locator('header').first();
    await expect(header).toBeVisible();

    // Sign-in CTA exists somewhere on the page (header or footer); we do
    // not pin the exact label so JA / EN copy churn does not break the
    // smoke.
    const signInLink = page.locator('a[href*="sign-in"]').first();
    await expect(signInLink).toBeVisible();
  });
});

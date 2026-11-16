import { test, expect } from '@playwright/test';

test.describe('Dashboard', () => {
  test('should display the dashboard with stats', async ({ page }) => {
    await page.goto('/ja/dashboard');

    // Check page title
    await expect(page).toHaveTitle(/SBOMHub/);

    // Wait for loading state to complete - the page shows skeleton while loading
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(3000);

    // Wait for the dashboard content to load (either content or error state)
    // The heading appears after loading completes - use getByRole with first() to avoid strict mode issues
    const dashboardHeading = page.getByRole('heading', { name: 'ダッシュボード' }).first();
    await expect(dashboardHeading).toBeVisible({ timeout: 20000 });

    // Check that the page has loaded by looking for either:
    // 1. The project count display in the header (e.g., "N プロジェクト")
    // 2. Or the vulnerability severity cards
    // Use separate checks instead of .or() which can cause strict mode issues
    const projectCountDisplay = page.locator('text=/\\d+ プロジェクト/').first();

    // Wait for the loading to complete
    try {
      await projectCountDisplay.waitFor({ state: 'visible', timeout: 10000 });
    } catch {
      // If project count not found, that's okay - we'll check for cards next
    }

    // Check vulnerability severity cards are visible
    // The VulnerabilityCard component has CardDescription with the label text
    // Look for the grid container with the 4 severity cards (md:grid-cols-4)
    const severityCardsGrid = page.locator('.grid.grid-cols-1.md\\:grid-cols-4');
    await expect(severityCardsGrid).toBeVisible({ timeout: 10000 });

    // Each card contains the severity text (Critical, High, Medium, Low)
    await expect(severityCardsGrid.getByText('Critical').first()).toBeVisible({ timeout: 10000 });
    await expect(severityCardsGrid.getByText('High').first()).toBeVisible();
    await expect(severityCardsGrid.getByText('Medium').first()).toBeVisible();
    await expect(severityCardsGrid.getByText('Low').first()).toBeVisible();

    // Check dashboard sections are visible (Japanese card titles - use text matching for headings with icons)
    await expect(page.getByText('要対応 TOP10 - EPSS順')).toBeVisible();
    await expect(page.getByText('プロジェクト別リスクスコア')).toBeVisible();
  });

  test('should navigate to projects page', async ({ page }) => {
    await page.goto('/ja/dashboard');

    // Wait for loading state to complete
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    // Click on Projects link in sidebar (Japanese: プロジェクト - use text matching for links with icons)
    // Use aside selector to target sidebar specifically (avoid matching project links in dashboard content)
    await page.locator('aside a').filter({ hasText: 'プロジェクト' }).click();

    // Verify navigation
    await expect(page).toHaveURL(/\/projects/);
    // Use level: 1 to target only the main h1 heading, not project card headings
    await expect(page.getByRole('heading', { name: /Projects|プロジェクト/i, level: 1 })).toBeVisible({ timeout: 15000 });
  });

  test('should switch language to English', async ({ page }) => {
    // Start from Japanese locale (default)
    await page.goto('/ja/dashboard');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    // Click language switcher button (shows JA when on Japanese locale)
    const jaButton = page.locator('button').filter({ hasText: 'JA' }).first();
    await jaButton.waitFor({ state: 'visible', timeout: 10000 });
    await jaButton.click();

    // Verify URL changed to English
    await expect(page).toHaveURL(/\/en/, { timeout: 10000 });

    // Verify button now shows EN
    await expect(page.locator('button').filter({ hasText: 'EN' })).toBeVisible({ timeout: 5000 });
  });
});

// Counts on the dashboard were built by concatenation: "1 projects",
// "1 components", a trend tooltip of "{count} items" (no noun) and
// "30 days ago" assembled from "30" + "days ago". They are ICU plurals now.
// The summary is the real API answer with the counts replaced, so singular
// and plural are both on screen whatever the database holds.
test.describe('Dashboard counts', () => {
  async function stubSummary(page: import('@playwright/test').Page) {
    await page.route(
      (url) => url.pathname === '/api/v1/dashboard/summary',
      async (route) => {
        const res = await route.fetch();
        const body = await res.json();
        body.total_projects = 1;
        body.total_components = 2;
        const days = body.trend as Array<{ date: string; critical: number; high: number; medium: number; low: number }>;
        expect(days.length, 'the API returns a trend').toBeGreaterThan(1);
        for (const [i, d] of days.entries()) Object.assign(d, { critical: 0, high: 0, medium: 0, low: i === 0 ? 1 : 2 });
        await route.fulfill({ response: res, json: body });
      },
    );
  }

  test('en: singular and plural nouns, a noun in the trend tooltip', async ({ page }) => {
    await stubSummary(page);
    await page.goto('/en/dashboard');
    await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible({ timeout: 15000 });
    const main = page.locator('main');
    await expect(main.getByText('1 project', { exact: true })).toBeVisible();
    await expect(main.getByText('2 components', { exact: true })).toBeVisible();
    await expect(main.getByText('30 days ago', { exact: true })).toBeVisible();
    const titles = await main.locator('[title]').evaluateAll((els) => els.map((e) => e.getAttribute('title')));
    expect(titles.length).toBeGreaterThan(1);
    expect(titles[0]).toMatch(/: 1 vulnerability$/);
    expect(titles[1]).toMatch(/: 2 vulnerabilities$/);
  });

  test('ja: counts read naturally', async ({ page }) => {
    await stubSummary(page);
    await page.goto('/ja/dashboard');
    await expect(page.getByRole('heading', { level: 1, name: 'ダッシュボード' })).toBeVisible({ timeout: 15000 });
    const main = page.locator('main');
    await expect(main.getByText('1 プロジェクト', { exact: true })).toBeVisible();
    await expect(main.getByText('2 コンポーネント', { exact: true })).toBeVisible();
    await expect(main.getByText('30日前', { exact: true })).toBeVisible();
    const titles = await main.locator('[title]').evaluateAll((els) => els.map((e) => e.getAttribute('title')));
    expect(titles[1]).toMatch(/: 2件の脆弱性$/);
  });
});

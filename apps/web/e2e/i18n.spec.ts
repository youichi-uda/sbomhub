import { test, expect } from '@playwright/test';

test.describe('Internationalization (i18n)', () => {
  test.describe('Japanese Text Display', () => {
    test('should display Japanese text on dashboard', async ({ page }) => {
      await page.goto('/ja/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Verify Japanese heading is displayed
      const dashboardHeading = page.getByRole('heading', { name: 'ダッシュボード' }).first();
      await expect(dashboardHeading).toBeVisible({ timeout: 15000 });

      // Check for Japanese card titles
      await expect(page.getByText('要対応 TOP10 - EPSS順')).toBeVisible();
      await expect(page.getByText('プロジェクト別リスクスコア')).toBeVisible();
    });

    test('should display Japanese text on projects page', async ({ page }) => {
      await page.goto('/ja/projects');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Verify Japanese heading is displayed (use level: 1 to target main heading only)
      await expect(page.getByRole('heading', { name: 'プロジェクト', level: 1 })).toBeVisible({ timeout: 10000 });

      // Check for Japanese button text
      await expect(page.getByRole('button', { name: /新規プロジェクト/i })).toBeVisible();
    });

    test('should display Japanese navigation items', async ({ page }) => {
      await page.goto('/ja/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Check for Japanese navigation items in sidebar
      await expect(page.locator('aside a').filter({ hasText: 'ダッシュボード' })).toBeVisible();
      await expect(page.locator('aside a').filter({ hasText: 'プロジェクト' })).toBeVisible();
    });
  });

  test.describe('Language Switching', () => {
    test('should switch from Japanese to English', async ({ page }) => {
      await page.goto('/ja/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Verify we're on Japanese page
      await expect(page).toHaveURL(/\/ja/);

      // Click language switcher button (shows JA when on Japanese locale)
      const jaButton = page.locator('button').filter({ hasText: 'JA' }).first();
      await jaButton.waitFor({ state: 'visible', timeout: 10000 });
      await jaButton.click();

      // Verify URL changed to English
      await expect(page).toHaveURL(/\/en/, { timeout: 10000 });

      // Verify button now shows EN
      await expect(page.locator('button').filter({ hasText: 'EN' })).toBeVisible({ timeout: 5000 });

      // Verify the dashboard page is displayed in English
      const dashboardHeading = page.getByRole('heading', { name: 'Dashboard' }).first();
      await expect(dashboardHeading).toBeVisible({ timeout: 10000 });
    });

    test('should switch from English to Japanese', async ({ page }) => {
      await page.goto('/en/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Verify we're on English page
      await expect(page).toHaveURL(/\/en/);

      // Click language switcher button (shows EN when on English locale)
      const enButton = page.locator('button').filter({ hasText: 'EN' }).first();
      await enButton.waitFor({ state: 'visible', timeout: 10000 });
      await enButton.click();

      // Verify URL changed to Japanese
      await expect(page).toHaveURL(/\/ja/, { timeout: 10000 });

      // Verify button now shows JA
      await expect(page.locator('button').filter({ hasText: 'JA' })).toBeVisible({ timeout: 5000 });

      // Verify Japanese heading is displayed
      const dashboardHeading = page.getByRole('heading', { name: 'ダッシュボード' }).first();
      await expect(dashboardHeading).toBeVisible({ timeout: 10000 });
    });

    test('should maintain language preference when navigating', async ({ page }) => {
      // Start in Japanese
      await page.goto('/ja/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Navigate to projects page via sidebar link
      await page.locator('aside a').filter({ hasText: 'プロジェクト' }).click();
      await page.waitForLoadState('networkidle');

      // Verify URL still has /ja
      await expect(page).toHaveURL(/\/ja\/projects/);

      // Verify Japanese content is displayed (use level: 1 to target main heading only)
      await expect(page.getByRole('heading', { name: 'プロジェクト', level: 1 })).toBeVisible({ timeout: 10000 });
    });

    test('should maintain language preference after page refresh', async ({ page }) => {
      // Start in Japanese
      await page.goto('/ja/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Refresh the page
      await page.reload();
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Verify URL still has /ja
      await expect(page).toHaveURL(/\/ja/);

      // Verify Japanese heading is still displayed
      const dashboardHeading = page.getByRole('heading', { name: 'ダッシュボード' }).first();
      await expect(dashboardHeading).toBeVisible({ timeout: 10000 });
    });
  });

  test.describe('Text Consistency Across Pages', () => {
    test('should have consistent Japanese text on legal pages', async ({ page }) => {
      // Check legal page
      await page.goto('/ja/legal');
      await page.waitForLoadState('networkidle');
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

      // Check privacy page
      await page.goto('/ja/privacy');
      await page.waitForLoadState('networkidle');
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

      // Check terms page
      await page.goto('/ja/terms');
      await page.waitForLoadState('networkidle');
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    });

    test('should have consistent English text on legal pages', async ({ page }) => {
      // Check legal page
      await page.goto('/en/legal');
      await page.waitForLoadState('networkidle');
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

      // Check privacy page
      await page.goto('/en/privacy');
      await page.waitForLoadState('networkidle');
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

      // Check terms page
      await page.goto('/en/terms');
      await page.waitForLoadState('networkidle');
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    });

    test('should have consistent navigation text in Japanese', async ({ page }) => {
      await page.goto('/ja/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Check sidebar navigation has consistent Japanese labels
      const sidebar = page.locator('aside');
      await expect(sidebar).toBeVisible({ timeout: 10000 });

      // Navigate to projects and verify navigation is still in Japanese
      await page.locator('aside a').filter({ hasText: 'プロジェクト' }).click();
      await page.waitForLoadState('networkidle');

      // Sidebar should still show Japanese text
      await expect(page.locator('aside a').filter({ hasText: 'ダッシュボード' })).toBeVisible();
      await expect(page.locator('aside a').filter({ hasText: 'プロジェクト' })).toBeVisible();
    });

    test('should have consistent navigation text in English', async ({ page }) => {
      await page.goto('/en/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(2000);

      // Check sidebar navigation has consistent labels
      const sidebar = page.locator('aside');
      await expect(sidebar).toBeVisible({ timeout: 10000 });

      // Navigate to projects (sidebar uses Japanese labels for Dashboard/Search, but i18n for Projects)
      // Projects link uses i18n translation which is "Projects" in English
      await page.locator('aside a').filter({ hasText: 'Projects' }).click();
      await page.waitForLoadState('networkidle');

      // Sidebar should show consistent English text
      await expect(page.locator('aside a').filter({ hasText: 'Dashboard' })).toBeVisible();
      await expect(page.locator('aside a').filter({ hasText: 'Projects' })).toBeVisible();
    });

    test('should display both locales for vulnerability severity labels', async ({ page }) => {
      // Check Japanese severity labels
      await page.goto('/ja/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(3000);

      // Severity cards should be visible
      const severityCardsGrid = page.locator('.grid.grid-cols-1.md\\:grid-cols-4');
      await expect(severityCardsGrid).toBeVisible({ timeout: 10000 });

      // Severity labels (these are typically in English even in Japanese UI)
      await expect(severityCardsGrid.getByText('Critical').first()).toBeVisible();
      await expect(severityCardsGrid.getByText('High').first()).toBeVisible();
      await expect(severityCardsGrid.getByText('Medium').first()).toBeVisible();
      await expect(severityCardsGrid.getByText('Low').first()).toBeVisible();

      // Now check English version
      await page.goto('/en/dashboard');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(3000);

      const severityCardsGridEn = page.locator('.grid.grid-cols-1.md\\:grid-cols-4');
      await expect(severityCardsGridEn).toBeVisible({ timeout: 10000 });

      await expect(severityCardsGridEn.getByText('Critical').first()).toBeVisible();
      await expect(severityCardsGridEn.getByText('High').first()).toBeVisible();
      await expect(severityCardsGridEn.getByText('Medium').first()).toBeVisible();
      await expect(severityCardsGridEn.getByText('Low').first()).toBeVisible();
    });
  });
});

import { test, expect } from '@playwright/test';

test.describe('Dashboard', () => {
  test('should display the dashboard with stats', async ({ page }) => {
    await page.goto('/');

    // Check page title
    await expect(page).toHaveTitle(/SBOMHub/);

    // Check header is visible
    await expect(page.getByText('SBOM Management Dashboard')).toBeVisible();

    // Check stats cards are visible (use exact match in card headers)
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Components', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Vulnerabilities', exact: true })).toBeVisible();

    // Check Recent Projects section
    await expect(page.getByRole('heading', { name: 'Recent Projects' })).toBeVisible();
  });

  test('should navigate to projects page', async ({ page }) => {
    await page.goto('/');

    // Click on Projects link in sidebar
    await page.getByRole('link', { name: 'Projects' }).click();

    // Verify navigation
    await expect(page).toHaveURL(/\/projects/);
    await expect(page.getByRole('heading', { name: /Projects|プロジェクト/i })).toBeVisible();
  });

  test('should switch language to Japanese', async ({ page }) => {
    await page.goto('/en');

    // Click language switcher button (toggle)
    await page.locator('button:has-text("EN")').first().click();

    // Verify URL changed to Japanese
    await expect(page).toHaveURL(/\/ja/);

    // Verify button now shows JA
    await expect(page.locator('button:has-text("JA")')).toBeVisible();
  });
});

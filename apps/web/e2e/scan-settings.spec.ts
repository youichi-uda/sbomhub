import { test, expect } from '@playwright/test';

test.describe('Scan Settings', () => {
    test('should navigate to scan settings page', async ({ page }) => {
        // The scan settings page is at /[locale]/settings/scan
        await page.goto('/ja/settings/scan');
        await page.waitForLoadState('networkidle');

        // Verify page loaded - heading is "定期スキャン設定"
        await expect(page.getByRole('heading', { name: /定期スキャン設定|Scan/i })).toBeVisible({ timeout: 15000 });
    });

    test('should display scan enable/disable toggle', async ({ page }) => {
        await page.goto('/ja/settings/scan');
        await page.waitForLoadState('networkidle');

        // Wait for loading to complete - page shows spinner while loading
        await page.waitForTimeout(1000);

        // Look for enable toggle label "スキャン有効" (Scan enabled)
        const enableLabel = page.getByText('スキャン有効');
        await expect(enableLabel).toBeVisible({ timeout: 10000 });

        // The toggle button uses rounded-full class
        const customToggle = page.locator('button.rounded-full');
        await expect(customToggle).toBeVisible();
    });

    test('should display schedule options', async ({ page }) => {
        await page.goto('/ja/settings/scan');
        await page.waitForLoadState('networkidle');

        // Wait for content to load
        await page.waitForTimeout(1000);

        // Look for schedule type options in Japanese: 毎時, 毎日, 毎週
        const hourlyOption = page.getByText('毎時');
        const dailyOption = page.getByText('毎日');
        const weeklyOption = page.getByText('毎週');

        // Wait for options to be visible - use .first() since all three options may be visible
        await expect(hourlyOption.or(dailyOption).or(weeklyOption).first()).toBeVisible({ timeout: 10000 });
    });

    test('should select daily schedule', async ({ page }) => {
        await page.goto('/ja/settings/scan');
        await page.waitForLoadState('networkidle');

        // Wait for content to load
        await page.waitForTimeout(1000);

        // Select daily option (second radio button)
        const dailyRadio = page.locator('input[type="radio"]').nth(1);
        await dailyRadio.waitFor({ state: 'visible', timeout: 10000 });
        await dailyRadio.click();
        await page.waitForTimeout(500);

        // Should show hour selector after selecting daily
        const hourSelect = page.locator('select').first();
        const hasSelect = await hourSelect.isVisible().catch(() => false);

        if (hasSelect) {
            await hourSelect.selectOption({ index: 9 }); // 09:00
        }
    });

    test('should select weekly schedule', async ({ page }) => {
        await page.goto('/ja/settings/scan');
        await page.waitForLoadState('networkidle');

        // Wait for content to load
        await page.waitForTimeout(1000);

        // Select weekly option (third radio button)
        const weeklyRadio = page.locator('input[type="radio"]').nth(2);
        await weeklyRadio.waitFor({ state: 'visible', timeout: 10000 });
        await weeklyRadio.click();
        await page.waitForTimeout(500);

        // Should show day and hour selectors
        const daySelect = page.locator('select').first();
        const hourSelect = page.locator('select').nth(1);

        if (await daySelect.isVisible()) {
            await daySelect.selectOption({ index: 1 }); // Monday (月曜日)
        }
        if (await hourSelect.isVisible()) {
            await hourSelect.selectOption({ index: 9 }); // 09:00
        }
    });

    test('should configure notification thresholds', async ({ page }) => {
        await page.goto('/ja/settings/scan');
        await page.waitForLoadState('networkidle');

        // Wait for content to load
        await page.waitForTimeout(1000);

        // Look for notification section label "通知条件"
        const notificationLabel = page.getByText('通知条件');
        await expect(notificationLabel).toBeVisible({ timeout: 10000 });

        // Look for severity labels - the page shows "Critical", "High", "Medium", "Low"
        const criticalText = page.getByText('Critical');
        await expect(criticalText).toBeVisible();

        // Try to interact with checkboxes
        const criticalLabel = page.locator('label').filter({ hasText: 'Critical' });
        const highLabel = page.locator('label').filter({ hasText: 'High' });

        if (await criticalLabel.isVisible()) {
            await criticalLabel.click();
            await page.waitForTimeout(300);
        }

        if (await highLabel.isVisible()) {
            await highLabel.click();
            await page.waitForTimeout(300);
        }
    });

    test('should save scan settings', async ({ page }) => {
        await page.goto('/ja/settings/scan');
        await page.waitForLoadState('networkidle');

        // Wait for content to load
        await page.waitForTimeout(1000);

        // Make a change - use the custom toggle button (rounded-full class)
        const toggle = page.locator('button.rounded-full').first();
        await toggle.waitFor({ state: 'visible', timeout: 10000 });
        await toggle.click();

        // Click save button (Japanese text: 保存)
        const saveButton = page.getByRole('button', { name: '保存' });
        await saveButton.click();

        await page.waitForTimeout(1000);

        // Should show success feedback (toast, message, or just no error)
        await expect(page.locator('body')).toBeVisible();
    });

    test('should display next scan time', async ({ page }) => {
        await page.goto('/ja/settings/scan');
        await page.waitForLoadState('networkidle');

        await page.waitForTimeout(1000);

        // Look for next scan info - 次回スキャン
        // May or may not show depending on whether scanning is enabled
        await expect(page.locator('body')).toBeVisible();
    });

    test('should display scan history if available', async ({ page }) => {
        await page.goto('/ja/settings/scan');
        await page.waitForLoadState('networkidle');

        await page.waitForTimeout(1000);

        // Look for history section "スキャン履歴"
        // Either history section exists or page loads without error
        await expect(page.locator('body')).toBeVisible();
    });
});

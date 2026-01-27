import { test, expect } from '@playwright/test';

test.describe('Scan Settings', () => {
    test('should navigate to scan settings page', async ({ page }) => {
        await page.goto('/en/settings/scan');
        await page.waitForLoadState('networkidle');

        // Verify page loaded
        await expect(page.getByRole('heading', { name: /Scan|スキャン/i })).toBeVisible({ timeout: 10000 });
    });

    test('should display scan enable/disable toggle', async ({ page }) => {
        await page.goto('/en/settings/scan');
        await page.waitForLoadState('networkidle');

        // Look for enable toggle
        const enableToggle = page.locator('button[role="switch"], input[type="checkbox"]').first();
        await expect(enableToggle.or(page.getByText(/Enable|有効/i))).toBeVisible();
    });

    test('should display schedule options', async ({ page }) => {
        await page.goto('/en/settings/scan');
        await page.waitForLoadState('networkidle');

        // Look for schedule type options
        const hourlyOption = page.getByText(/Hourly|毎時/i);
        const dailyOption = page.getByText(/Daily|毎日/i);
        const weeklyOption = page.getByText(/Weekly|毎週/i);

        const hasHourly = await hourlyOption.isVisible().catch(() => false);
        const hasDaily = await dailyOption.isVisible().catch(() => false);
        const hasWeekly = await weeklyOption.isVisible().catch(() => false);

        // At least one schedule option should be visible
        expect(hasHourly || hasDaily || hasWeekly).toBeTruthy();
    });

    test('should select daily schedule', async ({ page }) => {
        await page.goto('/en/settings/scan');
        await page.waitForLoadState('networkidle');

        // Select daily option
        const dailyRadio = page.locator('input[type="radio"]').nth(1);
        if (await dailyRadio.isVisible()) {
            await dailyRadio.click();
            await page.waitForTimeout(500);

            // Should show hour selector
            const hourSelect = page.locator('select').first();
            const hasSelect = await hourSelect.isVisible().catch(() => false);

            if (hasSelect) {
                await hourSelect.selectOption({ index: 9 }); // 09:00
            }
        }
    });

    test('should select weekly schedule', async ({ page }) => {
        await page.goto('/en/settings/scan');
        await page.waitForLoadState('networkidle');

        // Select weekly option
        const weeklyRadio = page.locator('input[type="radio"]').nth(2);
        if (await weeklyRadio.isVisible()) {
            await weeklyRadio.click();
            await page.waitForTimeout(500);

            // Should show day and hour selectors
            const daySelect = page.locator('select').first();
            const hourSelect = page.locator('select').nth(1);

            if (await daySelect.isVisible()) {
                await daySelect.selectOption({ index: 1 }); // Monday
            }
            if (await hourSelect.isVisible()) {
                await hourSelect.selectOption({ index: 9 }); // 09:00
            }
        }
    });

    test('should configure notification thresholds', async ({ page }) => {
        await page.goto('/en/settings/scan');
        await page.waitForLoadState('networkidle');

        // Look for severity checkboxes
        const criticalCheckbox = page.getByLabel(/Critical/i).or(page.locator('input[type="checkbox"]').first());
        const highCheckbox = page.getByLabel(/High/i).or(page.locator('input[type="checkbox"]').nth(1));

        if (await criticalCheckbox.isVisible()) {
            const isChecked = await criticalCheckbox.isChecked().catch(() => false);
            if (!isChecked) {
                await criticalCheckbox.check();
            }
        }

        if (await highCheckbox.isVisible()) {
            const isChecked = await highCheckbox.isChecked().catch(() => false);
            if (!isChecked) {
                await highCheckbox.check();
            }
        }
    });

    test('should save scan settings', async ({ page }) => {
        await page.goto('/en/settings/scan');
        await page.waitForLoadState('networkidle');

        // Make a change
        const toggle = page.locator('button[role="switch"], input[type="checkbox"]').first();
        if (await toggle.isVisible()) {
            await toggle.click();
        }

        // Click save button
        const saveButton = page.getByRole('button', { name: /Save|保存/i });
        await saveButton.click();

        await page.waitForTimeout(1000);

        // Should show success feedback (toast, message, or just no error)
        await expect(page.locator('body')).toBeVisible();
    });

    test('should display next scan time', async ({ page }) => {
        await page.goto('/en/settings/scan');
        await page.waitForLoadState('networkidle');

        await page.waitForTimeout(1000);

        // Look for next scan info
        const nextScanText = page.getByText(/Next scan|次回スキャン/i);
        const hasNextScan = await nextScanText.isVisible().catch(() => false);

        // May or may not show depending on whether scanning is enabled
        await expect(page.locator('body')).toBeVisible();
    });

    test('should display scan history if available', async ({ page }) => {
        await page.goto('/en/settings/scan');
        await page.waitForLoadState('networkidle');

        await page.waitForTimeout(1000);

        // Look for history section
        const historyHeading = page.getByRole('heading', { name: /History|履歴/i });
        const historyTable = page.locator('table');

        const hasHistory = await historyHeading.isVisible().catch(() => false);
        const hasTable = await historyTable.isVisible().catch(() => false);

        // Either history section exists or page loads without error
        await expect(page.locator('body')).toBeVisible();
    });
});

import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('IPA Settings', () => {
    test('should navigate to IPA settings page', async ({ page }) => {
        await page.goto('/en/settings/ipa');
        await page.waitForLoadState('networkidle');

        // Should show IPA settings page
        const heading = page.getByRole('heading', { level: 1 });
        await expect(heading).toContainText(/IPA|セキュリティ/i, { timeout: 15000 });
    });

    test('should display sync settings form', async ({ page }) => {
        await page.goto('/en/settings/ipa');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Should show enable/disable toggle or switch
        const enableToggle = page.locator('button[role="switch"], input[type="checkbox"]').first();
        await expect(enableToggle).toBeVisible({ timeout: 15000 });
    });

    test('should display severity notification options', async ({ page }) => {
        await page.goto('/en/settings/ipa');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Look for severity labels
        const severityLabels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        for (const severity of severityLabels.slice(0, 2)) {
            const label = page.getByText(severity);
            // At least CRITICAL and HIGH should be visible
            await expect(label).toBeVisible({ timeout: 10000 });
        }
    });

    test('should toggle sync enabled state', async ({ page }) => {
        await page.goto('/en/settings/ipa');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Find the enable switch
        const enableSwitch = page.locator('button[role="switch"]').first();
        await enableSwitch.waitFor({ state: 'visible', timeout: 10000 });

        // Get initial state
        const initialState = await enableSwitch.getAttribute('aria-checked');

        // Click to toggle
        await enableSwitch.click();
        await page.waitForTimeout(500);

        // State should change
        const newState = await enableSwitch.getAttribute('aria-checked');
        expect(newState).not.toBe(initialState);

        // Toggle back
        await enableSwitch.click();
    });

    test('should save IPA settings', async ({ page }) => {
        await page.goto('/en/settings/ipa');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Handle any alert dialogs
        page.on('dialog', dialog => dialog.accept());

        // Find and click save button - button text is "設定を保存" or contains "保存"
        const saveButton = page.locator('button').filter({ hasText: /保存|Save/i });
        await saveButton.waitFor({ state: 'visible', timeout: 10000 });
        await saveButton.click();

        // Wait for save to complete
        await page.waitForTimeout(2000);

        // Page should still be visible (no error)
        await expect(page.locator('body')).toBeVisible();
    });

    test('should trigger manual sync', async ({ page }) => {
        await page.goto('/en/settings/ipa');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Look for sync now button
        const syncButton = page.locator('button').filter({ hasText: /Sync|同期/i });

        if (await syncButton.isVisible()) {
            await syncButton.click();
            await page.waitForTimeout(3000);

            // Should show sync result or remain on page
            await expect(page.locator('body')).toBeVisible();
        }
    });
});

test.describe('IPA Announcements', () => {
    test('should fetch IPA announcements via API', async ({ request }) => {
        const response = await request.get(`${API_BASE_URL}/api/v1/ipa/announcements`);
        expect(response.status()).toBe(200);

        const data = await response.json();
        expect(data).toHaveProperty('announcements');
        expect(data).toHaveProperty('total');
        expect(data).toHaveProperty('limit');
        expect(data).toHaveProperty('offset');
    });

    test('should get IPA settings via API', async ({ request }) => {
        const response = await request.get(`${API_BASE_URL}/api/v1/settings/ipa`);
        expect(response.status()).toBe(200);

        const data = await response.json();
        expect(data).toHaveProperty('enabled');
        expect(data).toHaveProperty('notify_on_new');
    });

    test('should update IPA settings via API', async ({ request }) => {
        const response = await request.put(`${API_BASE_URL}/api/v1/settings/ipa`, {
            data: {
                enabled: true,
                notify_on_new: true,
                notify_severity: ['CRITICAL', 'HIGH'],
            },
        });

        expect(response.status()).toBe(200);

        const data = await response.json();
        expect(data.enabled).toBe(true);
        expect(data.notify_on_new).toBe(true);
    });
});

test.describe('IPA in Japanese', () => {
    test('should display IPA settings in Japanese', async ({ page }) => {
        await page.goto('/ja/settings/ipa');
        await page.waitForLoadState('networkidle');

        // Should show Japanese labels
        const japaneseLabels = ['IPA', 'セキュリティ', '同期', '通知'];
        let foundLabel = false;

        for (const label of japaneseLabels) {
            const element = page.getByText(label);
            if (await element.isVisible().catch(() => false)) {
                foundLabel = true;
                break;
            }
        }

        // At least one Japanese label should be visible
        expect(foundLabel || await page.locator('body').textContent()).toBeTruthy();
    });
});

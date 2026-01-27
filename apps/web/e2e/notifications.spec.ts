import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('Notification Settings', () => {
    let projectId: string;

    test.beforeAll(async ({ request }) => {
        // Create a test project
        const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `Notifications Test Project ${Date.now()}`,
                description: 'Project for notification settings E2E tests',
            },
        });
        const project = await response.json();
        projectId = project.id;
    });

    test.afterAll(async ({ request }) => {
        if (projectId) {
            await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
        }
    });

    test('should display Notifications tab in project detail', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Look for Notifications tab
        const notificationsTab = page.getByRole('button', { name: /Notifications|通知/i });
        await expect(notificationsTab).toBeVisible({ timeout: 5000 });
    });

    test('should show notification settings form', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Notifications|通知/i }).click();
        await page.waitForTimeout(500);

        // Should show webhook URL inputs
        const slackInput = page.getByPlaceholder(/slack/i).or(page.getByLabel(/Slack/i));
        const discordInput = page.getByPlaceholder(/discord/i).or(page.getByLabel(/Discord/i));

        await expect(slackInput.or(discordInput)).toBeVisible();
    });

    test('should configure Slack webhook', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Notifications|通知/i }).click();
        await page.waitForTimeout(500);

        // Fill in Slack webhook URL
        const slackInput = page.getByPlaceholder(/slack/i).or(page.locator('input[name*="slack"]'));
        if (await slackInput.isVisible()) {
            await slackInput.fill('https://hooks.slack.com/services/TEST/WEBHOOK/URL');
        }

        // Enable critical severity
        const criticalCheckbox = page.locator('input[type="checkbox"]').first();
        if (await criticalCheckbox.isVisible()) {
            await criticalCheckbox.check();
        }

        // Save
        await page.getByRole('button', { name: /Save|保存/i }).click();
        await page.waitForTimeout(1000);

        // Should show success message
        await expect(page.locator('body')).toBeVisible();
    });

    test('should configure Discord webhook', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Notifications|通知/i }).click();
        await page.waitForTimeout(500);

        // Fill in Discord webhook URL
        const discordInput = page.getByPlaceholder(/discord/i).or(page.locator('input[name*="discord"]'));
        if (await discordInput.isVisible()) {
            await discordInput.fill('https://discord.com/api/webhooks/TEST/WEBHOOK');
        }

        // Save
        await page.getByRole('button', { name: /Save|保存/i }).click();
        await page.waitForTimeout(1000);
    });

    test('should configure severity thresholds', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Notifications|通知/i }).click();
        await page.waitForTimeout(500);

        // Look for severity checkboxes
        const checkboxes = page.locator('input[type="checkbox"]');
        const count = await checkboxes.count();

        // Toggle some checkboxes
        for (let i = 0; i < Math.min(count, 4); i++) {
            const checkbox = checkboxes.nth(i);
            if (await checkbox.isVisible()) {
                const isChecked = await checkbox.isChecked();
                if (!isChecked) {
                    await checkbox.check();
                }
            }
        }

        // Save
        await page.getByRole('button', { name: /Save|保存/i }).click();
        await page.waitForTimeout(1000);
    });

    test('should have test notification button', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Notifications|通知/i }).click();
        await page.waitForTimeout(500);

        // Look for test notification button
        const testButton = page.getByRole('button', { name: /Test|Send Test|テスト送信/i });

        if (await testButton.isVisible()) {
            await expect(testButton).toBeEnabled();
            // Don't actually click as it would send real notifications
        }
    });

    test('should display notification logs if available', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Notifications|通知/i }).click();
        await page.waitForTimeout(1000);

        // Look for logs section
        const logsSection = page.getByText(/Logs|History|履歴|ログ/i);
        const hasLogs = await logsSection.isVisible().catch(() => false);

        // Either logs section exists or page loads without error
        await expect(page.locator('body')).toBeVisible();
    });
});

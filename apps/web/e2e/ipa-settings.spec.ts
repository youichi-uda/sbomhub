import { test, expect } from '@playwright/test';
import en from '../messages/en.json';
import ja from '../messages/ja.json';

const IPA = en.Settings.IPA;

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('IPA Settings', () => {
    // M11-2 #77: same fix shape as integrations.spec.ts — the page
    // already renders h1 but the sidebar h1 ("SBOMHub") creates a
    // strict-mode ambiguity. Filter by name to disambiguate.
    test('should navigate to IPA settings page', async ({ page }) => {
        await page.goto('/en/settings/ipa');
        await page.waitForLoadState('networkidle');

        const heading = page.getByRole('heading', {
            name: /IPA|セキュリティ/i,
            level: 1,
        });
        await expect(heading).toBeVisible({ timeout: 15000 });
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

    test('should save IPA settings', async ({ page, request }) => {
        // Known starting point (tenant-wide settings; restored below).
        const reset = await request.put(`${API_BASE_URL}/api/v1/settings/ipa`, {
            data: { enabled: true, notify_on_new: true, notify_severity: ['CRITICAL', 'HIGH'] },
        });
        expect(reset.status()).toBe(200);

        try {
            await page.goto('/en/settings/ipa');
            const medium = page.getByRole('checkbox', { name: 'Medium' });
            await expect(medium).toHaveAttribute('aria-checked', 'false', { timeout: 15000 });
            await medium.click();
            await expect(medium).toHaveAttribute('aria-checked', 'true');

            const saved = page.waitForResponse(
                (r) => r.url().endsWith('/api/v1/settings/ipa') && r.request().method() === 'PUT',
            );
            await page.getByRole('button', { name: IPA.saveSettings }).click();
            expect((await saved).status()).toBe(200);
            await expect(page.getByRole('button', { name: IPA.saveSettings })).toBeEnabled();

            // Persisted server-side...
            const res = await request.get(`${API_BASE_URL}/api/v1/settings/ipa`);
            expect(res.status()).toBe(200);
            expect(((await res.json()).notify_severity as string[]).sort()).toEqual(['CRITICAL', 'HIGH', 'MEDIUM']);

            // ...and shown after a reload.
            await page.reload();
            await expect(page.getByRole('checkbox', { name: 'Medium' })).toHaveAttribute('aria-checked', 'true', { timeout: 15000 });
        } finally {
            await request.put(`${API_BASE_URL}/api/v1/settings/ipa`, {
                data: { enabled: true, notify_on_new: true, notify_severity: ['CRITICAL', 'HIGH'] },
            });
        }
    });

    test('should trigger manual sync', async ({ page }) => {
        await page.goto('/en/settings/ipa');
        const syncButton = page.getByRole('button', { name: IPA.syncNow });
        await expect(syncButton).toBeEnabled({ timeout: 15000 });

        const synced = page.waitForResponse(
            (r) => r.url().endsWith('/api/v1/ipa/sync') && r.request().method() === 'POST',
        );
        await syncButton.click();
        expect((await synced).status()).toBe(200);

        // The result counters are shown (the hermetic stack fetches nothing, so 0/0).
        await expect(page.getByText(new RegExp(`^${IPA.new}: \\d+$`))).toBeVisible();
        await expect(page.getByText(new RegExp(`^${IPA.updated}: \\d+$`))).toBeVisible();
        await expect(syncButton).toBeEnabled();
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

        await expect(page.getByRole('heading', { level: 1, name: ja.Settings.IPA.title })).toBeVisible({ timeout: 15000 });
        await expect(page.getByRole('button', { name: ja.Settings.IPA.syncNow })).toBeVisible();
        await expect(page.getByRole('button', { name: ja.Settings.IPA.saveSettings })).toBeVisible();
    });
});

test.describe('IPA settings load failure (M71)', () => {
    // A failed load used to render the form with defaults, i.e. look
    // like "no settings". Same contract as the M66 list screens.
    test('should show a load error with Retry when the settings fail to load', async ({ page }) => {
        let fail = true;
        await page.route(`${API_BASE_URL}/api/v1/settings/ipa`, (route) =>
            fail && route.request().method() === 'GET' ? route.fulfill({ status: 500, body: '{"error":"boom"}' }) : route.continue(),
        );
        await page.goto('/en/settings/ipa');
        await expect(page.getByRole('heading', { level: 1, name: IPA.title })).toBeVisible({ timeout: 15000 });
        const error = page.getByTestId('ipa-settings-load-error');
        await expect(error).toBeVisible();
        await expect(error).toHaveAttribute('role', 'alert');
        await expect(error).toContainText(IPA.loadFailed);
        // No form of defaults, no Save button that would save nothing.
        await expect(page.getByRole('switch')).toHaveCount(0);
        await expect(page.getByRole('button', { name: IPA.saveSettings })).toHaveCount(0);

        fail = false;
        const retried = page.waitForResponse((r) => r.url() === `${API_BASE_URL}/api/v1/settings/ipa` && r.request().method() === 'GET');
        await error.getByRole('button', { name: en.Common.retry }).click();
        expect((await retried).status()).toBe(200);
        await expect(error).toHaveCount(0);
        await expect(page.getByRole('switch').first()).toBeVisible();
        await expect(page.getByRole('button', { name: IPA.saveSettings })).toBeVisible();
    });

    // Codex M71 R2 Medium: an empty 2xx answer is not settings either.
    for (const [label, fulfill] of [
        ['204 No Content', { status: 204, body: '' }],
        ['200 null', { status: 200, contentType: 'application/json', body: 'null' }],
        // Codex M71 R3 Medium: an object without the settings is not settings.
        ['200 {}', { status: 200, contentType: 'application/json', body: '{}' }],
    ] as const) {
        test(`should treat an empty answer (${label}) as a load failure`, async ({ page }) => {
            await page.route(`${API_BASE_URL}/api/v1/settings/ipa`, (route) =>
                route.request().method() === 'GET' ? route.fulfill(fulfill) : route.continue(),
            );
            await page.goto('/en/settings/ipa');
            await expect(page.getByTestId('ipa-settings-load-error')).toContainText(IPA.loadFailed, { timeout: 15000 });
            await expect(page.getByRole('switch')).toHaveCount(0);
            await expect(page.getByRole('button', { name: IPA.saveSettings })).toHaveCount(0);
        });
    }

    test('should show the load error in Japanese too', async ({ page }) => {
        await page.route(`${API_BASE_URL}/api/v1/settings/ipa`, (route) =>
            route.request().method() === 'GET' ? route.abort() : route.continue(),
        );
        await page.goto('/ja/settings/ipa');
        const error = page.getByTestId('ipa-settings-load-error');
        await expect(error).toContainText(ja.Settings.IPA.loadFailed, { timeout: 15000 });
        await expect(error.getByRole('button', { name: ja.Common.retry })).toBeVisible();
    });
});

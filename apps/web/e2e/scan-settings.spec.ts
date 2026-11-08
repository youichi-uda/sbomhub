import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import ja from '../messages/ja.json';
import { API_BASE_URL } from './fixtures/vuln-project';

// Settings > Scan (src/app/[locale]/(dashboard)/settings/scan/page.tsx),
// driven in Japanese. Scan settings are tenant-wide: every test starts from
// BASELINE (written through the API) and the suite restores it at the end.
const T = ja.Settings.Scan;
const SAVE = ja.Common.save;

const BASELINE = {
    enabled: false,
    schedule_type: 'daily',
    schedule_hour: 6,
    schedule_day: 1,
    notify_critical: true,
    notify_high: true,
    notify_medium: false,
    notify_low: false,
};

interface ScanSettings {
    enabled: boolean;
    schedule_type: 'hourly' | 'daily' | 'weekly';
    schedule_hour: number;
    schedule_day?: number | null;
    notify_critical: boolean;
    notify_high: boolean;
    notify_medium: boolean;
    notify_low: boolean;
    next_scan_at?: string | null;
}

async function putSettings(request: APIRequestContext, data: Record<string, unknown>) {
    const res = await request.put(`${API_BASE_URL}/api/v1/settings/scan`, { data });
    expect(res.status(), await res.text()).toBe(200);
}

async function getSettings(request: APIRequestContext): Promise<ScanSettings> {
    const res = await request.get(`${API_BASE_URL}/api/v1/settings/scan`);
    expect(res.status()).toBe(200);
    return (await res.json()) as ScanSettings;
}

async function openScanSettings(page: Page) {
    await page.goto('/ja/settings/scan');
    await expect(page.getByRole('heading', { level: 1, name: T.title })).toBeVisible({ timeout: 15000 });
}

function scheduleRadio(page: Page, label: string) {
    return page.locator('label', { hasText: label }).locator('input[type="radio"]');
}

function severityCheckbox(page: Page, label: string) {
    return page.locator('label', { hasText: label }).locator('input[type="checkbox"]');
}

/** The enable toggle: the only button in the "スキャン有効" row. */
function enableToggle(page: Page) {
    return page.locator('div.flex.items-center.justify-between', { hasText: T.enableScan }).getByRole('button');
}

async function save(page: Page) {
    const saved = page.waitForResponse(
        (r) => r.url().endsWith('/api/v1/settings/scan') && r.request().method() === 'PUT',
    );
    await page.getByRole('button', { name: SAVE, exact: true }).click();
    expect((await saved).status()).toBe(200);
    await expect(page.getByText(T.saveSuccess)).toBeVisible();
}

test.describe('Scan Settings', () => {
    test.beforeEach(async ({ request }) => {
        await putSettings(request, BASELINE);
    });

    test.afterAll(async ({ request }) => {
        await putSettings(request, BASELINE);
    });

    test('should navigate to scan settings page', async ({ page }) => {
        await openScanSettings(page);
        await expect(page.getByText(T.loadError)).toHaveCount(0);
    });

    test('should display scan enable/disable toggle', async ({ page }) => {
        await openScanSettings(page);
        await expect(page.getByText(T.enableScan, { exact: true })).toBeVisible();
        await expect(page.getByText(T.enableScanDescription)).toBeVisible();
        // BASELINE is disabled: knob on the left, muted track.
        const toggle = enableToggle(page);
        await expect(toggle).toHaveCount(1);
        await expect(toggle).toHaveClass(/bg-muted/);
    });

    test('should display schedule options', async ({ page }) => {
        await openScanSettings(page);
        await expect(page.getByText(T.scanInterval, { exact: true })).toBeVisible();
        for (const label of [T.hourly, T.daily, T.weekly]) {
            await expect(scheduleRadio(page, label)).toHaveCount(1);
        }
        // BASELINE is daily at 06:00.
        await expect(scheduleRadio(page, T.daily)).toBeChecked();
        await expect(page.locator('select')).toHaveCount(1);
        await expect(page.locator('select')).toHaveValue('6');
    });

    test('should select daily schedule', async ({ page, request }) => {
        await putSettings(request, { ...BASELINE, schedule_type: 'hourly' });
        await openScanSettings(page);
        await expect(scheduleRadio(page, T.hourly)).toBeChecked();
        await expect(page.locator('select')).toHaveCount(0);

        await scheduleRadio(page, T.daily).check();
        // Daily shows one hour selector.
        const hourSelect = page.locator('select');
        await expect(hourSelect).toHaveCount(1);
        await hourSelect.selectOption('9');
        await expect(hourSelect).toHaveValue('9');
        await save(page);

        const saved = await getSettings(request);
        expect(saved.schedule_type).toBe('daily');
        expect(saved.schedule_hour).toBe(9);
    });

    test('should select weekly schedule', async ({ page, request }) => {
        await openScanSettings(page);
        await scheduleRadio(page, T.weekly).check();

        // Weekly shows a day selector and an hour selector.
        const selects = page.locator('select');
        await expect(selects).toHaveCount(2);
        await selects.nth(0).selectOption({ label: '水曜日' });
        await selects.nth(1).selectOption('14');
        await save(page);

        const saved = await getSettings(request);
        expect(saved.schedule_type).toBe('weekly');
        expect(saved.schedule_day).toBe(3);
        expect(saved.schedule_hour).toBe(14);
    });

    test('should configure notification thresholds', async ({ page, request }) => {
        await openScanSettings(page);
        await expect(page.getByText(T.notificationConditions, { exact: true })).toBeVisible();

        // BASELINE: Critical + High on.
        await expect(severityCheckbox(page, 'Critical')).toBeChecked();
        await expect(severityCheckbox(page, 'High')).toBeChecked();
        await expect(severityCheckbox(page, 'Medium')).not.toBeChecked();
        await expect(severityCheckbox(page, 'Low')).not.toBeChecked();

        await severityCheckbox(page, 'High').uncheck();
        await severityCheckbox(page, 'Medium').check();
        await save(page);

        const saved = await getSettings(request);
        expect([saved.notify_critical, saved.notify_high, saved.notify_medium, saved.notify_low])
            .toEqual([true, false, true, false]);
    });

    test('should save scan settings', async ({ page, request }) => {
        await openScanSettings(page);
        const toggle = enableToggle(page);
        await toggle.click();
        await expect(toggle).toHaveClass(/bg-primary/);
        await save(page);

        expect((await getSettings(request)).enabled).toBe(true);

        // Persisted across a reload.
        await page.reload();
        await expect(enableToggle(page)).toHaveClass(/bg-primary/, { timeout: 15000 });

        // And it toggles back off.
        await enableToggle(page).click();
        await expect(enableToggle(page)).toHaveClass(/bg-muted/);
        await save(page);
        expect((await getSettings(request)).enabled).toBe(false);
    });

    test('should display next scan time', async ({ page, request }) => {
        // The API computes next_scan_at from the schedule on save.
        await putSettings(request, { ...BASELINE, enabled: true });
        const settings = await getSettings(request);
        expect(settings.next_scan_at).toBeTruthy();

        await openScanSettings(page);
        const expected = new Date(settings.next_scan_at!).toLocaleString('ja-JP');
        await expect(page.getByText(`${T.nextScan}: ${expected}`, { exact: true })).toBeVisible();
    });

    test('should hide scan history when there are no scans', async ({ page, request }) => {
        // The hermetic stack never runs a scheduled scan.
        const res = await request.get(`${API_BASE_URL}/api/v1/settings/scan/logs?limit=10`);
        expect(res.status()).toBe(200);
        expect((await res.json()) ?? []).toEqual([]);

        await openScanSettings(page);
        await expect(page.getByRole('heading', { name: T.scanHistory })).toHaveCount(0);
    });

    test('should display scan history when there are scans', async ({ page }) => {
        // No scan log can be produced for real here (see above): serve the
        // log list from a stub to check how the page renders it.
        await page.route('**/api/v1/settings/scan/logs*', (route) =>
            route.fulfill({
                json: [
                    { id: 's1', started_at: '2026-01-02T03:00:00Z', completed_at: '2026-01-02T03:01:00Z', status: 'completed', projects_scanned: 4, new_vulnerabilities: 2 },
                    { id: 's2', started_at: '2026-01-01T03:00:00Z', status: 'failed', projects_scanned: 0, new_vulnerabilities: 0, error_message: 'boom' },
                ],
            }),
        );
        await openScanSettings(page);

        await expect(page.getByRole('heading', { level: 2, name: T.scanHistory })).toBeVisible();
        await expect(page.getByRole('columnheader')).toHaveText([T.status, T.startTime, T.projects, T.newVulnerabilities]);
        const rows = page.locator('tbody tr');
        await expect(rows).toHaveCount(2);
        await expect(rows.nth(0).locator('td')).toHaveText([
            'completed',
            new Date('2026-01-02T03:00:00Z').toLocaleString('ja-JP'),
            '4',
            '2',
        ]);
        await expect(rows.nth(1).locator('td').nth(0)).toHaveText('failed');
    });
});

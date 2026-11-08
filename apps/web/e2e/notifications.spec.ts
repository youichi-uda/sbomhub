import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { API_BASE_URL, createProject, deleteProject, uniqueName } from './fixtures/vuln-project';

// Project detail > Notifications tab
// (NotificationSettingsForm in src/app/[locale]/(dashboard)/projects/[id]/page.tsx).
// Saving reports through a native alert(); the tests capture its text.
const P = en.ProjectDetail;
const V = en.Vulnerabilities;

interface NotificationSettings {
    slack_webhook_url?: string;
    discord_webhook_url?: string;
    notify_critical: boolean;
    notify_high: boolean;
    notify_medium: boolean;
    notify_low: boolean;
}

async function getSettings(request: APIRequestContext, projectId: string): Promise<NotificationSettings> {
    const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/notifications`);
    expect(res.status()).toBe(200);
    return (await res.json()) as NotificationSettings;
}

async function openNotificationsTab(page: Page, projectId: string) {
    await page.goto(`/en/projects/${projectId}`);
    await page.getByRole('button', { name: P.notifications, exact: true }).click();
    await expect(page.locator('input[name="slack_webhook"]')).toBeVisible({ timeout: 15000 });
}

/** Clicks Save and returns the text of the alert() the form shows. */
async function saveAndReadAlert(page: Page): Promise<string> {
    const alertShown = page.waitForEvent('dialog');
    await page.getByRole('button', { name: en.Common.save, exact: true }).click();
    const dialog = await alertShown;
    const message = `${dialog.type()}: ${dialog.message()}`;
    await dialog.accept();
    return message;
}

function severityCheckbox(page: Page, label: string) {
    return page.locator('label', { hasText: label }).locator('input[type="checkbox"]');
}

test.describe('Notification Settings', () => {
    let projectId = '';

    // A fresh project per test: the tests write the project's settings.
    test.beforeEach(async ({ request }) => {
        projectId = (await createProject(request, uniqueName('Notifications Test Project'))).id;
    });

    test.afterEach(async ({ request }) => {
        await deleteProject(request, projectId);
    });

    test('should display Notifications tab in project detail', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        const tab = page.getByRole('button', { name: P.notifications, exact: true });
        await expect(tab).toBeVisible({ timeout: 15000 });
        await tab.click();
        await expect(page.getByText(P.webhookUrls, { exact: true })).toBeVisible();
    });

    test('should show notification settings form', async ({ page }) => {
        await openNotificationsTab(page, projectId);

        await expect(page.getByText(P.slackWebhookUrl, { exact: true })).toBeVisible();
        await expect(page.getByText(P.discordWebhookUrl, { exact: true })).toBeVisible();
        await expect(page.locator('input[name="discord_webhook"]')).toBeVisible();
        await expect(page.locator('input[name="email_addresses"]')).toBeVisible();
        // Defaults for a project with no settings: Critical + High on.
        await expect(severityCheckbox(page, V.critical)).toBeChecked();
        await expect(severityCheckbox(page, V.high)).toBeChecked();
        await expect(severityCheckbox(page, V.medium)).not.toBeChecked();
        await expect(severityCheckbox(page, V.low)).not.toBeChecked();
    });

    test('should configure Slack webhook', async ({ page, request }) => {
        const url = 'https://hooks.slack.com/services/TEST/WEBHOOK/URL';
        await openNotificationsTab(page, projectId);
        await page.locator('input[name="slack_webhook"]').fill(url);
        await severityCheckbox(page, V.critical).check();

        expect(await saveAndReadAlert(page)).toBe(`alert: ${P.settingsSaved}`);

        const saved = await getSettings(request, projectId);
        expect(saved.slack_webhook_url).toBe(url);
        expect(saved.notify_critical).toBe(true);

        await page.reload();
        await page.getByRole('button', { name: P.notifications, exact: true }).click();
        await expect(page.locator('input[name="slack_webhook"]')).toHaveValue(url, { timeout: 15000 });
    });

    test('should configure Discord webhook', async ({ page, request }) => {
        const url = 'https://discord.com/api/webhooks/TEST/WEBHOOK';
        await openNotificationsTab(page, projectId);
        await page.locator('input[name="discord_webhook"]').fill(url);

        expect(await saveAndReadAlert(page)).toBe(`alert: ${P.settingsSaved}`);

        const saved = await getSettings(request, projectId);
        expect(saved.discord_webhook_url).toBe(url);
        expect(saved.slack_webhook_url ?? '').toBe('');
    });

    test('should configure severity thresholds', async ({ page, request }) => {
        await openNotificationsTab(page, projectId);

        // Flip every default: Critical/High off, Medium/Low on.
        await severityCheckbox(page, V.critical).uncheck();
        await severityCheckbox(page, V.high).uncheck();
        await severityCheckbox(page, V.medium).check();
        await severityCheckbox(page, V.low).check();

        expect(await saveAndReadAlert(page)).toBe(`alert: ${P.settingsSaved}`);

        const saved = await getSettings(request, projectId);
        expect({
            critical: saved.notify_critical,
            high: saved.notify_high,
            medium: saved.notify_medium,
            low: saved.notify_low,
        }).toEqual({ critical: false, high: false, medium: true, low: true });

        await page.reload();
        await page.getByRole('button', { name: P.notifications, exact: true }).click();
        await expect(severityCheckbox(page, V.critical)).not.toBeChecked({ timeout: 15000 });
        await expect(severityCheckbox(page, V.medium)).toBeChecked();
    });

    test('should have test notification button', async ({ page }) => {
        await openNotificationsTab(page, projectId);

        // Disabled until some destination is configured.
        const testButton = page.getByRole('button', { name: P.testNotification, exact: true });
        await expect(testButton).toBeDisabled();
        await page.locator('input[name="slack_webhook"]').fill('https://hooks.slack.com/services/T/W/U');
        await expect(testButton).toBeEnabled();
        await page.locator('input[name="slack_webhook"]').fill('');
        await expect(testButton).toBeDisabled();
    });

    test('should hide notification history when there are no logs', async ({ page, request }) => {
        const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/notifications/logs`);
        expect(res.status()).toBe(200);
        expect((await res.json()) ?? []).toEqual([]);

        await openNotificationsTab(page, projectId);
        await expect(page.getByText(P.notificationHistory)).toHaveCount(0);
    });

    test('should display notification logs when there are some', async ({ page }) => {
        // The hermetic stack cannot deliver a notification (no outbound
        // network), so no log row can be produced for real; serve the log
        // list from a stub to check how the tab renders it.
        await page.route(`**/api/v1/projects/${projectId}/notifications/logs`, (route) =>
            route.fulfill({
                json: [
                    { id: 'log-1', project_id: projectId, channel: 'slack', payload: '{}', status: 'sent', created_at: '2026-01-02T03:04:05Z' },
                    { id: 'log-2', project_id: projectId, channel: 'discord', payload: '{}', status: 'failed', error_message: 'timeout', created_at: '2026-01-02T03:04:06Z' },
                ],
            }),
        );
        await openNotificationsTab(page, projectId);

        await expect(page.getByRole('heading', { name: P.notificationHistory })).toBeVisible();
        const entries = page.locator('div.border.rounded-lg.p-3');
        await expect(entries).toHaveCount(2);
        await expect(entries.nth(0)).toContainText('sent');
        await expect(entries.nth(0)).toContainText('slack');
        await expect(entries.nth(1)).toContainText('failed');
        await expect(entries.nth(1)).toContainText('discord');
    });
});

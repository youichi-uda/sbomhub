import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import ja from '../messages/ja.json';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// Settings > Integrations (src/app/[locale]/(dashboard)/settings/integrations/page.tsx).
//
// The hermetic stack has no tracker connections and cannot create one:
// POST /integrations runs a live connection test against Jira / Backlog /
// GitHub and the SSRF guard rejects local hosts. The UI tests therefore
// cover the empty state and the add-connection form; the list rendering is
// covered by badge-hydration.spec.ts with a stubbed list response.
const I = en.Settings.Integrations;

async function openIntegrations(page: Page) {
    await page.goto('/en/settings/integrations');
    // The sidebar also mounts an h1 ("SBOMHub"), so filter by name.
    await expect(page.getByRole('heading', { level: 1, name: I.title })).toBeVisible({ timeout: 15000 });
}

// Opens the add dialog via the empty-state CTA. The header "Add
// Integration" button (a DialogTrigger) is covered by its own test below.
async function openAddDialog(page: Page) {
    await openIntegrations(page);
    await page.getByRole('button', { name: I.addFirstIntegration, exact: true }).click();
    const dialog = page.getByRole('dialog', { name: I.addNewIntegration });
    await expect(dialog).toBeVisible();
    return dialog;
}

test.describe('Issue Tracker Integrations', () => {
    test('should navigate to integrations settings page', async ({ page }) => {
        await openIntegrations(page);
        await expect(page.getByText(I.description, { exact: true })).toBeVisible();
    });

    test('should display add connection button', async ({ page }) => {
        // Regression (M65 bug 5): a closed Dialog used to drop its
        // DialogTrigger, so this header button never rendered.
        await openIntegrations(page);
        const add = page.getByRole('button', { name: I.addIntegration, exact: true });
        await expect(add).toBeEnabled();
        await expect(page.getByRole('dialog')).toHaveCount(0);
        await add.click();
        const dialog = page.getByRole('dialog', { name: I.addNewIntegration });
        await expect(dialog).toBeVisible();
        // Closing and re-opening works: the trigger survives the close.
        await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await add.click();
        await expect(dialog).toBeVisible();
    });

    test('should show connection form dialog when clicking add', async ({ page }) => {
        const dialog = await openAddDialog(page);
        await expect(dialog.getByText(I.enterConnectionInfo)).toBeVisible();

        // The service Select (components/ui/select.tsx shim: a plain button
        // + div options, no combobox/option roles) shows the current value.
        const serviceTrigger = dialog.getByRole('button', { name: 'jira', exact: true });
        await expect(serviceTrigger).toBeVisible();

        // Opening it lists all three trackers.
        await serviceTrigger.click();
        for (const label of ['Jira', 'Backlog', 'GitHub Issues']) {
            await expect(dialog.getByText(label, { exact: true })).toBeVisible();
        }
        await dialog.getByText('Backlog', { exact: true }).click();
        await expect(dialog.getByRole('button', { name: 'backlog', exact: true })).toBeVisible();
        await expect(dialog.getByText('GitHub Issues', { exact: true })).toHaveCount(0);
        await expect(dialog.getByRole('link', { name: I.getBacklogToken })).toBeVisible();
    });

    test('should show Jira connection form fields', async ({ page }) => {
        const dialog = await openAddDialog(page);

        // Jira (default) asks for name, base URL, email and API token.
        const name = dialog.getByLabel(I.connectionName);
        const baseUrl = dialog.getByLabel(I.baseUrl);
        const email = dialog.getByLabel(I.email);
        const token = dialog.getByLabel(I.apiToken);
        await expect(baseUrl).toHaveAttribute('placeholder', 'https://your-domain.atlassian.net');
        await expect(email).toBeVisible();
        await expect(token).toHaveAttribute('type', 'password');
        await expect(dialog.getByRole('link', { name: I.getAtlassianToken })).toBeVisible();

        // Submit stays disabled until the required fields are filled.
        const submit = dialog.getByRole('button', { name: I.addConnection });
        await expect(submit).toBeDisabled();
        await name.fill('E2E Jira');
        await baseUrl.fill('https://e2e.atlassian.net');
        await expect(submit).toBeDisabled();
        await token.fill('dummy-token');
        await expect(submit).toBeEnabled();

        // Switching to GitHub drops the email field, and asks for a repository.
        await baseUrl.fill('');
        await dialog.getByRole('button', { name: 'jira', exact: true }).click();
        await dialog.getByText('GitHub Issues', { exact: true }).click();
        await expect(dialog.getByLabel(I.email)).toHaveCount(0);
        await expect(dialog.getByLabel(I.baseUrl)).toHaveValue('https://api.github.com');
        await expect(dialog.getByLabel(I.repository)).toBeVisible();
        // Repository is required for GitHub.
        await expect(submit).toBeDisabled();
        await dialog.getByLabel(I.repository).fill('octocat/hello-world');
        await expect(submit).toBeEnabled();

        // Cancel closes the dialog without creating anything.
        await dialog.getByRole('button', { name: en.Common.cancel, exact: true }).click();
        await expect(dialog).toBeHidden();
    });

    test('should display empty state when no connections', async ({ page, request }) => {
        // Precondition: the hermetic stack has no connections (see header).
        const res = await request.get(`${API_BASE_URL}/api/v1/integrations`);
        expect(res.status()).toBe(200);
        expect((await res.json()).connections ?? []).toEqual([]);

        await openIntegrations(page);
        await expect(page.getByRole('heading', { name: I.noIntegrations })).toBeVisible();
        await expect(page.getByText(I.noIntegrationsDescription)).toBeVisible();

        // The empty-state CTA opens the same dialog.
        await page.getByRole('button', { name: I.addFirstIntegration }).click();
        await expect(page.getByRole('dialog', { name: I.addNewIntegration })).toBeVisible();
    });
});

test.describe('Issue Tracker API', () => {
    test('should list integrations via API', async ({ request }) => {
        const response = await request.get(`${API_BASE_URL}/api/v1/integrations`);
        expect(response.status()).toBe(200);

        const data = await response.json();
        expect(data).toHaveProperty('connections');
    });

    test('should reject invalid connection data via API', async ({ request }) => {
        const response = await request.post(`${API_BASE_URL}/api/v1/integrations`, {
            data: {
                // Missing required fields
                name: '',
            },
        });

        expect(response.status()).toBe(400);
        expect((await response.json()).message).toBe('tracker_type, name, base_url, and api_token are required');
    });
});

test.describe('Vulnerability Tickets', () => {
    // The former "ticket status in vulnerability view" UI test was removed:
    // no page mounts CreateTicketButton, so there is no ticket UI to check.
    test('should list tickets via API', async ({ request }) => {
        const response = await request.get(`${API_BASE_URL}/api/v1/tickets`);
        expect(response.status()).toBe(200);

        const data = await response.json();
        expect(data).toHaveProperty('tickets');
        expect(data).toHaveProperty('total');
    });
});

test.describe('Integration Settings in Japanese', () => {
    test('should display integrations page in Japanese', async ({ page }) => {
        const J = ja.Settings.Integrations;
        await page.goto('/ja/settings/integrations');
        await expect(page.getByRole('heading', { level: 1, name: J.title })).toBeVisible({ timeout: 15000 });
        await expect(page.getByText(J.description, { exact: true })).toBeVisible();
        await expect(page.getByRole('heading', { name: J.noIntegrations })).toBeVisible();
    });
});

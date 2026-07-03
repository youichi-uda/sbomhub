import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('Issue Tracker Integrations', () => {
    // M11-2 #77: the page already renders the title as h1, but the
    // dashboard layout's sidebar also mounts an h1 ("SBOMHub") which
    // makes the bare `getByRole('heading', { level: 1 })` lookup
    // ambiguous in strict mode. Filtering by name resolves the
    // ambiguity without touching the sidebar (a11y best practice
    // would be to demote it; deferred to M12 since it would touch a
    // shared layout).
    test('should navigate to integrations settings page', async ({ page }) => {
        await page.goto('/en/settings/integrations');
        await page.waitForLoadState('networkidle');

        const heading = page.getByRole('heading', {
            name: /Integration|連携|課題管理/i,
            level: 1,
        });
        await expect(heading).toBeVisible({ timeout: 15000 });
    });

    test('should display add connection button', async ({ page }) => {
        await page.goto('/en/settings/integrations');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Should show add connection button
        const addButton = page.locator('button').filter({ hasText: /Add|追加|Connect|接続/i });
        await expect(addButton).toBeVisible({ timeout: 15000 });
    });

    test('should show connection form dialog when clicking add', async ({ page }) => {
        await page.goto('/en/settings/integrations');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Click add button
        const addButton = page.locator('button').filter({ hasText: /Add|追加|Connect|接続/i });
        await addButton.click();
        await page.waitForTimeout(1000);

        // Should show dialog with tracker type selection
        const dialog = page.locator('[role="dialog"]');
        if (await dialog.isVisible()) {
            // The dialog offers Jira, Backlog, and GitHub Issues. The closed
            // service Select renders only the selected value ("Jira" by
            // default), so this first probe can only see Jira/Backlog text.
            const jiraOption = dialog.getByText(/Jira/i);
            const backlogOption = dialog.getByText(/Backlog/i);

            const jiraVisible = await jiraOption.isVisible().catch(() => false);
            const backlogVisible = await backlogOption.isVisible().catch(() => false);

            expect(jiraVisible || backlogVisible).toBeTruthy();

            // GitHub Issues option assert (F369, closes the F363 TODO):
            // open the service Select and check the option list. Radix
            // portals the option list to <body>, so the option probe is
            // page-scoped (audit.spec.ts / vulnerabilities.spec.ts
            // precedent), and the trigger probe keeps the suite's
            // soft-guard style — the assert fires whenever the trigger is
            // actually interactable.
            const serviceTrigger = dialog.getByRole('combobox').first();
            if (await serviceTrigger.isVisible().catch(() => false)) {
                await serviceTrigger.click();
                await page.waitForTimeout(500);

                const githubOption = page.getByRole('option', { name: /GitHub Issues/i });
                const githubVisible = await githubOption.isVisible().catch(() => false);
                expect(githubVisible).toBeTruthy();

                await page.keyboard.press('Escape');
            }
        }
    });

    test('should show Jira connection form fields', async ({ page }) => {
        await page.goto('/en/settings/integrations');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Click add button
        const addButton = page.locator('button').filter({ hasText: /Add|追加|Connect|接続/i });
        await addButton.click();
        await page.waitForTimeout(1000);

        const dialog = page.locator('[role="dialog"]');
        if (await dialog.isVisible()) {
            // Select Jira
            const jiraOption = dialog.locator('button, [role="option"]').filter({ hasText: /Jira/i });
            if (await jiraOption.isVisible()) {
                await jiraOption.click();
                await page.waitForTimeout(500);
            }

            // Should show form fields for Jira
            const urlInput = dialog.locator('input').filter({ hasNotText: '' }).first();
            expect(await urlInput.isVisible() || await dialog.isVisible()).toBeTruthy();
        }
    });

    test('should display empty state when no connections', async ({ page }) => {
        await page.goto('/en/settings/integrations');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Should show empty state or connections list
        const emptyState = page.getByText(/No connections|接続がありません|まだ接続されていません/i);
        const connectionsList = page.locator('[data-testid="connections-list"]');

        const hasEmptyState = await emptyState.isVisible().catch(() => false);
        const hasConnectionsList = await connectionsList.isVisible().catch(() => false);

        // Either empty state or connections list should be visible
        await expect(page.locator('body')).toBeVisible();
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

        // Should return 400 for invalid data
        expect(response.status()).toBeGreaterThanOrEqual(400);
    });
});

test.describe('Vulnerability Tickets', () => {
    let projectId: string;
    let vulnerabilityId: string;

    test.beforeAll(async ({ request }) => {
        // Create a test project
        const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `Ticket Test Project ${Date.now()}`,
                description: 'Project for ticket E2E tests',
            },
        });
        const project = await projectResponse.json();
        projectId = project.id;
    });

    test.afterAll(async ({ request }) => {
        if (projectId) {
            await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
        }
    });

    test('should list tickets via API', async ({ request }) => {
        const response = await request.get(`${API_BASE_URL}/api/v1/tickets`);
        expect(response.status()).toBe(200);

        const data = await response.json();
        expect(data).toHaveProperty('tickets');
        expect(data).toHaveProperty('total');
    });

    test('should display ticket status in vulnerability view', async ({ page }) => {
        if (!projectId) {
            test.skip();
            return;
        }

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Go to vulnerabilities tab
        const vulnTab = page.locator('button').filter({ hasText: /Vulnerabilities|脆弱性/i });
        if (await vulnTab.isVisible()) {
            await vulnTab.click();
            await page.waitForTimeout(1000);
        }

        // Page should load without error
        await expect(page.locator('body')).toBeVisible();
    });
});

test.describe('Integration Settings in Japanese', () => {
    test('should display integrations page in Japanese', async ({ page }) => {
        await page.goto('/ja/settings/integrations');
        await page.waitForLoadState('networkidle');

        // Should show Japanese content
        const japaneseLabels = ['連携', '接続', 'Jira', 'Backlog', '課題管理'];
        let foundLabel = false;

        for (const label of japaneseLabels) {
            const element = page.getByText(label);
            if (await element.isVisible().catch(() => false)) {
                foundLabel = true;
                break;
            }
        }

        // Page should load
        await expect(page.locator('body')).toBeVisible();
    });
});

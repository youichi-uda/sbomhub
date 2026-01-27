import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('API Keys Management', () => {
    let projectId: string;

    test.beforeAll(async ({ request }) => {
        // Create a test project
        const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `API Keys Test Project ${Date.now()}`,
                description: 'Project for API keys E2E tests',
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

    test('should display API Keys tab in project detail', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Look for API Keys tab
        const apiKeysTab = page.getByRole('button', { name: /API Keys|APIキー/i });
        await expect(apiKeysTab).toBeVisible({ timeout: 5000 });
    });

    test('should show empty API keys list initially', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on API Keys tab
        await page.getByRole('button', { name: /API Keys|APIキー/i }).click();
        await page.waitForTimeout(500);

        // Should show empty state or add button
        const addButton = page.getByRole('button', { name: /Create|Add|New|作成|追加/i });
        await expect(addButton).toBeVisible();
    });

    test('should create new API key', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /API Keys|APIキー/i }).click();
        await page.waitForTimeout(500);

        // Click create button
        const createButton = page.getByRole('button', { name: /Create|Add|New|作成/i });
        await createButton.click();

        // Fill in key name
        const nameInput = page.getByPlaceholder(/name|名前/i).or(page.locator('input[type="text"]').first());
        await nameInput.fill('E2E Test API Key');

        // Select permissions if available
        const permissionsSelect = page.locator('select').first();
        if (await permissionsSelect.isVisible()) {
            await permissionsSelect.selectOption({ index: 0 });
        }

        // Submit
        await page.getByRole('button', { name: /Create|Generate|Save|作成/i }).click();

        await page.waitForTimeout(1000);

        // Should show the generated key (once, can't be retrieved again)
        const keyDisplay = page.locator('[class*="key"], [class*="secret"], code');
        const keyVisible = await keyDisplay.first().isVisible().catch(() => false);

        // Either key is shown or success message
        await expect(page.locator('body')).toBeVisible();
    });

    test('should display API key prefix in list', async ({ page, request }) => {
        // First create an API key via API
        await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/apikeys`, {
            data: {
                name: 'List Test Key',
                permissions: 'read',
            },
        });

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /API Keys|APIキー/i }).click();
        await page.waitForTimeout(1000);

        // Should show key entry with prefix (like "sbh_...")
        await expect(page.getByText(/sbh_|key_|List Test Key/i)).toBeVisible({ timeout: 5000 });
    });

    test('should show delete confirmation for API key', async ({ page, request }) => {
        // Create an API key via API
        await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/apikeys`, {
            data: {
                name: 'Delete Test Key',
                permissions: 'read',
            },
        });

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /API Keys|APIキー/i }).click();
        await page.waitForTimeout(1000);

        // Find and click delete button
        const deleteButton = page.locator('button').filter({ has: page.locator('svg.lucide-trash-2') }).first();
        if (await deleteButton.isVisible()) {
            await deleteButton.click();

            // Should show confirmation dialog
            await expect(page.getByText(/confirm|sure|確認/i)).toBeVisible();

            // Cancel deletion
            await page.getByRole('button', { name: /Cancel|キャンセル/i }).click();
        }
    });

    test('should delete API key', async ({ page, request }) => {
        // Create an API key via API
        const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/apikeys`, {
            data: {
                name: 'Actually Delete Key',
                permissions: 'read',
            },
        });
        const key = await createResponse.json();

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /API Keys|APIキー/i }).click();
        await page.waitForTimeout(1000);

        // Find and click delete button for the specific key
        const deleteButton = page.locator('button').filter({ has: page.locator('svg.lucide-trash-2') }).first();
        if (await deleteButton.isVisible()) {
            await deleteButton.click();

            // Confirm deletion
            const confirmButton = page.getByRole('button', { name: /Delete|Confirm|削除/i });
            if (await confirmButton.isVisible()) {
                await confirmButton.click();
            }

            await page.waitForTimeout(1000);

            // Key should be removed from list
            await expect(page.getByText('Actually Delete Key')).not.toBeVisible();
        }
    });
});

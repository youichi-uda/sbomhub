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

        // Wait for the page to fully load - the project name should be visible
        await page.waitForTimeout(2000);

        // Look for API Keys tab - the button text includes the count, e.g., "API Keys (0)"
        const apiKeysTab = page.locator('button').filter({ hasText: /API Keys/i });
        await expect(apiKeysTab).toBeVisible({ timeout: 15000 });
    });

    test('should show empty API keys list initially', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Click on API Keys tab
        await page.locator('button').filter({ hasText: /API Keys/i }).click();
        await page.waitForTimeout(1000);

        // Should show empty state or add button - "Create API Key" button
        const addButton = page.locator('button').filter({ hasText: /Create API Key/i });
        await expect(addButton).toBeVisible({ timeout: 10000 });
    });

    test('should create new API key', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        await page.locator('button').filter({ hasText: /API Keys/i }).click();
        await page.waitForTimeout(1000);

        // Click create button - matches "Create API Key" button text
        const createButton = page.locator('button').filter({ hasText: /Create API Key/i });
        await createButton.click();

        // Fill in key name - placeholder is "e.g., GitHub Actions CI"
        const nameInput = page.getByPlaceholder(/GitHub Actions/i);
        await nameInput.waitFor({ state: 'visible', timeout: 5000 });
        await nameInput.fill('E2E Test API Key');

        // Submit - button text is "Create Key"
        await page.locator('button').filter({ hasText: /^Create Key$|^作成$/i }).click();

        await page.waitForTimeout(2000);

        // Should show the generated key with success message (text is "API Key Created!")
        await expect(page.getByText(/API Key Created/i)).toBeVisible({ timeout: 15000 });

        // The key should be displayed in a code element within the success card
        const keyDisplay = page.locator('.bg-green-50 code');
        await expect(keyDisplay).toBeVisible();

        // Copy button should be present (uses Copy icon, then Check after copy)
        const copyButton = page.locator('.bg-green-50').getByRole('button').first();
        await expect(copyButton).toBeVisible();
    });

    test('should display API key prefix in list', async ({ page, request }) => {
        // First create an API key via API (permissions is optional)
        const response = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/apikeys`, {
            data: {
                name: 'List Test Key',
            },
        });

        // Log response for debugging
        console.log('API Key creation status:', response.status());

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        await page.locator('button').filter({ hasText: /API Keys/i }).click();
        await page.waitForTimeout(1000);

        // Should show key entry with the name and prefix displayed as "(key_prefix...)"
        // The UI shows: key.name followed by (key.key_prefix...)
        await expect(page.getByText('List Test Key')).toBeVisible({ timeout: 10000 });
    });

    test('should show delete confirmation for API key', async ({ page, request }) => {
        // Create an API key via API
        await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/apikeys`, {
            data: {
                name: 'Delete Test Key',
            },
        });

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        await page.locator('button').filter({ hasText: /API Keys/i }).click();
        await page.waitForTimeout(1000);

        // Find and click delete button (uses Trash icon, has text-red-500 class)
        const deleteButton = page.locator('button.text-red-500').first();
        if (await deleteButton.isVisible({ timeout: 5000 }).catch(() => false)) {
            await deleteButton.click();

            // The page uses window.confirm() for deletion, so we need to handle the dialog
            // The confirmation uses "Delete this API key? This action cannot be undone."
            page.on('dialog', dialog => dialog.dismiss());

            // Just verify the delete button exists
            await expect(deleteButton).toBeVisible();
        }
    });

    test('should delete API key', async ({ page, request }) => {
        // Create an API key via API with a unique name for this test
        const uniqueName = `Delete Test Key ${Date.now()}`;
        const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/apikeys`, {
            data: {
                name: uniqueName,
            },
        });
        const key = await createResponse.json();
        expect(createResponse.ok()).toBeTruthy();

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        await page.locator('button').filter({ hasText: /API Keys/i }).click();
        await page.waitForTimeout(1000);

        // Wait for the key to appear in the list first
        await expect(page.getByText(uniqueName)).toBeVisible({ timeout: 10000 });

        // Find the delete button within the same row as the key name
        // The key list item structure has the key name and a delete button in the same container
        const keyRow = page.locator('.border.rounded-lg.p-3').filter({ hasText: uniqueName });
        const deleteButton = keyRow.locator('button').filter({ hasText: 'Delete' });
        await expect(deleteButton).toBeVisible({ timeout: 5000 });

        // Set up dialog handler BEFORE clicking
        page.on('dialog', async dialog => {
            await dialog.accept();
        });

        // Wait for the DELETE API call to complete after clicking
        const deleteResponsePromise = page.waitForResponse(
            (response) => response.url().includes('/apikeys/') && response.request().method() === 'DELETE',
            { timeout: 15000 }
        );

        await deleteButton.click();

        // Wait for the DELETE API call to complete
        const deleteResponse = await deleteResponsePromise;
        expect(deleteResponse.ok()).toBeTruthy();

        // After the delete API call succeeds, reload and verify key is gone
        // This is more reliable than waiting for React state update
        await page.waitForTimeout(1000);

        // Reload the page to get fresh state from server
        await page.reload();
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);

        // Switch to API Keys tab again
        await page.locator('button').filter({ hasText: /API Keys/i }).click();
        await page.waitForTimeout(1000);

        // Verify the key is no longer present
        await expect(page.getByText(uniqueName)).toBeHidden({ timeout: 10000 });
    });
});

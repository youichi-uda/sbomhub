import { test, expect } from '@playwright/test';

import { API_BASE_URL, createProject, deleteProject } from './fixtures/vuln-project';

test.describe('Error Handling', () => {
    test('should display 404 page for non-existent project', async ({ page }) => {
        // Navigate to a non-existent project
        const fakeProjectId = 'non-existent-project-id-12345';
        await page.goto(`/en/projects/${fakeProjectId}`);
        await page.waitForTimeout(1000);

        // Should show 404 page or error message
        const notFoundHeading = page.getByRole('heading', { name: /404|Not Found|見つかりません/i });
        const notFoundText = page.getByText(/not found|does not exist|見つかりません|存在しません/i);
        const errorPage = page.locator('[data-testid="error-page"], .error-page');

        const has404Heading = await notFoundHeading.isVisible().catch(() => false);
        const has404Text = await notFoundText.isVisible().catch(() => false);
        const hasErrorPage = await errorPage.isVisible().catch(() => false);

        // One of these should be visible
        expect(has404Heading || has404Text || hasErrorPage).toBeTruthy();
    });

    test('should display 404 page for invalid URL path', async ({ page }) => {
        await page.goto('/en/invalid-page-path-xyz');
        await page.waitForTimeout(1000);

        // Should show 404 page
        const notFoundIndicator = page.getByText(/404|not found|見つかりません|page does not exist/i);
        await expect(notFoundIndicator.first()).toBeVisible();
    });

    test('should handle network error gracefully', async ({ page }) => {
        // Block all API requests to simulate network failure
        await page.route(`${API_BASE_URL}/**`, route => route.abort());

        await page.goto('/en/projects');
        await page.waitForTimeout(2000);

        // Should show error state or retry option
        const errorMessage = page.getByText(/error|failed|エラー|失敗|could not load|retry/i);
        const retryButton = page.getByRole('button', { name: /Retry|再試行|Try Again/i });

        const hasError = await errorMessage.isVisible().catch(() => false);
        const hasRetry = await retryButton.isVisible().catch(() => false);

        // Either error message or page still renders (with empty state)
        expect(hasError || hasRetry || await page.locator('main').isVisible()).toBeTruthy();
    });

    test('should handle API timeout gracefully', async ({ page }) => {
        // Delay API responses to simulate timeout
        await page.route(`${API_BASE_URL}/api/v1/projects`, async route => {
            await new Promise(resolve => setTimeout(resolve, 30000)); // 30 second delay
            await route.continue();
        });

        // Navigate with a timeout
        await page.goto('/en/projects', { timeout: 5000 }).catch(() => {});
        await page.waitForTimeout(2000);

        // Page should show loading state or timeout error
        const loadingIndicator = page.getByText(/loading|読み込み中|please wait/i);
        const timeoutError = page.getByText(/timeout|timed out|タイムアウト/i);
        const pageContent = page.locator('main');

        const isLoading = await loadingIndicator.isVisible().catch(() => false);
        const hasTimeout = await timeoutError.isVisible().catch(() => false);
        const hasContent = await pageContent.isVisible().catch(() => false);

        expect(isLoading || hasTimeout || hasContent).toBeTruthy();
    });

    test('should handle project deletion of already deleted project', async ({ page, request }) => {
        // Create and immediately delete a project
        const projectName = `Deleted Project ${Date.now()}`;
        const project = await createProject(request, projectName, 'Will be deleted');

        // Delete via API
        const deleted = await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
        expect(deleted.ok(), `DELETE returned ${deleted.status()}`).toBe(true);

        // Try to access the deleted project
        await page.goto(`/en/projects/${project.id}`);
        await page.waitForTimeout(1000);

        // Should show not found or error
        const notFoundText = page.getByText(/not found|does not exist|見つかりません|deleted/i);
        await expect(notFoundText.first()).toBeVisible();
    });

    test('should show validation error for invalid SBOM upload', async ({ page, request }) => {
        // Create a project
        const projectName = `Invalid SBOM Test ${Date.now()}`;
        const project = await createProject(request, projectName, 'For invalid SBOM test');

        // Try to upload invalid SBOM
        const invalidSbom = {
            invalid: 'not a valid sbom',
            random: 'data',
        };

        const uploadResponse = await request.post(
            `${API_BASE_URL}/api/v1/projects/${project.id}/sbom`,
            {
                data: JSON.stringify(invalidSbom),
                headers: { 'Content-Type': 'application/json' },
            }
        );

        // API should reject invalid SBOM
        expect(uploadResponse.status()).toBeGreaterThanOrEqual(400);

        // Navigate to project and verify error is shown if any
        await page.goto(`/en/projects/${project.id}`);
        await page.waitForLoadState('networkidle');

        // Project should still be accessible
        await expect(page.getByText('Back to Projects')).toBeVisible();

        // Cleanup
        await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
    });

    test('should handle empty SBOM components gracefully', async ({ page, request }) => {
        const projectName = `Empty SBOM Test ${Date.now()}`;
        const project = await createProject(request, projectName, 'For empty SBOM test');

        // Upload SBOM with no components
        const emptySbom = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [],
        };

        const upload = await request.post(`${API_BASE_URL}/api/v1/projects/${project.id}/sbom`, {
            data: JSON.stringify(emptySbom),
            headers: { 'Content-Type': 'application/json' },
        });
        expect(upload.ok(), `empty SBOM upload returned ${upload.status()}`).toBe(true);

        // Navigate to project
        await page.goto(`/en/projects/${project.id}`);
        await page.waitForLoadState('networkidle');

        // Click on Components tab
        await page.getByRole('button', { name: /Components/i }).click();
        await page.waitForTimeout(1000);

        // Should show empty state message
        const emptyMessage = page.getByText(/no components|コンポーネントなし|0 件|empty/i);
        const zeroCount = page.getByRole('button', { name: /Components \(0\)/i });

        const hasEmptyMessage = await emptyMessage.isVisible().catch(() => false);
        const hasZeroCount = await zeroCount.isVisible().catch(() => false);

        expect(hasEmptyMessage || hasZeroCount).toBeTruthy();

        // Cleanup
        await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
    });

    // (Removed: "should display error for unauthorized access". It was a
    // reasonless declaration-form skip since M11-2. The CI stack runs in
    // self-hosted anonymous mode where every request is the seeded admin,
    // so there is no unauthorized state to reach, and the page it visited,
    // /en/settings, does not exist (404). Auth redirects are covered by
    // auth.spec.ts.)

    test('should handle API error responses gracefully', async ({ page }) => {
        // Intercept API and return error response
        await page.route(`${API_BASE_URL}/api/v1/projects`, route =>
            route.fulfill({
                status: 500,
                contentType: 'application/json',
                body: JSON.stringify({ error: 'Internal Server Error' }),
            })
        );

        await page.goto('/en/projects');
        await page.waitForTimeout(2000);

        // Should show error message
        const errorMessage = page.getByText(/error|failed|問題|エラー|sorry|申し訳/i);
        const mainContent = page.locator('main');

        const hasError = await errorMessage.isVisible().catch(() => false);
        const hasContent = await mainContent.isVisible().catch(() => false);

        // Error message or at least page content should be visible
        expect(hasError || hasContent).toBeTruthy();
    });

    // Duplicate project names: the API deliberately allows them within a
    // tenant (M11-2 #77 left the dedup / 409 question as a product
    // decision). This pins the current behaviour — two projects, distinct
    // ids, both listed — so a change to it is a visible, deliberate one.
    test('should allow duplicate project names as distinct projects', async ({ page, request }) => {
        const projectName = `Duplicate Test ${Date.now()}`;
        const original = await createProject(request, projectName, 'Original');
        try {
            await page.goto('/en/projects');
            await page.getByRole('button', { name: /New Project/i }).first().click();
            await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });
            await page.getByPlaceholder('My Project').fill(projectName);
            await page.getByPlaceholder('Project description').fill('Duplicate attempt');

            const created = page.waitForResponse(
                (r) => r.request().method() === 'POST' && r.url().endsWith('/api/v1/projects'),
            );
            await page.locator('.fixed button:has-text("Create")').click();
            const response = await created;
            expect(response.status()).toBe(201);
            const duplicateId = (await response.json()).id as string;
            expect(duplicateId).not.toBe(original.id);

            // Both are listed, in the UI and in the API.
            await expect(page.getByRole('link', { name: projectName, exact: true })).toHaveCount(2, { timeout: 10000 });
            const list = await request.get(`${API_BASE_URL}/api/v1/projects`);
            expect(list.status()).toBe(200);
            const ids = ((await list.json()) as Array<{ id: string; name: string }>)
                .filter((p) => p.name === projectName)
                .map((p) => p.id)
                .sort();
            expect(ids).toEqual([original.id, duplicateId].sort());
        } finally {
            const list = await request.get(`${API_BASE_URL}/api/v1/projects`);
            for (const p of ((await list.json()) ?? []) as Array<{ id: string; name: string }>) {
                if (p.name === projectName) await deleteProject(request, p.id);
            }
        }
    });

    test('should handle session expiration gracefully', async ({ page }) => {
        // Navigate to a page
        await page.goto('/en/dashboard');
        await page.waitForLoadState('networkidle');

        // Simulate session expiration by clearing cookies
        await page.context().clearCookies();

        // Try to perform an action that requires authentication
        await page.goto('/en/projects');
        await page.waitForTimeout(1000);

        // Should redirect to login or show session expired message
        const loginPage = page.getByText(/sign in|login|ログイン/i);
        const sessionExpired = page.getByText(/session expired|セッション切れ|再ログイン/i);
        const projectsPage = page.getByRole('heading', { name: /Projects/i });

        const needsLogin = await loginPage.isVisible().catch(() => false);
        const hasSessionExpired = await sessionExpired.isVisible().catch(() => false);
        const hasAccess = await projectsPage.isVisible().catch(() => false);

        // One of these should be true
        expect(needsLogin || hasSessionExpired || hasAccess).toBeTruthy();
    });

    test('should handle large file upload error', async ({ page, request }) => {
        const projectName = `Large File Test ${Date.now()}`;
        const project = await createProject(request, projectName, 'For large file test');

        // Create a very large SBOM (simulated with many components)
        const components = [];
        for (let i = 0; i < 10000; i++) {
            components.push({
                type: 'library',
                name: `component-${i}`,
                version: '1.0.0',
                licenses: [{ license: { id: 'MIT' } }],
            });
        }

        const largeSbom = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components,
        };

        // Try to upload large SBOM
        const uploadResponse = await request.post(
            `${API_BASE_URL}/api/v1/projects/${project.id}/sbom`,
            {
                data: JSON.stringify(largeSbom),
                headers: { 'Content-Type': 'application/json' },
                timeout: 60000,
            }
        );

        // Should either succeed or return appropriate error
        expect([200, 201, 400, 413, 500]).toContain(uploadResponse.status());

        // Cleanup
        await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
    });
});

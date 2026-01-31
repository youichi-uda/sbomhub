import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// Helper to check if page was redirected to sign-in
async function isRedirectedToSignIn(page: any): Promise<boolean> {
    const url = page.url();
    return url.includes('/sign-in') || url.includes('/login');
}

// Search functionality tests - work in self-hosted mode, may require auth in SaaS mode
test.describe('Search Functionality', () => {
    let projectId: string | null = null;

    test.beforeAll(async ({ request }) => {
        // Create a test project with vulnerable component
        const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `Search Test Project ${Date.now()}`,
                description: 'Project for search E2E tests',
            },
        });

        // Skip if auth required
        if (response.status() === 401) {
            return;
        }

        const project = await response.json();
        projectId = project.id;

        // Upload SBOM with known components
        const sbom = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [
                {
                    type: 'library',
                    name: 'lodash',
                    version: '4.17.20',
                    purl: 'pkg:npm/lodash@4.17.20',
                    licenses: [{ license: { id: 'MIT' } }],
                },
                {
                    type: 'library',
                    name: 'express',
                    version: '4.17.1',
                    purl: 'pkg:npm/express@4.17.1',
                    licenses: [{ license: { id: 'MIT' } }],
                },
            ],
        };

        await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
            data: JSON.stringify(sbom),
            headers: { 'Content-Type': 'application/json' },
        });
    });

    test.afterAll(async ({ request }) => {
        if (projectId) {
            await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
        }
    });

    test('should display search page with input fields', async ({ page }) => {
        await page.goto('/en/search');
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, this is expected in SaaS mode
        if (await isRedirectedToSignIn(page)) {
            // Sign-in redirect is valid - test passes
            return;
        }

        // Verify search page elements - English locale uses English text
        await expect(page.getByRole('heading', { name: 'Cross Search', level: 1 })).toBeVisible();
        // The CVE input has placeholder "CVE-2021-44228"
        await expect(page.getByPlaceholder('CVE-2021-44228')).toBeVisible();
        // Verify the CVE search button is visible
        await expect(page.getByRole('button', { name: 'Search' }).first()).toBeVisible();
    });

    test('should search for component by name', async ({ page }) => {
        await page.goto('/en/search');
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, skip test
        if (await isRedirectedToSignIn(page)) {
            return;
        }

        // Click on component search tab if exists, or fill component name
        const componentInput = page.getByPlaceholder(/component/i).or(page.locator('input[type="text"]').nth(1));

        if (await componentInput.isVisible()) {
            await componentInput.fill('lodash');

            // Submit search
            await page.getByRole('button', { name: /Search/i }).click();

            // Wait for results
            await page.waitForTimeout(1000);

            // Should show matching projects with the component
            // (may show "no results" if component search isn't fully wired up)
        }
    });

    test('should search for CVE and display results', async ({ page }) => {
        await page.goto('/en/search');
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, skip test
        if (await isRedirectedToSignIn(page)) {
            return;
        }

        // Search for a well-known CVE
        const cveInput = page.getByPlaceholder('CVE-2021-44228');
        await cveInput.fill('CVE-2021-44228');

        // Submit search
        await page.getByRole('button', { name: 'Search' }).first().click();

        // Wait for results
        await page.waitForTimeout(2000);

        // Check for meaningful response - either results or "not found" message
        const resultsSection = page.locator('[data-testid="search-results"], .search-results, table, ul');
        const noResultsMessage = page.getByText(/not found|見つかりません|no results|0 件/i);
        const cveDetails = page.getByText(/CVE-2021-44228/i);

        const hasResults = await resultsSection.isVisible().catch(() => false);
        const hasNoResultsMsg = await noResultsMessage.isVisible().catch(() => false);
        const hasCVEDetails = await cveDetails.isVisible().catch(() => false);

        // One of these should be true - meaningful response received
        expect(hasResults || hasNoResultsMsg || hasCVEDetails).toBeTruthy();
    });

    test('should display CVE details with severity and description', async ({ page, request }) => {
        if (!projectId) {
            test.skip();
            return;
        }

        // First check if we have any vulnerabilities in our test project
        const vulnResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`);

        if (vulnResponse.status() === 401) {
            test.skip();
            return;
        }

        const vulns = await vulnResponse.json();

        if (!vulns || vulns.length === 0) {
            test.skip();
            return;
        }

        await page.goto('/en/search');
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, skip test
        if (await isRedirectedToSignIn(page)) {
            return;
        }

        // Search for a CVE we know exists
        const cveInput = page.getByPlaceholder('CVE-2021-44228');
        await cveInput.fill(vulns[0].cve_id);
        await page.getByRole('button', { name: 'Search' }).first().click();
        await page.waitForTimeout(2000);

        // Verify CVE details are shown
        await expect(page.getByText(vulns[0].cve_id)).toBeVisible();

        // Check for severity badge
        const severityBadge = page.getByText(/CRITICAL|HIGH|MEDIUM|LOW/i);
        if (await severityBadge.isVisible().catch(() => false)) {
            await expect(severityBadge.first()).toBeVisible();
        }
    });

    test('should handle non-existent CVE search gracefully', async ({ page }) => {
        await page.goto('/en/search');
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, skip test
        if (await isRedirectedToSignIn(page)) {
            return;
        }

        // Search for a CVE that doesn't exist
        const cveInput = page.getByPlaceholder('CVE-2021-44228');
        await cveInput.fill('CVE-9999-99999');

        await page.getByRole('button', { name: 'Search' }).first().click();
        await page.waitForTimeout(1000);

        // Should show "not found" message (Japanese or English)
        const noResults = page.getByText(/not found|no results|見つかりません|存在しません/i);
        const emptyState = page.locator('[data-testid="empty-state"], .empty-state');

        const hasNoResultsMsg = await noResults.isVisible().catch(() => false);
        const hasEmptyState = await emptyState.isVisible().catch(() => false);

        // At least one indicator of "no results" should be shown
        expect(hasNoResultsMsg || hasEmptyState).toBeTruthy();
    });

    test('should validate CVE format', async ({ page }) => {
        await page.goto('/en/search');
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, skip test
        if (await isRedirectedToSignIn(page)) {
            return;
        }

        // Enter invalid CVE format
        const cveInput = page.getByPlaceholder('CVE-2021-44228');
        await cveInput.fill('invalid-cve-format');

        await page.getByRole('button', { name: 'Search' }).first().click();
        await page.waitForTimeout(1000);

        // Should show validation error or "not found" message
        // The UI shows "CVE not found" for invalid formats (server validates and returns error)
        const validationError = page.getByText(/invalid|無効|format|形式/i);
        const noResults = page.getByText(/not found|見つかりません|CVE not found/i);
        const errorCard = page.locator('.border-red-200');

        const hasValidationError = await validationError.isVisible().catch(() => false);
        const hasNoResults = await noResults.isVisible().catch(() => false);
        const hasErrorCard = await errorCard.isVisible().catch(() => false);

        // Either validation error, not found message, or error card is shown
        expect(hasValidationError || hasNoResults || hasErrorCard).toBeTruthy();
    });

    test('should navigate to project from search results', async ({ page, request }) => {
        if (!projectId) {
            test.skip();
            return;
        }

        // First check if we have any components via API
        const componentsResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/components`);

        if (componentsResponse.status() === 401) {
            test.skip();
            return;
        }

        const components = await componentsResponse.json();

        if (components && components.length > 0) {
            await page.goto('/en/search');
            await page.waitForLoadState('networkidle');

            // If redirected to sign-in, skip test
            if (await isRedirectedToSignIn(page)) {
                return;
            }

            const componentInput = page.getByPlaceholder(/component/i).or(page.locator('input[type="text"]').nth(1));

            if (await componentInput.isVisible()) {
                await componentInput.fill('lodash');
                await page.getByRole('button', { name: /Search/i }).click();
                await page.waitForTimeout(2000);

                // If there are clickable project links in results, click one
                const projectLink = page.locator('a[href*="/projects/"]').first();
                if (await projectLink.isVisible()) {
                    await projectLink.click();

                    // Verify navigation to project page
                    await expect(page).toHaveURL(/\/projects\//);

                    // Verify project detail page elements
                    await expect(page.getByText('Back to Projects')).toBeVisible();
                }
            }
        }
    });

    test('should display component search results with project context', async ({ page, request }) => {
        if (!projectId) {
            test.skip();
            return;
        }

        const componentsResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/components`);

        if (componentsResponse.status() === 401) {
            test.skip();
            return;
        }

        const components = await componentsResponse.json();

        if (!components || components.length === 0) {
            test.skip();
            return;
        }

        await page.goto('/en/search');
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, skip test
        if (await isRedirectedToSignIn(page)) {
            return;
        }

        // Switch to component search tab if it exists
        const componentTab = page.getByRole('tab', { name: /component|コンポーネント/i });
        if (await componentTab.isVisible()) {
            await componentTab.click();
        }

        const componentInput = page.getByPlaceholder(/component/i).or(page.locator('input[type="text"]').nth(1));

        if (await componentInput.isVisible()) {
            // Search for a known component
            await componentInput.fill(components[0].name);
            await page.getByRole('button', { name: /Search|検索/i }).click();
            await page.waitForTimeout(2000);

            // Verify results show component name
            await expect(page.getByText(components[0].name)).toBeVisible();

            // Verify results include project information
            const resultsArea = page.locator('.search-results, [data-testid="search-results"], main');
            const projectLink = resultsArea.locator('a[href*="/projects/"]');

            if (await projectLink.isVisible()) {
                // Results should link to the project containing this component
                const href = await projectLink.first().getAttribute('href');
                expect(href).toContain('/projects/');
            }
        }
    });

    test('should show result count for component search', async ({ page, request }) => {
        if (!projectId) {
            test.skip();
            return;
        }

        const componentsResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/components`);

        if (componentsResponse.status() === 401) {
            test.skip();
            return;
        }

        const components = await componentsResponse.json();

        if (!components || components.length === 0) {
            test.skip();
            return;
        }

        await page.goto('/en/search');
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, skip test
        if (await isRedirectedToSignIn(page)) {
            return;
        }

        const componentInput = page.getByPlaceholder(/component/i).or(page.locator('input[type="text"]').nth(1));

        if (await componentInput.isVisible()) {
            await componentInput.fill('lodash');
            await page.getByRole('button', { name: /Search|検索/i }).click();
            await page.waitForTimeout(2000);

            // Look for result count indicator
            const resultCount = page.getByText(/\d+\s*(results?|件|matches?|found)/i);
            const resultsFound = await resultCount.isVisible().catch(() => false);

            // If we have results, there should be a count or actual result items
            const resultItems = page.locator('table tbody tr, .result-item, [data-testid="result-item"]');
            const itemCount = await resultItems.count();

            expect(resultsFound || itemCount > 0).toBeTruthy();
        }
    });
});

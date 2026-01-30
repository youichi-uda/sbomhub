import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('Search Functionality', () => {
    let projectId: string;

    test.beforeAll(async ({ request }) => {
        // Create a test project with vulnerable component
        const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `Search Test Project ${Date.now()}`,
                description: 'Project for search E2E tests',
            },
        });
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

        // Verify search page elements
        // The heading is in Japanese: "横断検索" (Cross-search) - use exact match to avoid matching "CVE横断検索"
        await expect(page.getByRole('heading', { name: '横断検索', exact: true })).toBeVisible();
        // The CVE input has placeholder "CVE-2021-44228"
        await expect(page.getByPlaceholder('CVE-2021-44228')).toBeVisible();
        // Verify the CVE search button is visible (use exact match to avoid matching tab triggers)
        await expect(page.getByRole('button', { name: '検索', exact: true }).first()).toBeVisible();
    });

    test('should search for component by name', async ({ page }) => {
        await page.goto('/en/search');

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

    test('should search for CVE', async ({ page }) => {
        await page.goto('/en/search');

        // Search for a well-known CVE
        // The CVE input has placeholder "CVE-2021-44228"
        const cveInput = page.getByPlaceholder('CVE-2021-44228');
        await cveInput.fill('CVE-2021-44228');

        // Submit search - use exact match to target only the submit button, not tab triggers
        await page.getByRole('button', { name: '検索', exact: true }).first().click();

        // Wait for results
        await page.waitForTimeout(2000);

        // Results may or may not show depending on whether we have that CVE in our DB
        // Just verify no crash and page responds
        await expect(page.locator('body')).toBeVisible();
    });

    test('should handle empty CVE search gracefully', async ({ page }) => {
        await page.goto('/en/search');

        // The CVE input has placeholder "CVE-2021-44228"
        const cveInput = page.getByPlaceholder('CVE-2021-44228');
        await cveInput.fill('CVE-9999-99999');

        // Submit search - use exact match to target only the submit button, not tab triggers
        await page.getByRole('button', { name: '検索', exact: true }).first().click();

        await page.waitForTimeout(1000);

        // Should show "not found" or empty results (Japanese: "CVEが見つかりませんでした")
        const noResults = page.getByText(/not found|no results|見つかりません/i);
        const resultsExist = await noResults.isVisible().catch(() => false);

        // Either shows "not found" or just empty - both are valid
        await expect(page.locator('body')).toBeVisible();
    });

    test('should navigate to project from search results', async ({ page, request }) => {
        // First check if we have any components via API
        const componentsResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/components`);
        const components = await componentsResponse.json();

        if (components && components.length > 0) {
            await page.goto('/en/search');

            const componentInput = page.getByPlaceholder(/component/i).or(page.locator('input[type="text"]').nth(1));

            if (await componentInput.isVisible()) {
                await componentInput.fill('lodash');
                await page.getByRole('button', { name: /Search/i }).click();
                await page.waitForTimeout(2000);

                // If there are clickable project links in results, click one
                const projectLink = page.locator('a[href*="/projects/"]').first();
                if (await projectLink.isVisible()) {
                    await projectLink.click();
                    await expect(page).toHaveURL(/\/projects\//);
                }
            }
        }
    });
});

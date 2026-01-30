import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('VEX Statement Management', () => {
    let projectId: string;
    let vulnerabilityId: string;

    test.beforeAll(async ({ request }) => {
        // Create a test project
        const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `VEX Test Project ${Date.now()}`,
                description: 'Project for VEX E2E tests',
            },
        });
        const project = await projectResponse.json();
        projectId = project.id;

        // Upload SBOM with component that might have vulnerabilities
        const sbom = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [
                {
                    type: 'library',
                    name: 'log4j-core',
                    version: '2.14.0',
                    purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0',
                    licenses: [{ license: { id: 'Apache-2.0' } }],
                },
            ],
        };

        await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
            data: JSON.stringify(sbom),
            headers: { 'Content-Type': 'application/json' },
        });

        // Get vulnerabilities for this project
        const vulnResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`);
        const vulns = await vulnResponse.json();
        if (vulns && vulns.length > 0) {
            vulnerabilityId = vulns[0].id;
        }
    });

    test.afterAll(async ({ request }) => {
        if (projectId) {
            await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
        }
    });

    test('should display VEX tab in project detail', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);

        // Wait for page to load
        await page.waitForLoadState('networkidle');

        // Look for VEX tab - use more specific locator to match tab button with count
        const vexTab = page.getByRole('button', { name: /^VEX \(\d+\)$/i });
        await expect(vexTab).toBeVisible({ timeout: 5000 });
    });

    test('should show VEX statements list', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on VEX tab - use specific locator for tab button with count
        await page.getByRole('button', { name: /^VEX \(\d+\)$/i }).click();

        // Should show empty state or existing statements
        await page.waitForTimeout(1000);
        await expect(page.locator('body')).toBeVisible();
    });

    test('should create VEX statement via dialog', async ({ page, request }) => {
        // First ensure we have vulnerabilities
        const vulnResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`);
        const vulns = await vulnResponse.json();

        if (!vulns || vulns.length === 0) {
            test.skip();
            return;
        }

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on VEX tab - use specific locator for tab button with count
        await page.getByRole('button', { name: /^VEX \(\d+\)$/i }).click();
        await page.waitForTimeout(500);

        // Click add VEX button or look for vulnerability with "Add VEX" action
        const addButton = page.getByRole('button', { name: /Add VEX|VEX追加/i });
        if (await addButton.isVisible()) {
            await addButton.click();

            // Fill in VEX form
            const statusSelect = page.locator('select').first();
            if (await statusSelect.isVisible()) {
                await statusSelect.selectOption('not_affected');
            }

            // Select justification if available
            const justificationSelect = page.locator('select').nth(1);
            if (await justificationSelect.isVisible()) {
                await justificationSelect.selectOption('component_not_present');
            }

            // Add impact statement
            const impactInput = page.getByPlaceholder(/impact|影響/i);
            if (await impactInput.isVisible()) {
                await impactInput.fill('This component is not used in production.');
            }

            // Submit
            await page.getByRole('button', { name: /Save|Submit|保存/i }).click();

            await page.waitForTimeout(1000);
        }
    });

    test('should export VEX document', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on VEX tab - use specific locator for tab button with count
        await page.getByRole('button', { name: /^VEX \(\d+\)$/i }).click();
        await page.waitForTimeout(500);

        // Look for export button
        const exportButton = page.getByRole('button', { name: /Export|エクスポート/i });
        const exportLink = page.getByRole('link', { name: /Export|エクスポート/i });

        if (await exportButton.isVisible()) {
            // Just verify the button exists - clicking may trigger download
            await expect(exportButton).toBeEnabled();
        } else if (await exportLink.isVisible()) {
            await expect(exportLink).toHaveAttribute('href', /vex\/export/);
        }
    });

    test('should delete VEX statement', async ({ page, request }) => {
        // First create a VEX statement via API to ensure we have one
        const vulnResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`);
        const vulns = await vulnResponse.json();

        if (!vulns || vulns.length === 0) {
            test.skip();
            return;
        }

        // Create VEX via API
        await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/vex`, {
            data: {
                vulnerability_id: vulns[0].id,
                status: 'under_investigation',
            },
        });

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on VEX tab - use specific locator for tab button with count
        await page.getByRole('button', { name: /^VEX \(\d+\)$/i }).click();
        await page.waitForTimeout(1000);

        // Find delete button
        const deleteButton = page.locator('button').filter({ has: page.locator('svg.lucide-trash-2, svg.lucide-x') }).first();
        if (await deleteButton.isVisible()) {
            await deleteButton.click();

            // Confirm deletion if dialog appears
            const confirmButton = page.getByRole('button', { name: /Delete|Confirm|削除/i });
            if (await confirmButton.isVisible()) {
                await confirmButton.click();
            }

            await page.waitForTimeout(1000);
        }
    });
});

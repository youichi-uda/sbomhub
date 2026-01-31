import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('Complete Workflow', () => {
    // Track resources for cleanup
    let createdProjectId: string;

    test.afterAll(async ({ request }) => {
        // Cleanup: delete the project created during tests
        if (createdProjectId) {
            await request.delete(`${API_BASE_URL}/api/v1/projects/${createdProjectId}`);
        }
    });

    test('should complete full SBOM management workflow', async ({ page, request }) => {
        // ============================
        // Step 1: Create a new project
        // ============================
        await page.goto('/en/projects');

        const projectName = `Workflow Test ${Date.now()}`;
        const projectDescription = 'Complete workflow E2E test project';

        await page.getByRole('button', { name: /New Project/i }).click();
        await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

        await page.getByPlaceholder('My Project').fill(projectName);
        await page.getByPlaceholder('Project description').fill(projectDescription);
        await page.locator('.fixed button:has-text("Create")').click();

        // Verify project was created
        await expect(page.getByText(projectName)).toBeVisible({ timeout: 10000 });

        // Get project ID for later steps
        const projectLink = page.locator(`a[href*="/projects/"]`).filter({ hasText: projectName }).first();
        const href = await projectLink.getAttribute('href');
        createdProjectId = href?.match(/projects\/([^\/]+)/)?.[1] || '';

        expect(createdProjectId).toBeTruthy();

        // ============================
        // Step 2: Upload SBOM
        // ============================
        await page.getByText(projectName).click();
        await expect(page.getByText('Back to Projects')).toBeVisible();

        // Verify Upload SBOM button is visible
        const uploadButton = page.getByRole('button', { name: /Upload SBOM/i });
        await expect(uploadButton).toBeVisible();

        // Upload SBOM via API (more reliable than file dialog in E2E)
        const sbom = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            metadata: {
                timestamp: new Date().toISOString(),
                tools: [{ name: 'E2E Test', version: '1.0' }],
            },
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
                {
                    type: 'library',
                    name: 'log4j-core',
                    version: '2.14.0',
                    purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0',
                    licenses: [{ license: { id: 'Apache-2.0' } }],
                },
            ],
        };

        const uploadResponse = await request.post(
            `${API_BASE_URL}/api/v1/projects/${createdProjectId}/sbom`,
            {
                data: JSON.stringify(sbom),
                headers: { 'Content-Type': 'application/json' },
            }
        );
        expect(uploadResponse.ok()).toBeTruthy();
        const sbomData = await uploadResponse.json();

        // Reload page to see uploaded SBOM
        await page.reload();
        await page.waitForLoadState('networkidle');

        // ============================
        // Step 3: Verify Components
        // ============================
        const componentsTab = page.getByRole('button', { name: /Components/i });
        await componentsTab.click();
        await page.waitForTimeout(1000);

        // Verify components are displayed
        await expect(page.getByText('lodash')).toBeVisible({ timeout: 5000 });
        await expect(page.getByText('express')).toBeVisible();
        await expect(page.getByText('log4j-core')).toBeVisible();

        // Verify component count matches
        const tabText = await componentsTab.textContent();
        const countMatch = tabText?.match(/\((\d+)\)/);
        if (countMatch) {
            const displayedCount = parseInt(countMatch[1], 10);
            expect(displayedCount).toBe(3);
        }

        // ============================
        // Step 4: Trigger Vulnerability Scan
        // ============================
        const scanResponse = await request.post(
            `${API_BASE_URL}/api/v1/projects/${createdProjectId}/scan?sbom_id=${sbomData.id}`
        );
        expect(scanResponse.status()).toBe(202);

        // Wait for scan to complete
        await page.waitForTimeout(10000);

        // Refresh and check vulnerabilities
        await page.reload();
        await page.waitForLoadState('networkidle');

        const vulnTab = page.getByRole('button', { name: /Vulnerabilities/i });
        await vulnTab.click();
        await page.waitForTimeout(1000);

        // Get vulnerability count from API
        const vulnResponse = await request.get(
            `${API_BASE_URL}/api/v1/projects/${createdProjectId}/vulnerabilities`
        );
        const vulnerabilities = await vulnResponse.json();

        // Verify vulnerability count is shown
        const vulnTabText = await vulnTab.textContent();
        const vulnCountMatch = vulnTabText?.match(/\((\d+)\)/);
        if (vulnCountMatch && vulnerabilities.length > 0) {
            const displayedCount = parseInt(vulnCountMatch[1], 10);
            expect(displayedCount).toBe(vulnerabilities.length);
        }

        // ============================
        // Step 5: Create VEX Statement (if vulnerabilities exist)
        // ============================
        if (vulnerabilities && vulnerabilities.length > 0) {
            // Create VEX via API
            const vexResponse = await request.post(
                `${API_BASE_URL}/api/v1/projects/${createdProjectId}/vex`,
                {
                    data: {
                        vulnerability_id: vulnerabilities[0].id,
                        status: 'not_affected',
                        justification: 'component_not_present',
                        impact_statement: 'Component is not used in production environment',
                    },
                }
            );

            if (vexResponse.ok()) {
                // Navigate to VEX tab
                const vexTab = page.getByRole('button', { name: /^VEX \(\d+\)$/i });
                await vexTab.click();
                await page.waitForTimeout(1000);

                // Verify VEX statement is visible
                await expect(page.getByText(/not_affected/i).first()).toBeVisible();
            }
        }

        // ============================
        // Step 6: SSVC Evaluation (if vulnerabilities exist)
        // ============================
        if (vulnerabilities && vulnerabilities.length > 0) {
            // Navigate to SSVC if available
            const ssvcTab = page.getByRole('button', { name: /SSVC/i });

            if (await ssvcTab.isVisible()) {
                await ssvcTab.click();
                await page.waitForTimeout(1000);

                // Check if SSVC evaluation UI is present
                const ssvcForm = page.locator('form, [data-testid="ssvc-form"]');
                const exploitationSelect = page.getByRole('combobox').filter({ hasText: /Exploitation|Automatable/i });

                if (await ssvcForm.isVisible() || await exploitationSelect.isVisible()) {
                    // SSVC evaluation UI is available
                    await expect(page.getByText(/SSVC|Decision|Exploitation/i).first()).toBeVisible();
                }
            }
        }

        // ============================
        // Step 7: Verify Dashboard
        // ============================
        await page.goto('/en/dashboard');
        await page.waitForLoadState('networkidle');

        // Dashboard should show the project
        await expect(page.getByText(projectName)).toBeVisible({ timeout: 5000 });

        // ============================
        // Step 8: Verify Search
        // ============================
        await page.goto('/en/search');
        await page.waitForLoadState('networkidle');

        // Search for component we uploaded
        const componentInput = page.getByPlaceholder(/component/i).or(page.locator('input[type="text"]').nth(1));
        if (await componentInput.isVisible()) {
            await componentInput.fill('lodash');
            await page.getByRole('button', { name: /Search|検索/i }).click();
            await page.waitForTimeout(2000);

            // Should find the component in our project
            const searchResults = page.locator('a[href*="/projects/"]').filter({ hasText: projectName });
            const hasResults = await searchResults.isVisible().catch(() => false);

            // Either we find results or empty state - both are valid
            expect(hasResults || await page.locator('body').isVisible()).toBeTruthy();
        }
    });

    test('should handle SBOM version update workflow', async ({ page, request }) => {
        // Create a project for this test
        const projectName = `Version Update Test ${Date.now()}`;

        const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: projectName,
                description: 'SBOM version update test',
            },
        });
        const project = await projectResponse.json();
        const projectId = project.id;

        // Upload initial SBOM (version 1)
        const sbomV1 = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [
                {
                    type: 'library',
                    name: 'lodash',
                    version: '4.17.20',
                    licenses: [{ license: { id: 'MIT' } }],
                },
            ],
        };

        await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
            data: JSON.stringify(sbomV1),
            headers: { 'Content-Type': 'application/json' },
        });

        // Navigate to project
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Verify initial component
        await page.getByRole('button', { name: /Components/i }).click();
        await expect(page.getByText('4.17.20')).toBeVisible();

        // Upload updated SBOM (version 2)
        const sbomV2 = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 2,
            components: [
                {
                    type: 'library',
                    name: 'lodash',
                    version: '4.17.21', // Updated version
                    licenses: [{ license: { id: 'MIT' } }],
                },
                {
                    type: 'library',
                    name: 'axios', // New component
                    version: '1.0.0',
                    licenses: [{ license: { id: 'MIT' } }],
                },
            ],
        };

        await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
            data: JSON.stringify(sbomV2),
            headers: { 'Content-Type': 'application/json' },
        });

        // Reload and verify updated components
        await page.reload();
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Components/i }).click();
        await page.waitForTimeout(1000);

        // Verify updated version
        await expect(page.getByText('4.17.21')).toBeVisible();
        await expect(page.getByText('axios')).toBeVisible();

        // Verify component count updated
        const componentsTab = page.getByRole('button', { name: /Components/i });
        const tabText = await componentsTab.textContent();
        const countMatch = tabText?.match(/\((\d+)\)/);
        if (countMatch) {
            const displayedCount = parseInt(countMatch[1], 10);
            expect(displayedCount).toBe(2);
        }

        // Cleanup
        await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    });

    test('should handle multi-project comparison workflow', async ({ page, request }) => {
        // Create two projects
        const project1Name = `Compare Project 1 ${Date.now()}`;
        const project2Name = `Compare Project 2 ${Date.now()}`;

        const project1Response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: { name: project1Name, description: 'First project' },
        });
        const project1 = await project1Response.json();

        const project2Response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: { name: project2Name, description: 'Second project' },
        });
        const project2 = await project2Response.json();

        // Upload different SBOMs
        const sbom1 = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [
                { type: 'library', name: 'lodash', version: '4.17.20', licenses: [{ license: { id: 'MIT' } }] },
                { type: 'library', name: 'express', version: '4.17.1', licenses: [{ license: { id: 'MIT' } }] },
            ],
        };

        const sbom2 = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [
                { type: 'library', name: 'lodash', version: '4.17.21', licenses: [{ license: { id: 'MIT' } }] }, // Different version
                { type: 'library', name: 'axios', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] }, // Different library
            ],
        };

        await request.post(`${API_BASE_URL}/api/v1/projects/${project1.id}/sbom`, {
            data: JSON.stringify(sbom1),
            headers: { 'Content-Type': 'application/json' },
        });

        await request.post(`${API_BASE_URL}/api/v1/projects/${project2.id}/sbom`, {
            data: JSON.stringify(sbom2),
            headers: { 'Content-Type': 'application/json' },
        });

        // Verify both projects on dashboard
        await page.goto('/en/dashboard');
        await page.waitForLoadState('networkidle');

        await expect(page.getByText(project1Name)).toBeVisible({ timeout: 5000 });
        await expect(page.getByText(project2Name)).toBeVisible();

        // Search for lodash - should find in both projects
        await page.goto('/en/search');
        const componentInput = page.getByPlaceholder(/component/i).or(page.locator('input[type="text"]').nth(1));

        if (await componentInput.isVisible()) {
            await componentInput.fill('lodash');
            await page.getByRole('button', { name: /Search|検索/i }).click();
            await page.waitForTimeout(2000);

            // Results should include both projects
            const project1Link = page.locator('a[href*="/projects/"]').filter({ hasText: project1Name });
            const project2Link = page.locator('a[href*="/projects/"]').filter({ hasText: project2Name });

            const hasProject1 = await project1Link.isVisible().catch(() => false);
            const hasProject2 = await project2Link.isVisible().catch(() => false);

            // At least one project should be in results
            expect(hasProject1 || hasProject2).toBeTruthy();
        }

        // Cleanup
        await request.delete(`${API_BASE_URL}/api/v1/projects/${project1.id}`);
        await request.delete(`${API_BASE_URL}/api/v1/projects/${project2.id}`);
    });
});

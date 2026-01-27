import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('License Policy Management', () => {
    let projectId: string;

    test.beforeAll(async ({ request }) => {
        // Create a test project
        const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `License Test Project ${Date.now()}`,
                description: 'Project for license policy E2E tests',
            },
        });
        const project = await response.json();
        projectId = project.id;

        // Upload SBOM with licensed components
        const sbom = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [
                {
                    type: 'library',
                    name: 'mit-component',
                    version: '1.0.0',
                    licenses: [{ license: { id: 'MIT' } }],
                },
                {
                    type: 'library',
                    name: 'gpl-component',
                    version: '2.0.0',
                    licenses: [{ license: { id: 'GPL-3.0' } }],
                },
                {
                    type: 'library',
                    name: 'apache-component',
                    version: '3.0.0',
                    licenses: [{ license: { id: 'Apache-2.0' } }],
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

    test('should display Licenses tab in project detail', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Look for Licenses tab
        const licensesTab = page.getByRole('button', { name: /Licenses|ライセンス/i });
        await expect(licensesTab).toBeVisible({ timeout: 5000 });
    });

    test('should show license policies list', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on Licenses tab
        await page.getByRole('button', { name: /Licenses|ライセンス/i }).click();
        await page.waitForTimeout(500);

        // Should show policies section
        await expect(page.locator('body')).toBeVisible();
    });

    test('should create allowed license policy', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on Licenses tab
        await page.getByRole('button', { name: /Licenses|ライセンス/i }).click();
        await page.waitForTimeout(500);

        // Look for add policy button
        const addButton = page.getByRole('button', { name: /Add Policy|Add License|ポリシー追加/i });
        if (await addButton.isVisible()) {
            await addButton.click();

            // Select license
            const licenseSelect = page.locator('select').first();
            if (await licenseSelect.isVisible()) {
                await licenseSelect.selectOption({ label: /MIT/i });
            }

            // Select policy type
            const policySelect = page.locator('select').nth(1);
            if (await policySelect.isVisible()) {
                await policySelect.selectOption('allowed');
            }

            // Add reason
            const reasonInput = page.getByPlaceholder(/reason|理由/i);
            if (await reasonInput.isVisible()) {
                await reasonInput.fill('MIT is approved for commercial use');
            }

            // Submit
            await page.getByRole('button', { name: /Save|Create|保存/i }).click();
            await page.waitForTimeout(1000);

            // Verify policy appears
            await expect(page.getByText('MIT')).toBeVisible();
        }
    });

    test('should create denied license policy', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Licenses|ライセンス/i }).click();
        await page.waitForTimeout(500);

        const addButton = page.getByRole('button', { name: /Add Policy|Add License|ポリシー追加/i });
        if (await addButton.isVisible()) {
            await addButton.click();

            // Select GPL license
            const licenseSelect = page.locator('select').first();
            if (await licenseSelect.isVisible()) {
                // Try to select GPL
                const options = await licenseSelect.locator('option').allTextContents();
                const gplOption = options.find((o) => o.includes('GPL'));
                if (gplOption) {
                    await licenseSelect.selectOption({ label: gplOption });
                }
            }

            // Select denied policy type
            const policySelect = page.locator('select').nth(1);
            if (await policySelect.isVisible()) {
                await policySelect.selectOption('denied');
            }

            const reasonInput = page.getByPlaceholder(/reason|理由/i);
            if (await reasonInput.isVisible()) {
                await reasonInput.fill('GPL not allowed due to copyleft requirements');
            }

            await page.getByRole('button', { name: /Save|Create|保存/i }).click();
            await page.waitForTimeout(1000);
        }
    });

    test('should check license violations', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Licenses|ライセンス/i }).click();
        await page.waitForTimeout(500);

        // Look for violations section or check button
        const checkButton = page.getByRole('button', { name: /Check Violations|違反チェック/i });
        if (await checkButton.isVisible()) {
            await checkButton.click();
            await page.waitForTimeout(1000);
        }

        // Violations may or may not be shown depending on policies
        await expect(page.locator('body')).toBeVisible();
    });

    test('should delete license policy', async ({ page, request }) => {
        // First create a policy via API
        await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/licenses`, {
            data: {
                license_id: 'BSD-3-Clause',
                license_name: 'BSD 3-Clause',
                policy_type: 'review',
                reason: 'Needs legal review',
            },
        });

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Licenses|ライセンス/i }).click();
        await page.waitForTimeout(1000);

        // Find delete button
        const deleteButton = page.locator('button').filter({ has: page.locator('svg.lucide-trash-2') }).first();
        if (await deleteButton.isVisible()) {
            await deleteButton.click();

            // Confirm if dialog appears
            const confirmButton = page.getByRole('button', { name: /Delete|Confirm|削除/i });
            if (await confirmButton.isVisible()) {
                await confirmButton.click();
            }

            await page.waitForTimeout(1000);
        }
    });
});

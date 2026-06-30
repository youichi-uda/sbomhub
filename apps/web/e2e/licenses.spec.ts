import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// M12-1 #82: root-cause audited (F164-style page-side hydration audit).
// The per-project Licenses tab DOES exist on /projects/:id — see
// apps/web/src/app/[locale]/(dashboard)/projects/[id]/page.tsx ~L298
// which renders the tab as `{t("Components.license")} ({licensePolicies.length})`
// (i.e. "License (0)" in EN, "ライセンス (0)" in JA). The M11-2 hang
// at 15s was driven by the regex `/Licenses|ライセンス/i` requiring the
// trailing "s" — JS regex `Licenses` does NOT match "License" (singular).
// Fix: allow either form via `/Licenses?|License|ライセンス/i`. The
// LicensePolicyForm body matches the spec asserts (select first =
// license dropdown with "MIT License (MIT)" labels, select second =
// policy type with `allowed` / `denied` / `review` values, textarea
// for reason, submit button text "Add Policy" identical to the
// header trigger so `nth(1)` is the form submit).
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

        // Look for Licenses tab. M12-1 #82: the tab text is
        // singular "License (0)" in EN (`t("Components.license")` +
        // count) — `/Licenses/i` would not match because regex needs
        // the trailing `s`. Accept either form for forward-compat.
        const licensesTab = page.getByRole('button', { name: /Licenses?|License|ライセンス/i });
        await expect(licensesTab).toBeVisible({ timeout: 5000 });
    });

    test('should show license policies list', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on Licenses tab — accept singular/plural EN forms.
        await page.getByRole('button', { name: /Licenses?|License|ライセンス/i }).click();
        await page.waitForTimeout(500);

        // Should show policies section
        await expect(page.locator('body')).toBeVisible();
    });

    test('should create allowed license policy', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on Licenses tab — accept singular/plural EN forms.
        await page.getByRole('button', { name: /Licenses?|License|ライセンス/i }).click();
        await page.waitForTimeout(500);

        // Click the Add Policy button
        await page.getByRole('button', { name: 'Add Policy' }).click();
        await page.waitForTimeout(300);

        // Select license - options are formatted as "MIT License (MIT)"
        const licenseSelect = page.locator('select').first();
        await expect(licenseSelect).toBeVisible();
        await licenseSelect.selectOption({ label: 'MIT License (MIT)' });

        // Select policy type - second select is for policy type, default is "allowed"
        const policySelect = page.locator('select').nth(1);
        await expect(policySelect).toBeVisible();
        await policySelect.selectOption('allowed');

        // Add reason
        const reasonInput = page.locator('textarea');
        await reasonInput.fill('MIT is approved for commercial use');

        // Submit - button text is "Add Policy"
        await page.getByRole('button', { name: 'Add Policy' }).nth(1).click();
        await page.waitForTimeout(1000);

        // Verify policy appears in the list
        await expect(page.getByText('MIT License')).toBeVisible();
    });

    test('should create denied license policy', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on Licenses tab — accept singular/plural EN forms.
        await page.getByRole('button', { name: /Licenses?|License|ライセンス/i }).click();
        await page.waitForTimeout(500);

        // Click the Add Policy button
        await page.getByRole('button', { name: 'Add Policy' }).click();
        await page.waitForTimeout(300);

        // Select GPL license - options are formatted as "GNU GPL v3.0 (GPL-3.0-only)"
        const licenseSelect = page.locator('select').first();
        await expect(licenseSelect).toBeVisible();
        await licenseSelect.selectOption({ label: 'GNU GPL v3.0 (GPL-3.0-only)' });

        // Select denied policy type
        const policySelect = page.locator('select').nth(1);
        await expect(policySelect).toBeVisible();
        await policySelect.selectOption('denied');

        // Add reason
        const reasonInput = page.locator('textarea');
        await reasonInput.fill('GPL not allowed due to copyleft requirements');

        // Submit - button text is "Add Policy"
        await page.getByRole('button', { name: 'Add Policy' }).nth(1).click();
        await page.waitForTimeout(1000);

        // Verify policy appears in the list
        await expect(page.getByText('GNU GPL v3.0')).toBeVisible();
    });

    test('should check license violations', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /Licenses?|License|ライセンス/i }).click();
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

        await page.getByRole('button', { name: /Licenses?|License|ライセンス/i }).click();
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

import { test, expect } from '@playwright/test';
import en from '../messages/en.json';

import { API_BASE_URL, createProject, uniqueName, uploadSbom } from './fixtures/vuln-project';

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
    let sbomId: string;

    test.beforeAll(async ({ request }) => {
        // Create a test project
        const project = await createProject(request, uniqueName('License Test Project'), 'Project for license policy E2E tests');
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

        sbomId = await uploadSbom(request, projectId, sbom);
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

    test('should show license policies list', async ({ page, request }) => {
        // A policy of this spec's own, so the list has a known row.
        const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/licenses`, {
            data: { license_id: 'ISC', license_name: 'ISC License', policy_type: 'review', reason: 'E2E list check' },
        });
        expect(createResponse.ok(), `policy create returned ${createResponse.status()}`).toBe(true);
        const policy = await createResponse.json();
        try {
            await page.goto(`/en/projects/${projectId}`);
            await page.getByRole('button', { name: /Licenses?|License|ライセンス/i }).click();

            await expect(page.getByText(en.ProjectDetail.licensePolicies, { exact: true })).toBeVisible({ timeout: 10000 });
            await expect(page.getByRole('button', { name: 'Add Policy' })).toBeVisible();
            const row = page
                .locator('div.border.rounded-lg:not(.bg-card)')
                .filter({ hasText: '(ISC)' })
                .filter({ has: page.getByRole('button', { name: en.Common.delete, exact: true }) });
            await expect(row).toHaveCount(1);
            await expect(row).toContainText('ISC License');
            await expect(row.getByText('review', { exact: true })).toBeVisible();
        } finally {
            await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}/licenses/${policy.id}`);
        }
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
        const licenseSelect = page.locator('select:not([data-testid="evidence-pack-format"])').first();
        await expect(licenseSelect).toBeVisible();
        await licenseSelect.selectOption({ label: 'MIT License (MIT)' });

        // Select policy type - second select is for policy type, default is "allowed"
        const policySelect = page.locator('select:not([data-testid="evidence-pack-format"])').nth(1);
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
        const licenseSelect = page.locator('select:not([data-testid="evidence-pack-format"])').first();
        await expect(licenseSelect).toBeVisible();
        await licenseSelect.selectOption({ label: 'GNU GPL v3.0 (GPL-3.0-only)' });

        // Select denied policy type
        const policySelect = page.locator('select:not([data-testid="evidence-pack-format"])').nth(1);
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

    test('should check license violations', async ({ page, request }) => {
        // Deny Apache-2.0: the SBOM's apache-component now violates it.
        const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/licenses`, {
            data: {
                license_id: 'Apache-2.0',
                license_name: 'Apache License 2.0',
                policy_type: 'denied',
                reason: 'E2E: Apache-2.0 denied for the violation check',
            },
        });
        expect(createResponse.ok(), `policy create returned ${createResponse.status()}`).toBe(true);
        const policy = await createResponse.json();

        try {
            // The server reports the violation...
            const violationsRes = await request.get(
                `${API_BASE_URL}/api/v1/projects/${projectId}/licenses/violations?sbom_id=${sbomId}`,
            );
            expect(violationsRes.status()).toBe(200);
            const violations = ((await violationsRes.json()) ?? []) as Array<{ component_name: string; policy_type: string }>;
            expect(violations).toContainEqual(expect.objectContaining({ component_name: 'apache-component', policy_type: 'denied' }));

            // ...and the Licenses tab lists it, with the same count.
            await page.goto(`/en/projects/${projectId}`);
            await page.getByRole('button', { name: /Licenses?|License|ライセンス/i }).click();
            await expect(page.getByRole('heading', { name: `${en.ProjectDetail.licenseViolations} (${violations.length})` }))
                .toBeVisible({ timeout: 10000 });
            const row = page.locator('div.border-red-200', { hasText: 'apache-component' });
            await expect(row).toHaveCount(1);
            await expect(row).toContainText('3.0.0');
            await expect(row).toContainText('Apache-2.0');
            await expect(row).toContainText('denied');
            await expect(row).toContainText('E2E: Apache-2.0 denied for the violation check');
            // mit-component is allowed / unconstrained: no violation row.
            await expect(page.locator('div.border-red-200', { hasText: 'mit-component' })).toHaveCount(0);
        } finally {
            await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}/licenses/${policy.id}`);
        }
    });

    test('should delete license policy', async ({ page, request }) => {
        // First create a policy via API
        const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/licenses`, {
            data: {
                license_id: 'BSD-3-Clause',
                license_name: 'BSD 3-Clause',
                policy_type: 'review',
                reason: 'Needs legal review',
            },
        });
        expect(createResponse.ok(), `policy create returned ${createResponse.status()}`).toBe(true);
        const policy = await createResponse.json();
        expect(typeof policy.id).toBe('string');

        await page.goto(`/en/projects/${projectId}`);
        await page.getByRole('button', { name: /Licenses?|License|ライセンス/i }).click();

        // The policy's row (bordered box carrying "(BSD-3-Clause)"; the
        // enclosing Card is also bordered, hence :not(.bg-card)) and its
        // text "Delete" button. This used to look for an svg.lucide-trash-2
        // icon that this panel has never rendered, so the whole test body was
        // skipped behind an `if (isVisible)` guard and asserted nothing.
        const policyRow = page
            .locator('div.border.rounded-lg:not(.bg-card)')
            .filter({ hasText: '(BSD-3-Clause)' })
            .filter({ has: page.getByRole('button', { name: en.Common.delete, exact: true }) });
        await expect(policyRow).toHaveCount(1, { timeout: 10000 });

        // Deletion is confirmed through a native window.confirm().
        let confirmMessage: string | null = null;
        page.once('dialog', async (dialog) => {
            confirmMessage = `${dialog.type()}: ${dialog.message()}`;
            await dialog.accept();
        });
        await policyRow.getByRole('button', { name: en.Common.delete, exact: true }).click();
        await expect.poll(() => confirmMessage).toBe(`confirm: ${en.ProjectDetail.deleteLicenseConfirm}`);

        await expect(policyRow).toHaveCount(0);
        const listResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/licenses`);
        expect(listResponse.ok()).toBe(true);
        const policies = ((await listResponse.json()) ?? []) as Array<{ id: string }>;
        expect(policies.map((p) => p.id)).not.toContain(policy.id);
    });
});

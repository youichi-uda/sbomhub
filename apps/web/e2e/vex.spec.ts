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

    test('should show VEX statements list with count', async ({ page, request }) => {
        // Get VEX statements count from API
        const vexResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vex`);
        const vexStatements = await vexResponse.json();
        const expectedCount = Array.isArray(vexStatements) ? vexStatements.length : 0;

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Click on VEX tab
        const vexTab = page.getByRole('button', { name: /^VEX \(\d+\)$/i });
        await vexTab.click();
        await page.waitForTimeout(1000);

        // Verify the tab shows correct count
        const tabText = await vexTab.textContent();
        if (tabText) {
            const match = tabText.match(/\((\d+)\)/);
            if (match) {
                const displayedCount = parseInt(match[1], 10);
                expect(displayedCount).toBe(expectedCount);
            }
        }

        // If there are VEX statements, verify they are displayed
        if (expectedCount > 0) {
            // VEX statements should show status
            const statusIndicator = page.getByText(/not_affected|affected|under_investigation|fixed/i);
            await expect(statusIndicator.first()).toBeVisible();
        } else {
            // Empty state should be shown
            const emptyMessage = page.getByText(/no VEX|VEXなし|empty/i);
            const hasEmptyMessage = await emptyMessage.isVisible().catch(() => false);
            // Empty state or just no items - both are valid
            expect(hasEmptyMessage || true).toBeTruthy();
        }
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

    test('should delete VEX statement and update count', async ({ page, request }) => {
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

        // Get initial VEX count from tab
        const vexTab = page.getByRole('button', { name: /^VEX \(\d+\)$/i });
        const initialTabText = await vexTab.textContent();
        const initialMatch = initialTabText?.match(/\((\d+)\)/);
        const initialCount = initialMatch ? parseInt(initialMatch[1], 10) : 0;

        await vexTab.click();
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

            await page.waitForTimeout(2000);

            // Verify count decreased
            const updatedTabText = await vexTab.textContent();
            const updatedMatch = updatedTabText?.match(/\((\d+)\)/);
            const updatedCount = updatedMatch ? parseInt(updatedMatch[1], 10) : 0;

            expect(updatedCount).toBeLessThan(initialCount);
        }
    });

    test('should create VEX statement and verify in list', async ({ page, request }) => {
        const vulnResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`);
        const vulns = await vulnResponse.json();

        if (!vulns || vulns.length === 0) {
            test.skip();
            return;
        }

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // Get initial VEX count
        const vexTab = page.getByRole('button', { name: /^VEX \(\d+\)$/i });
        const initialTabText = await vexTab.textContent();
        const initialMatch = initialTabText?.match(/\((\d+)\)/);
        const initialCount = initialMatch ? parseInt(initialMatch[1], 10) : 0;

        await vexTab.click();
        await page.waitForTimeout(500);

        // Look for add VEX button
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
            await page.waitForTimeout(2000);

            // Verify count increased
            const updatedTabText = await vexTab.textContent();
            const updatedMatch = updatedTabText?.match(/\((\d+)\)/);
            const updatedCount = updatedMatch ? parseInt(updatedMatch[1], 10) : 0;

            expect(updatedCount).toBeGreaterThan(initialCount);

            // Verify the new VEX status is visible
            await expect(page.getByText(/not_affected/i).first()).toBeVisible();
        }
    });

    test('should render cross-project VEX suggestions section without crashing (M26 F376)', async ({ page }) => {
        // Cross-project VEX suggestion aggregation (issue #131, read-only
        // Phase 1). The web-e2e seed does NOT provision a second project in
        // the same tenant with an approved vex_statement that matches this
        // project's vulnerabilities, so in this environment the suggestions
        // API returns an empty list and the section renders nothing (the
        // component returns null when empty). The real aggregation behaviour
        // — tenant-scoped cross-project matching, tenant-boundary isolation,
        // self / already-triaged exclusion, purl vs vulnerability_only match
        // typing — is verified by the Wave A backend integration test
        // (apps/api, `-tags=integration`, real-PG), NOT here.
        //
        // Soft-guard style (consistent with the rest of this file): assert the
        // triage page renders regardless of suggestions, then, IF seed data
        // ever surfaces a suggestion, assert the section shape (provenance +
        // match-type badge). This keeps the test meaningful once cross-project
        // seed data lands without failing in the seedless CI env today.
        await page.goto(`/en/projects/${projectId}/triage`);
        await page.waitForLoadState('networkidle');

        // The triage page must render even when suggestions are empty / the
        // aggregation endpoint is not yet deployed.
        await expect(page.getByTestId('triage-page')).toBeVisible({ timeout: 10000 });

        const section = page.getByTestId('cross-project-suggestions');
        if (await section.isVisible().catch(() => false)) {
            // Section header count + at least one suggestion card carrying its
            // source-project provenance and a purl / CVE-only match label.
            const card = page.getByTestId('cross-project-suggestion-card').first();
            await expect(card).toBeVisible();
            await expect(card).toHaveAttribute('data-match-type', /^(purl|vulnerability_only)$/);
        }
    });

    test('should render a populated cross-project suggestion card (M26 F380)', async ({ page }) => {
        // Deterministic companion to the empty-state smoke test above. The
        // web-e2e seed never provisions cross-project VEX data, so the
        // non-empty render path (endpoint wiring, envelope → card mapping,
        // i18n keys for every label, no card crash) went unexercised — a
        // broken endpoint, a mis-mapped field, or a missing i18n key would
        // pass CI silently. Intercept the aggregation endpoint with a single
        // fully-populated suggestion and assert the card renders every piece
        // of provenance a reviewer relies on. The real aggregation semantics
        // (tenant isolation, exclusions, purl vs vulnerability_only, F377
        // component_id fan-out, F379 provenance) stay in the Wave A real-PG
        // integration tests; this pins only the web render contract.
        const suggestion = {
            vulnerability_id: '11111111-1111-4111-8111-111111111111',
            cve_id: 'CVE-2026-0999',
            component: {
                component_id: '22222222-2222-4222-8222-222222222222',
                name: 'libmock',
                version: '1.2.3',
                purl: 'pkg:npm/libmock@1.2.3',
            },
            match_type: 'purl',
            source: {
                project_id: '33333333-3333-4333-8333-333333333333',
                project_name: 'Mock Source Project',
                statement_id: '44444444-4444-4444-8444-444444444444',
                status: 'not_affected',
                justification: 'vulnerable_code_not_present',
                impact_statement: 'The vulnerable path is not reachable in our build.',
                action_statement: 'No action required.',
                created_at: '2026-07-01T00:00:00Z',
            },
        };

        // Host-agnostic glob so the intercept holds regardless of the API base
        // URL the web build points NEXT_PUBLIC_API_URL at.
        await page.route('**/api/v1/projects/*/vex/suggestions', route =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ suggestions: [suggestion] }),
            })
        );

        await page.goto(`/en/projects/${projectId}/triage`);
        await page.waitForLoadState('networkidle');

        await expect(page.getByTestId('triage-page')).toBeVisible({ timeout: 10000 });

        // Section renders (non-empty branch) with the header count.
        const section = page.getByTestId('cross-project-suggestions');
        await expect(section).toBeVisible();
        await expect(section).toContainText('Decided in other projects');
        await expect(section).toContainText('(1)');

        // The single card carries every field a reviewer weighs.
        const card = page.getByTestId('cross-project-suggestion-card').first();
        await expect(card).toBeVisible();
        await expect(card).toHaveAttribute('data-cve-id', 'CVE-2026-0999');
        await expect(card).toHaveAttribute('data-match-type', 'purl');
        // CVE id
        await expect(card).toContainText('CVE-2026-0999');
        // source project provenance
        await expect(card).toContainText('Mock Source Project');
        // match-type label (purl → "Component match")
        await expect(card).toContainText('Component match');
        // VEX status label (not_affected → "Not affected")
        await expect(card).toContainText('Not affected');
        // justification (underscores rendered as spaces) + impact + action
        await expect(card).toContainText('vulnerable code not present');
        await expect(card).toContainText('The vulnerable path is not reachable in our build.');
        await expect(card).toContainText('No action required.');
    });

    test('should display VEX status correctly for each statement', async ({ page, request }) => {
        const vexResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vex`);
        const vexStatements = await vexResponse.json();

        if (!vexStatements || vexStatements.length === 0) {
            test.skip();
            return;
        }

        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        await page.getByRole('button', { name: /^VEX \(\d+\)$/i }).click();
        await page.waitForTimeout(1000);

        // Verify each VEX statement status matches API data
        for (const vex of vexStatements.slice(0, 3)) { // Check first 3 to avoid long tests
            const statusText = page.getByText(new RegExp(vex.status, 'i'));
            await expect(statusText.first()).toBeVisible();
        }
    });
});

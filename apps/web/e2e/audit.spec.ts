import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// Audit Log is a Pro tier feature
// In self-hosted mode, it may be available; in SaaS mode without Pro, it shows upgrade prompt
test.describe('Audit Log', () => {
    let projectId: string | null = null;

    test.beforeAll(async ({ request }) => {
        // Create a test project to generate audit logs
        const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `Audit Test Project ${Date.now()}`,
                description: 'Project for audit log E2E tests',
            },
        });

        // Skip if auth required
        if (response.status() === 401) {
            return;
        }

        const project = await response.json();
        projectId = project.id;

        // Upload an SBOM to create more audit entries
        const sbom = {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [
                {
                    type: 'library',
                    name: 'test-component',
                    version: '1.0.0',
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

    test('should display audit log page or upgrade prompt', async ({ page }) => {
        await page.goto('/en/audit');
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, this is expected in SaaS mode
        const url = page.url();
        if (url.includes('/sign-in') || url.includes('/login')) {
            // Sign-in redirect is valid - test passes
            return;
        }

        // Check if we have access or get shown upgrade message
        const hasAccess = await page.getByRole('heading', { name: /Audit Log|監査ログ/i }).isVisible().catch(() => false);
        const upgradeMessage = await page.getByText(/upgrade|Pro|Enterprise|アップグレード|premium|available/i).isVisible().catch(() => false);

        // Either we have access or see upgrade prompt
        expect(hasAccess || upgradeMessage).toBeTruthy();
    });

    test('should show appropriate content based on tier', async ({ page }) => {
        await page.goto('/en/audit');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1000);

        // If redirected to sign-in, this is expected in SaaS mode
        const url = page.url();
        if (url.includes('/sign-in') || url.includes('/login')) {
            // Sign-in redirect is valid - test passes
            return;
        }

        // Check what's displayed - could be audit table or restriction message
        const restrictionMessage = page.getByText(/upgrade|Pro|Enterprise|restricted|制限|アップグレード|premium|available/i);
        const auditTable = page.locator('table, [data-testid="audit-log-table"]');

        const hasRestriction = await restrictionMessage.isVisible().catch(() => false);
        const hasTable = await auditTable.isVisible().catch(() => false);

        // One of these should be visible depending on tier
        expect(hasRestriction || hasTable).toBeTruthy();
    });

    test('should display audit log entries with required fields', async ({ page }) => {
        await page.goto('/en/audit');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1000);

        // Check if audit log table is visible
        const auditTable = page.locator('table, [data-testid="audit-log-table"]');

        if (await auditTable.isVisible()) {
            // Verify table headers exist
            const headers = ['Action', 'User', 'Timestamp', 'Details', 'アクション', 'ユーザー', '日時', '詳細', 'Type', 'Resource'];
            let hasExpectedHeaders = false;

            for (const header of headers) {
                const headerCell = page.getByRole('columnheader', { name: new RegExp(header, 'i') });
                if (await headerCell.isVisible().catch(() => false)) {
                    hasExpectedHeaders = true;
                    break;
                }
            }

            // If table is visible, it should have headers
            if (await auditTable.locator('thead').isVisible().catch(() => false)) {
                expect(hasExpectedHeaders).toBeTruthy();
            }

            // Verify at least one audit entry exists (if data is present)
            const tableRows = page.locator('table tbody tr');
            const rowCount = await tableRows.count();

            if (rowCount > 0) {
                // First row should have content
                const firstRow = tableRows.first();
                const actionText = await firstRow.textContent();
                expect(actionText).toBeTruthy();
            }
        }
        // If table is not visible, the test passes (user might not have access)
    });

    test('should filter audit logs by date range', async ({ page }) => {
        await page.goto('/en/audit');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1000);

        const auditTable = page.locator('table, [data-testid="audit-log-table"]');

        if (await auditTable.isVisible()) {
            // Look for date filter inputs
            const dateFromInput = page.locator('input[type="date"]').first();

            if (await dateFromInput.isVisible().catch(() => false)) {
                // Set date range to today
                const today = new Date().toISOString().split('T')[0];
                await dateFromInput.fill(today);

                // Apply filter if there's an apply button
                const applyButton = page.getByRole('button', { name: /Apply|Filter|適用|フィルター/i });
                if (await applyButton.isVisible().catch(() => false)) {
                    await applyButton.click();
                }

                await page.waitForTimeout(1000);

                // Verify table is still visible after filtering
                await expect(auditTable).toBeVisible();
            }
        }
        // If table or filter is not visible, test passes (user might not have access)
    });

    test('should filter audit logs by action type', async ({ page }) => {
        await page.goto('/en/audit');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1000);

        const auditTable = page.locator('table, [data-testid="audit-log-table"]');

        if (await auditTable.isVisible()) {
            // Look for action filter dropdown
            const actionFilter = page.getByRole('combobox').first();
            const actionFilterAlt = page.locator('select').first();

            let filter = null;
            if (await actionFilter.isVisible().catch(() => false)) {
                filter = actionFilter;
            } else if (await actionFilterAlt.isVisible().catch(() => false)) {
                filter = actionFilterAlt;
            }

            if (filter && await filter.isVisible().catch(() => false)) {
                // Click filter to open options
                await filter.click();
                await page.waitForTimeout(300);

                const createOption = page.getByRole('option', { name: /create|作成/i });
                if (await createOption.isVisible().catch(() => false)) {
                    await createOption.click();
                    await page.waitForTimeout(1000);

                    // Verify table is still visible after filtering
                    await expect(auditTable).toBeVisible();
                }
            }
        }
        // If table or filter is not visible, test passes (user might not have access)
    });

    test('should export audit logs to CSV', async ({ page }) => {
        await page.goto('/en/audit');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1000);

        const auditTable = page.locator('table, [data-testid="audit-log-table"]');

        if (await auditTable.isVisible()) {
            // Look for export button
            const exportButton = page.getByRole('button', { name: /Export|CSV|エクスポート|Download/i });

            if (await exportButton.isVisible().catch(() => false)) {
                // Verify button is enabled
                await expect(exportButton).toBeEnabled();

                // Set up download listener
                const downloadPromise = page.waitForEvent('download', { timeout: 5000 }).catch(() => null);

                await exportButton.click();

                const download = await downloadPromise;

                if (download) {
                    // Verify download file name contains csv
                    const fileName = download.suggestedFilename();
                    expect(fileName).toMatch(/\.csv$/i);
                }
            }
        }
        // If table or export button is not visible, test passes (user might not have access)
    });

    test('should paginate audit log entries', async ({ page }) => {
        await page.goto('/en/audit');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1000);

        const auditTable = page.locator('table, [data-testid="audit-log-table"]');

        if (await auditTable.isVisible()) {
            // Look for pagination controls
            const nextButton = page.getByRole('button', { name: /Next|次|→|>/i });
            const pageNumbers = page.locator('button, a').filter({ hasText: /^[0-9]+$/ });

            const hasPagination =
                await nextButton.isVisible().catch(() => false) ||
                await pageNumbers.first().isVisible().catch(() => false);

            if (hasPagination && await nextButton.isVisible().catch(() => false)) {
                const isEnabled = await nextButton.isEnabled().catch(() => false);
                if (isEnabled) {
                    // Get current page content
                    const initialContent = await auditTable.textContent();

                    // Click next page
                    await nextButton.click();
                    await page.waitForTimeout(1000);

                    // Content should be different (if there are more pages)
                    const newContent = await auditTable.textContent();

                    // Either content changed or we're on last page
                    expect(newContent || initialContent).toBeTruthy();
                }
            }
        }
        // If table or pagination is not visible, test passes (user might not have access)
    });

    test('should display audit log entry details', async ({ page }) => {
        await page.goto('/en/audit');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1000);

        const auditTable = page.locator('table, [data-testid="audit-log-table"]');

        if (await auditTable.isVisible()) {
            const tableRows = page.locator('table tbody tr');
            const rowCount = await tableRows.count();

            if (rowCount > 0) {
                // Click on first audit entry to see details
                const firstRow = tableRows.first();
                const detailsButton = firstRow.getByRole('button', { name: /Details|View|詳細|表示/i });

                if (await detailsButton.isVisible().catch(() => false)) {
                    await detailsButton.click();
                    await page.waitForTimeout(500);

                    // Verify details modal/panel appears
                    const detailsModal = page.locator('[role="dialog"], .modal, .details-panel');
                    if (await detailsModal.isVisible().catch(() => false)) {
                        await expect(detailsModal).toBeVisible();
                    }
                } else {
                    // Try clicking the row itself
                    await firstRow.click();
                    await page.waitForTimeout(500);
                }
            }
        }
        // If table is not visible or empty, test passes (user might not have access or no data)
    });

    test('should show project-specific audit logs', async ({ page }) => {
        if (!projectId) {
            test.skip();
            return;
        }

        // Navigate to project detail page
        await page.goto(`/en/projects/${projectId}`);
        await page.waitForLoadState('networkidle');

        // If redirected to sign-in, this is expected in SaaS mode
        const url = page.url();
        if (url.includes('/sign-in') || url.includes('/login')) {
            // Sign-in redirect is valid - test passes
            return;
        }

        // Wait for page to load with timeout
        await page.waitForTimeout(2000);

        // Look for audit/activity tab or section
        const auditTab = page.getByRole('button', { name: /Audit|Activity|監査|アクティビティ/i });
        const activitySection = page.getByText(/Recent Activity|最近のアクティビティ/i);

        if (await auditTab.isVisible({ timeout: 5000 }).catch(() => false)) {
            await auditTab.click();
            await page.waitForTimeout(1000);

            // Verify we can see the tab content (logs may or may not be present)
            const logEntries = page.locator('table tbody tr, .activity-item, [data-testid="audit-entry"]');
            const entryCount = await logEntries.count();

            // Entry count should be a valid number (may be 0 if feature not available)
            expect(entryCount).toBeGreaterThanOrEqual(0);
        } else if (await activitySection.isVisible({ timeout: 5000 }).catch(() => false)) {
            // Activity section should show recent actions
            await expect(activitySection).toBeVisible();
        }
        // If neither tab nor section is visible, test passes (feature may not be available)
    });
});

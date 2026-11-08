import { test, expect, type Page } from '@playwright/test';
import { API_BASE_URL, createProject, deleteProject, uniqueName, uploadSbom } from './fixtures/vuln-project';
import en from '../messages/en.json';

// Audit Logs page (src/app/[locale]/(dashboard)/audit/page.tsx).
//
// The CI stack is self-hosted (is_self_hosted: true, plan 'enterprise'),
// so the feature is always available: the page must render the table, never
// the upgrade prompt. Each request the API serves is recorded, so the
// beforeAll below creates a project (project.created), uploads an SBOM and
// views the project enough times that the log is guaranteed to span more
// than one 50-row page.
const A = en.Audit;

const PAGE_SIZE = 50;

test.describe('Audit Log', () => {
    let projectId = '';
    let idPrefix = '';

    test.beforeAll(async ({ request }) => {
        const project = await createProject(request, uniqueName('Audit Test Project'), 'Project for audit log E2E tests');
        projectId = project.id;
        idPrefix = projectId.substring(0, 8);

        await uploadSbom(request, projectId, {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [
                { type: 'library', name: 'test-component', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
            ],
        });

        // Each GET is audited as project.viewed: makes total > one page.
        for (let i = 0; i < PAGE_SIZE + 5; i++) {
            const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}`);
            expect(res.status()).toBe(200);
        }

        // The entries are visible through the API before any UI test runs.
        await expect
            .poll(() => hasCreatedEntry(request, projectId), { timeout: 10_000 })
            .toBe(true);
    });

    test.afterAll(async ({ request }) => {
        await deleteProject(request, projectId);
    });

    async function openAuditPage(page: Page) {
        await page.goto('/en/audit');
        await expect(page.getByRole('heading', { level: 1, name: A.title })).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('table')).toBeVisible();
    }

    async function openFilters(page: Page) {
        await page.getByRole('button', { name: A.filter }).click();
        await expect(page.getByRole('heading', { name: A.filterConditions })).toBeVisible();
        await expect(page.locator('select')).toHaveCount(2);
        await expect(page.locator('input[type="date"]')).toHaveCount(2);
    }

    /** The project.created row for the beforeAll project (resource id is shown truncated). */
    function createdRow(page: Page) {
        return page.locator('tbody tr', { hasText: `${idPrefix}...` }).filter({ hasText: 'Project Created' });
    }

    test('should display the audit log page, not the upgrade prompt', async ({ page }) => {
        await openAuditPage(page);
        // Self-hosted enterprise: the feature is available.
        await expect(page.getByText(A.proFeatureMessage)).toHaveCount(0);
        await expect(page.getByText(/^View all operation history \([\d,]+ entries\)$/)).toBeVisible();
        await expect(page.getByRole('button', { name: A.exportCsv })).toBeVisible();
    });

    test('should display audit log entries with required fields', async ({ page }) => {
        await openAuditPage(page);
        await expect(page.getByRole('columnheader')).toHaveText([
            A.dateTime,
            A.action,
            A.resource,
            A.user,
            A.ipAddress,
        ]);
        await expect(page.getByText(A.noLogs)).toHaveCount(0);
        // The seed + beforeAll guarantee a full first page.
        await expect(page.locator('tbody tr')).toHaveCount(PAGE_SIZE);
        const first = page.locator('tbody tr').first().locator('td');
        await expect(first).toHaveCount(5);
        await expect(first.nth(0)).not.toBeEmpty();
        await expect(first.nth(1)).not.toBeEmpty();
        await expect(first.nth(3)).toHaveText('Administrator');
    });

    test('should record the project created by this spec', async ({ page }) => {
        await openAuditPage(page);
        await openFilters(page);
        await page.locator('select').nth(0).selectOption('project.created');
        const row = createdRow(page);
        await expect(row).toHaveCount(1);
        const cells = row.locator('td');
        await expect(cells.nth(1)).toHaveText('Project Created');
        await expect(cells.nth(2)).toContainText('Project');
        await expect(cells.nth(3)).toHaveText('Administrator');
    });

    test('should filter audit logs by date range', async ({ page }) => {
        await openAuditPage(page);
        await openFilters(page);
        const startDate = page.locator('input[type="date"]').nth(0);

        // Nothing can have happened after 2099-01-01.
        await startDate.fill('2099-01-01');
        await expect(page.getByText(A.noLogs)).toBeVisible();
        await expect(page.locator('tbody tr')).toHaveCount(1);
        await expect(page.getByText('ON', { exact: true })).toBeVisible();

        // Everything happened after 2000-01-01.
        await startDate.fill('2000-01-01');
        await expect(page.getByText(A.noLogs)).toHaveCount(0);
        await expect(page.locator('tbody tr')).toHaveCount(PAGE_SIZE);

        // Clear resets the filter.
        await startDate.fill('2099-01-01');
        await expect(page.getByText(A.noLogs)).toBeVisible();
        await page.getByRole('button', { name: A.clear }).click();
        await expect(startDate).toHaveValue('');
        await expect(page.locator('tbody tr')).toHaveCount(PAGE_SIZE);
    });

    test('should filter audit logs by action type', async ({ page }) => {
        await openAuditPage(page);
        await openFilters(page);
        const actionSelect = page.locator('select').nth(0);
        await expect(actionSelect.locator('option', { hasText: 'Project Created' })).toHaveCount(1);
        await actionSelect.selectOption('project.created');
        await expect(actionSelect).toHaveValue('project.created');

        await expect(createdRow(page)).toHaveCount(1);
        // Every row left is a project.created entry.
        const actionCells = page.locator('tbody tr td:nth-child(2)');
        const texts = await actionCells.allTextContents();
        expect(texts.length).toBeGreaterThan(0);
        expect(new Set(texts.map((t) => t.trim()))).toEqual(new Set(['Project Created']));
    });

    test('should export audit logs to CSV', async ({ page }) => {
        await openAuditPage(page);
        const exportButton = page.getByRole('button', { name: A.exportCsv });
        await expect(exportButton).toBeEnabled();

        const downloadPromise = page.waitForEvent('download', { timeout: 15_000 });
        await exportButton.click();
        const download = await downloadPromise;

        expect(download.suggestedFilename()).toMatch(/^audit-logs-\d{4}-\d{2}-\d{2}\.csv$/);
        const path = await download.path();
        const fs = await import('node:fs/promises');
        const csv = (await fs.readFile(path, 'utf8')).replace(/^﻿/, '');
        const [header, ...rows] = csv.trim().split(/\r?\n/);
        expect(header).toBe('ID,Timestamp,Action,Resource Type,Resource ID,User ID,User Email,User Name,IP Address,User Agent');
        expect(rows.some((r) => r.includes(`,project.created,project,${projectId},`))).toBe(true);
        await expect(page.getByText(A.exportFailed)).toHaveCount(0);
    });

    test('should paginate audit log entries', async ({ page }) => {
        await openAuditPage(page);
        const prev = page.getByRole('button', { name: A.previous, exact: true });
        const next = page.getByRole('button', { name: A.next, exact: true });
        await expect(prev).toBeDisabled();
        await expect(next).toBeEnabled();
        await expect(page.getByText(/^1 \/ \d+$/)).toBeVisible();
        await expect(page.getByText(/^1 - 50 \/ [\d]+ entries$/)).toBeVisible();

        const firstRowPage1 = await page.locator('tbody tr').first().textContent();
        await next.click();
        await expect(page.getByText(/^2 \/ \d+$/)).toBeVisible();
        await expect(page.getByText(/^51 - \d+ \/ \d+ entries$/)).toBeVisible();
        await expect(prev).toBeEnabled();
        await expect(page.locator('tbody tr').first()).not.toHaveText(firstRowPage1 ?? '');

        await prev.click();
        await expect(page.getByText(/^1 \/ \d+$/)).toBeVisible();
        await expect(prev).toBeDisabled();
    });
});

async function hasCreatedEntry(request: import('@playwright/test').APIRequestContext, projectId: string) {
    const res = await request.get(`${API_BASE_URL}/api/v1/audit-logs?limit=100&action=project.created`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    return (body.logs as Array<{ resource_id?: string }>).some((l) => l.resource_id === projectId);
}

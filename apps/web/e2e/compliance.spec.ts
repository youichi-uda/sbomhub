import { test, expect, type APIRequestContext } from '@playwright/test';
import en from '../messages/en.json';
import ja from '../messages/ja.json';
import { API_BASE_URL, createProject, deleteProject, uniqueName, uploadSbom } from './fixtures/vuln-project';

// Project compliance page (src/app/[locale]/(dashboard)/projects/[id]/compliance/page.tsx).
// It used to be Japanese-only (hard-coded strings) whatever the URL locale,
// and the overview's category / check labels and details come from the API
// in Japanese only. Both are now translated (src/lib/compliance-labels.ts).
const C = en.Compliance;
const JAPANESE = /[\u3040-\u30ff\u3400-\u9fff\uff01-\uff60]/;

interface ComplianceCheck { id: string; label: string; passed: boolean }
interface ComplianceCategory { name: string; label: string; score: number; max_score: number; checks: ComplianceCheck[] }
interface ComplianceResult { score: number; max_score: number; categories: ComplianceCategory[] }

async function getCompliance(request: APIRequestContext, projectId: string): Promise<ComplianceResult> {
    const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/compliance`);
    expect(res.status()).toBe(200);
    const body = (await res.json()) as ComplianceResult;
    expect(body.categories.length).toBeGreaterThan(0);
    return body;
}

test.describe('Compliance Dashboard', () => {
    let projectId = '';

    test.beforeAll(async ({ request }) => {
        const project = await createProject(request, uniqueName('Compliance Test Project'), 'Project for compliance E2E tests');
        projectId = project.id;

        await uploadSbom(request, projectId, {
            bomFormat: 'CycloneDX',
            specVersion: '1.4',
            version: 1,
            components: [
                { type: 'library', name: 'express', version: '4.18.2', licenses: [{ license: { id: 'MIT' } }] },
                { type: 'library', name: 'lodash', version: '4.17.21', licenses: [{ license: { id: 'MIT' } }] },
            ],
        });
    });

    test.afterAll(async ({ request }) => {
        await deleteProject(request, projectId);
    });

    test('should navigate to compliance page', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByRole('heading', { level: 1, name: C.title })).toBeVisible({ timeout: 15000 });
        await expect(page.getByText(C.subtitle)).toBeVisible();
        await expect(page.getByText(C.loadFailed)).toHaveCount(0);
    });

    test('should display compliance score', async ({ page, request }) => {
        const result = await getCompliance(request, projectId);
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText(C.totalScore)).toBeVisible({ timeout: 15000 });
        await expect(page.getByText(`${result.score} / ${result.max_score} points`, { exact: true })).toBeVisible();
    });

    test('should display compliance categories', async ({ page, request }) => {
        const result = await getCompliance(request, projectId);
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText(C.checkItems, { exact: true })).toBeVisible({ timeout: 15000 });

        for (const category of result.categories) {
            const trigger = page.locator('button', { hasText: C.category[category.name as keyof typeof C.category] });
            await expect(trigger).toHaveCount(1);
            await expect(trigger).toContainText(`${category.score}/${category.max_score}`);
        }
    });

    test('should show compliance checks within categories', async ({ page, request }) => {
        const result = await getCompliance(request, projectId);
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText(C.checkItems, { exact: true })).toBeVisible({ timeout: 15000 });

        const checkLabel = (id: string) => C.check[id as keyof typeof C.check];
        for (const category of result.categories) {
            const firstCheck = page.getByText(checkLabel(category.checks[0].id), { exact: true });
            // Collapsed by default; expanding reveals every check.
            await expect(firstCheck).toHaveCount(0);
            await page.locator('button', { hasText: C.category[category.name as keyof typeof C.category] }).click();
            for (const check of category.checks) {
                const label = page.getByText(checkLabel(check.id), { exact: true });
                await expect(label).toBeVisible();
                // Passed checks are rendered in the foreground colour, failed ones muted.
                await expect(label).toHaveClass(check.passed ? /text-foreground/ : /text-muted-foreground/);
            }
        }
    });

    test('should have export report functionality', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText(C.exportTitle)).toBeVisible({ timeout: 15000 });

        for (const [label, format] of [['JSON', 'json'], ['PDF', 'pdf'], ['Excel', 'xlsx']] as const) {
            const link = page.getByRole('link', { name: label, exact: true });
            await expect(link).toHaveAttribute('href', `${API_BASE_URL}/api/v1/projects/${projectId}/compliance/report?format=${format}`);
            await expect(link).toHaveAttribute('download', '');
        }
    });

    test('should support multiple export formats', async ({ page, request }) => {
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText(C.exportTitle)).toBeVisible({ timeout: 15000 });

        const expected: Record<string, string> = {
            JSON: 'application/json',
            PDF: 'application/pdf',
            Excel: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        };
        for (const [label, contentType] of Object.entries(expected)) {
            // Follow the href the page renders: it must serve that format.
            const href = await page.getByRole('link', { name: label, exact: true }).getAttribute('href');
            expect(href).toBeTruthy();
            const res = await request.get(href!);
            expect(res.status(), `${label} export`).toBe(200);
            expect(res.headers()['content-type']).toContain(contentType);
            expect((await res.body()).length).toBeGreaterThan(0);
        }
    });

    test('should link back to project', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByRole('heading', { level: 1, name: C.title })).toBeVisible({ timeout: 15000 });

        // The back control is an icon-only link, named for screen readers,
        // that stays in the URL's locale (it always went to /ja).
        const backLink = page.getByRole('link', { name: C.back });
        await expect(backLink).toHaveCount(1);
        await expect(backLink).toHaveAttribute('href', `/en/projects/${projectId}`);
        // One interactive element, not a link wrapping an unnamed <button>
        // (Codex R3 Medium).
        await expect(backLink.locator('button')).toHaveCount(0);
        await backLink.click();
        await expect(page).toHaveURL(new RegExp(`/en/projects/${projectId}$`));
        await expect(page.getByRole('heading', { level: 1, name: C.title })).toHaveCount(0);
    });

    test('/en shows no Japanese on any tab, the API Japanese labels and details included', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByRole('heading', { level: 1, name: C.title })).toBeVisible({ timeout: 15000 });
        const main = page.locator('main');
        // Overview, every category expanded (checks and their details).
        for (const name of Object.values(C.category)) {
            const trigger = page.locator('button', { hasText: name });
            if ((await trigger.count()) > 0) await trigger.click();
        }
        // The details the API wrote in Japanese are shown in English.
        await expect(main.getByText(new RegExp(`^└─ ${C.detail.noVex}$`))).toBeVisible();
        expect((await main.innerText()).match(new RegExp(`.{0,20}${JAPANESE.source}.{0,20}`, 'g'))).toBeNull();

        for (const tab of [C.tabChecklist, C.tabVisualization]) {
            await page.getByRole('tab', { name: tab }).click();
            await expect(page.getByRole('tab', { name: tab })).toHaveAttribute('aria-selected', 'true');
            await page.waitForLoadState('networkidle');
            expect((await main.innerText()).match(new RegExp(`.{0,20}${JAPANESE.source}.{0,20}`, 'g')), tab).toBeNull();
        }
        // The checklist uses the API's English item labels.
        await page.getByRole('tab', { name: C.tabChecklist }).click();
        await expect(main.getByText('Clarify target software information', { exact: true })).toBeVisible();
    });

    test('/ja keeps the Japanese page', async ({ page }) => {
        await page.goto(`/ja/projects/${projectId}/compliance`);
        await expect(page.getByRole('heading', { level: 1, name: ja.Compliance.title })).toBeVisible({ timeout: 15000 });
        await expect(page.getByRole('tab', { name: ja.Compliance.tabChecklist })).toBeVisible();
        await expect(page.locator('button', { hasText: ja.Compliance.category.vulnerability_management })).toBeVisible();
        await page.getByRole('tab', { name: ja.Compliance.tabChecklist }).click();
        await expect(page.getByText('対象ソフトウェアの情報を明確化', { exact: true })).toBeVisible();
    });
});

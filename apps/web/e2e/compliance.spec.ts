import { test, expect, type APIRequestContext } from '@playwright/test';
import { API_BASE_URL, createProject, deleteProject, uniqueName, uploadSbom } from './fixtures/vuln-project';

// Project compliance page (src/app/[locale]/(dashboard)/projects/[id]/compliance/page.tsx).
// The page is Japanese-only (hard-coded strings), whatever the URL locale;
// the strings below are copied from it.

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
        await expect(page.getByRole('heading', { level: 1, name: 'コンプライアンス対応状況' })).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('経産省SBOMガイドライン自己評価')).toBeVisible();
        await expect(page.getByText('データの読み込みに失敗しました')).toHaveCount(0);
    });

    test('should display compliance score', async ({ page, request }) => {
        const result = await getCompliance(request, projectId);
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText('総合スコア')).toBeVisible({ timeout: 15000 });
        await expect(page.getByText(`${result.score} / ${result.max_score} ポイント`, { exact: true })).toBeVisible();
    });

    test('should display compliance categories', async ({ page, request }) => {
        const result = await getCompliance(request, projectId);
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText('チェック項目', { exact: true })).toBeVisible({ timeout: 15000 });

        for (const category of result.categories) {
            const trigger = page.locator('button', { hasText: category.label });
            await expect(trigger).toHaveCount(1);
            await expect(trigger).toContainText(`${category.score}/${category.max_score}`);
        }
    });

    test('should show compliance checks within categories', async ({ page, request }) => {
        const result = await getCompliance(request, projectId);
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText('チェック項目', { exact: true })).toBeVisible({ timeout: 15000 });

        for (const category of result.categories) {
            const firstCheck = page.getByText(category.checks[0].label, { exact: true });
            // Collapsed by default; expanding reveals every check.
            await expect(firstCheck).toHaveCount(0);
            await page.locator('button', { hasText: category.label }).click();
            for (const check of category.checks) {
                const label = page.getByText(check.label, { exact: true });
                await expect(label).toBeVisible();
                // Passed checks are rendered in the foreground colour, failed ones muted.
                await expect(label).toHaveClass(check.passed ? /text-foreground/ : /text-muted-foreground/);
            }
        }
    });

    test('should have export report functionality', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText('レポート出力')).toBeVisible({ timeout: 15000 });

        for (const [label, format] of [['JSON', 'json'], ['PDF', 'pdf'], ['Excel', 'xlsx']] as const) {
            const link = page.getByRole('link', { name: label, exact: true });
            await expect(link).toHaveAttribute('href', `${API_BASE_URL}/api/v1/projects/${projectId}/compliance/report?format=${format}`);
            await expect(link).toHaveAttribute('download', '');
        }
    });

    test('should support multiple export formats', async ({ page, request }) => {
        await page.goto(`/en/projects/${projectId}/compliance`);
        await expect(page.getByText('レポート出力')).toBeVisible({ timeout: 15000 });

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
        await expect(page.getByRole('heading', { level: 1, name: 'コンプライアンス対応状況' })).toBeVisible({ timeout: 15000 });

        // The back control is an icon-only link (no accessible name).
        const backLink = page.locator(`main a[href$="/projects/${projectId}"]`);
        await expect(backLink).toHaveCount(1);
        await backLink.click();
        await expect(page).toHaveURL(new RegExp(`/projects/${projectId}$`));
        await expect(page.getByRole('heading', { level: 1, name: 'コンプライアンス対応状況' })).toHaveCount(0);
    });
});

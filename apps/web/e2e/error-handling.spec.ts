import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { API_BASE_URL, createProject, deleteProject, uniqueName } from './fixtures/vuln-project';

// The projects list page (src/app/[locale]/(dashboard)/projects/page.tsx)
// catches a failed GET /projects and renders its normal "No projects yet"
// empty state: there is no error or retry UI. The two failure-path tests
// below keep the honest assertions (an error is shown, the misleading empty
// state is not) behind a fixme until the page grows an error state.
const LOAD_FAILURE_BUG =
    'BUG: projects list shows the "No projects yet" empty state when GET /api/v1/projects fails (network error or HTTP 500); no error message or retry is rendered';

async function expectLoadFailureShown(page: Page) {
    await expect(page.getByRole('heading', { level: 1, name: en.Projects.title })).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(/failed to load|could not load|error/i)).toBeVisible();
    await expect(page.getByText(en.Projects.noProjects)).toHaveCount(0);
}

test.describe('Error Handling', () => {
    test('should display 404 page for non-existent project', async ({ page }) => {
        await page.goto('/en/projects/non-existent-project-id-12345');
        await expect(page.locator('main')).toHaveText(en.Common.projectNotFound, { timeout: 15000 });
    });

    test('should display 404 page for invalid URL path', async ({ page }) => {
        const response = await page.goto('/en/invalid-page-path-xyz');
        expect(response?.status()).toBe(404);
        await expect(page.getByRole('heading', { level: 1, name: '404' })).toBeVisible();
        await expect(page.getByRole('heading', { level: 2, name: 'This page could not be found.' })).toBeVisible();
    });

    test('should handle network error gracefully', async ({ page }) => {
        test.fixme(true, LOAD_FAILURE_BUG);
        await page.route(`${API_BASE_URL}/api/v1/projects`, (route) => route.abort());
        await page.goto('/en/projects');
        await expectLoadFailureShown(page);
    });

    test('should show a loading state while the projects request is pending', async ({ page }) => {
        // Hold GET /projects until the loading state has been checked.
        let release!: () => void;
        const held = new Promise<void>((resolve) => { release = resolve; });
        await page.route(`${API_BASE_URL}/api/v1/projects`, async (route) => {
            await held;
            await route.continue();
        });

        await page.goto('/en/projects');
        await expect(page.getByText(en.Common.loading, { exact: true })).toBeVisible({ timeout: 15000 });
        await expect(page.getByRole('heading', { level: 1, name: en.Projects.title })).toHaveCount(0);

        release();
        await expect(page.getByRole('heading', { level: 1, name: en.Projects.title })).toBeVisible({ timeout: 15000 });
        await expect(page.getByText(en.Common.loading, { exact: true })).toHaveCount(0);
    });

    test('should handle project deletion of already deleted project', async ({ page, request }) => {
        const project = await createProject(request, uniqueName('Deleted Project'), 'Will be deleted');
        await deleteProject(request, project.id); // asserts GET -> 404

        await page.goto(`/en/projects/${project.id}`);
        await expect(page.locator('main')).toHaveText(en.Common.projectNotFound, { timeout: 15000 });
    });

    test('should show validation error for invalid SBOM upload', async ({ page, request }) => {
        const project = await createProject(request, uniqueName('Invalid SBOM Test'), 'For invalid SBOM test');
        try {
            await page.goto(`/en/projects/${project.id}`);
            await expect(page.getByRole('heading', { level: 1, name: project.name })).toBeVisible({ timeout: 15000 });

            // Upload a JSON file that is not an SBOM through the Upload tab.
            let alertText: string | null = null;
            page.once('dialog', async (dialog) => {
                alertText = `${dialog.type()}: ${dialog.message()}`;
                await dialog.accept();
            });
            const upload = page.waitForResponse(
                (r) => r.request().method() === 'POST' && r.url().endsWith(`/api/v1/projects/${project.id}/sbom`),
            );
            await page.locator('input[type="file"]').setInputFiles({
                name: 'not-an-sbom.json',
                mimeType: 'application/json',
                buffer: Buffer.from(JSON.stringify({ invalid: 'not a valid sbom', random: 'data' })),
            });

            const response = await upload;
            expect(response.status()).toBe(400);
            expect((await response.json()).error).toBe('failed to parse SBOM: unknown SBOM format');
            await expect.poll(() => alertText).toBe(`alert: ${en.ProjectDetail.uploadFailed}`);

            // Nothing was stored.
            const sboms = await request.get(`${API_BASE_URL}/api/v1/projects/${project.id}/sboms`);
            expect(sboms.status()).toBe(200);
            expect((await sboms.json()) ?? []).toEqual([]);
        } finally {
            await deleteProject(request, project.id);
        }
    });

    test('should handle empty SBOM components gracefully', async ({ page, request }) => {
        const project = await createProject(request, uniqueName('Empty SBOM Test'), 'For empty SBOM test');
        try {
            const upload = await request.post(`${API_BASE_URL}/api/v1/projects/${project.id}/sbom`, {
                data: JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.4', version: 1, components: [] }),
                headers: { 'Content-Type': 'application/json' },
            });
            expect(upload.status(), await upload.text()).toBe(201);

            await page.goto(`/en/projects/${project.id}`);
            const componentsTab = page.getByRole('button', { name: `${en.Components.title} (0)`, exact: true });
            await expect(componentsTab).toBeVisible({ timeout: 15000 });
            await componentsTab.click();
            await expect(page.getByText(en.ProjectDetail.noComponents, { exact: true })).toBeVisible();
            await expect(page.locator('main table')).toHaveCount(0);
        } finally {
            await deleteProject(request, project.id);
        }
    });

    // (Removed: "should display error for unauthorized access". It was a
    // reasonless declaration-form skip since M11-2. The CI stack runs in
    // self-hosted anonymous mode where every request is the seeded admin,
    // so there is no unauthorized state to reach, and the page it visited,
    // /en/settings, does not exist (404). Auth redirects are covered by
    // auth.spec.ts.)

    test('should handle API error responses gracefully', async ({ page }) => {
        test.fixme(true, LOAD_FAILURE_BUG);
        await page.route(`${API_BASE_URL}/api/v1/projects`, (route) =>
            route.fulfill({
                status: 500,
                contentType: 'application/json',
                body: JSON.stringify({ error: 'Internal Server Error' }),
            }),
        );
        await page.goto('/en/projects');
        await expectLoadFailureShown(page);
    });

    // Duplicate project names: the API deliberately allows them within a
    // tenant (M11-2 #77 left the dedup / 409 question as a product
    // decision). This pins the current behaviour — two projects, distinct
    // ids, both listed — so a change to it is a visible, deliberate one.
    test('should allow duplicate project names as distinct projects', async ({ page, request }) => {
        const projectName = `Duplicate Test ${Date.now()}`;
        const original = await createProject(request, projectName, 'Original');
        try {
            await page.goto('/en/projects');
            await page.getByRole('button', { name: /New Project/i }).first().click();
            await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });
            await page.getByPlaceholder('My Project').fill(projectName);
            await page.getByPlaceholder('Project description').fill('Duplicate attempt');

            const created = page.waitForResponse(
                (r) => r.request().method() === 'POST' && r.url().endsWith('/api/v1/projects'),
            );
            await page.locator('.fixed button:has-text("Create")').click();
            const response = await created;
            expect(response.status()).toBe(201);
            const duplicateId = (await response.json()).id as string;
            expect(duplicateId).not.toBe(original.id);

            // Both are listed, in the UI and in the API.
            await expect(page.getByRole('link', { name: projectName, exact: true })).toHaveCount(2, { timeout: 10000 });
            const list = await request.get(`${API_BASE_URL}/api/v1/projects`);
            expect(list.status()).toBe(200);
            const ids = ((await list.json()) as Array<{ id: string; name: string }>)
                .filter((p) => p.name === projectName)
                .map((p) => p.id)
                .sort();
            expect(ids).toEqual([original.id, duplicateId].sort());
        } finally {
            const list = await request.get(`${API_BASE_URL}/api/v1/projects`);
            for (const p of ((await list.json()) ?? []) as Array<{ id: string; name: string }>) {
                if (p.name === projectName) await deleteProject(request, p.id);
            }
        }
    });

    // (Removed: "should handle session expiration gracefully". The CI
    // stack has no session: anonymous self-hosted mode serves every request
    // as the seeded admin, so clearing cookies changes nothing and the test
    // could only ever take its "still has access" branch.)

    test('should accept a 10,000-component SBOM upload', async ({ request }) => {
        const project = await createProject(request, uniqueName('Large File Test'), 'For large file test');
        try {
            // 10,000 distinct component ROWS (distinct purls) that share ONE
            // synthetic name/version. Every upload starts a background NVD/JVN
            // scan, which de-duplicates by name+version
            // (service/nvd_cpe.go::nvdWorkKey); with 10,000 distinct names it
            // made ~10,000 live NVD lookups for up to the 30 min scan deadline,
            // outliving this test and the project. One shared synthetic name
            // keeps it at a single unmatchable lookup (Codex R4 High).
            // KNOWN LIMIT (Codex R5 High): the JVN half of that scan does not
            // de-duplicate and still walks all 10,000 rows (0.5 s apart) until
            // the 30 min scan deadline — as the pre-existing version of this
            // test always did. The fix is environmental, not here: run the
            // web-e2e-full stack with SBOMHUB_OFFLINE=true (verified: the full
            // suite passes unchanged in offline mode, 2026-11-09).

            const components = Array.from({ length: 10000 }, (_, i) => ({
                type: 'library',
                name: 'sbomhub-e2e-bulk-load',
                version: '1.0.0',
                purl: `pkg:generic/sbomhub-e2e/bulk-load@1.0.0?n=${i}`,
                licenses: [{ license: { id: 'MIT' } }],
            }));
            const uploadResponse = await request.post(`${API_BASE_URL}/api/v1/projects/${project.id}/sbom`, {
                data: JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.4', version: 1, components }),
                headers: { 'Content-Type': 'application/json' },
                timeout: 60000,
            });

            // ~1 MB is well within the upload limit: stored in full.
            expect(uploadResponse.status(), await uploadResponse.text()).toBe(201);
            const stored = await request.get(`${API_BASE_URL}/api/v1/projects/${project.id}/components`);
            expect(stored.status()).toBe(200);
            expect(((await stored.json()) as unknown[]).length).toBe(10000);
        } finally {
            await deleteProject(request, project.id);
        }
    });
});

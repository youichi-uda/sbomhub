import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import {
    API_BASE_URL,
    FIXTURE_CVES,
    createProject,
    deleteProject,
    listVulns,
    uniqueName,
    uploadSbom,
    uploadVulnerableSbom,
} from './fixtures/vuln-project';

const componentsTab = (page: Page) =>
    page.getByRole('button', { name: new RegExp(`^${en.Components.title} \\(\\d+\\)$`) });
const vulnerabilitiesTab = (page: Page) =>
    page.getByRole('button', { name: new RegExp(`^${en.Vulnerabilities.title} \\(\\d+\\)$`) });
const vexTab = (page: Page) => page.getByRole('button', { name: /^VEX \(\d+\)$/ });

/** The components table body rows, keyed by the name cell. */
const componentRow = (page: Page, name: string) =>
    page.locator('tbody tr').filter({ has: page.locator('td').first().getByText(name, { exact: true }) });

async function searchComponent(page: Page, name: string): Promise<void> {
    await page.goto('/en/search');
    await page.getByRole('tab', { name: en.Search.componentSearch }).click();
    await page.getByPlaceholder(en.Search.componentNamePlaceholder).fill(name);
    const response = page.waitForResponse(
        (resp) => resp.url().includes('/api/v1/search/component') && resp.request().method() === 'GET',
    );
    await page.getByRole('button', { name: en.Search.searchButton, exact: true }).click();
    expect((await response).status()).toBe(200);
}

test.describe('Complete Workflow', () => {
    // Track resources for cleanup
    let createdProjectId: string | undefined;

    test.afterAll(async ({ request }) => {
        await deleteProject(request, createdProjectId);
    });

    test('should complete full SBOM management workflow', async ({ page, request }) => {
        // ============================
        // Step 1: Create a new project through the UI
        // ============================
        await page.goto('/en/projects');

        const projectName = uniqueName('Workflow Test');
        const projectDescription = 'Complete workflow E2E test project';
        // A component name unique to this run, so the search step can
        // assert an exact hit.
        const marker = `workflow-e2e-marker-${Date.now()}`;

        await page.getByRole('button', { name: en.Projects.create }).first().click();
        const dialog = page.getByRole('dialog');
        await expect(dialog.getByPlaceholder(en.Projects.namePlaceholder)).toBeVisible();
        await dialog.getByPlaceholder(en.Projects.namePlaceholder).fill(projectName);
        await dialog.getByPlaceholder(en.Projects.descriptionPlaceholder).fill(projectDescription);
        await dialog.getByRole('button', { name: en.Common.create, exact: true }).click();
        await expect(dialog).toBeHidden();

        const projectLink = page.getByRole('link', { name: projectName, exact: true });
        await expect(projectLink).toBeVisible({ timeout: 10000 });
        const href = await projectLink.getAttribute('href');
        createdProjectId = href?.match(/projects\/([^/]+)/)?.[1];
        expect(createdProjectId, `project link href ${href}`).toBeTruthy();
        const projectId = createdProjectId as string;

        // The API agrees.
        const projectRes = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}`);
        expect(projectRes.status()).toBe(200);
        expect(await projectRes.json()).toMatchObject({ name: projectName, description: projectDescription });

        // ============================
        // Step 2: Open it and upload an SBOM
        // ============================
        await projectLink.click();
        await expect(page.getByRole('heading', { name: projectName, level: 1 })).toBeVisible();
        await expect(page.getByText(en.ProjectDetail.backToProjects)).toBeVisible();
        await expect(page.getByRole('button', { name: en.Projects.upload })).toBeVisible();

        // Upload via API (more reliable than the file dialog); the two
        // fixture components get linked to FIXTURE_CVES.
        await uploadVulnerableSbom(request, projectId, [
            {
                type: 'library',
                name: marker,
                version: '1.2.3',
                licenses: [{ license: { id: 'Apache-2.0' } }],
            },
        ]);
        await page.reload();

        // ============================
        // Step 3: Verify components
        // ============================
        await componentsTab(page).click();
        await expect(componentsTab(page)).toHaveText(`${en.Components.title} (3)`);
        await expect(componentRow(page, 'vuln-fixture-critical')).toHaveCount(1);
        await expect(componentRow(page, 'vuln-fixture-high')).toHaveCount(1);
        await expect(componentRow(page, marker)).toContainText('1.2.3');

        // ============================
        // Step 4: Verify vulnerabilities
        // ============================
        await expect(vulnerabilitiesTab(page)).toHaveText(`${en.Vulnerabilities.title} (${FIXTURE_CVES.length})`);
        await vulnerabilitiesTab(page).click();
        await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length);

        // ============================
        // Step 5: Create a VEX statement from the vulnerability entry
        // ============================
        const target = FIXTURE_CVES[2]; // HIGH, not in KEV
        await page
            .locator(`[data-vuln-cve-id="${target.cveId}"]`)
            .getByRole('button', { name: en.ProjectDetail.addVex })
            .click();
        const vexForm = page.locator('form').filter({
            has: page.getByText(en.VexForm.createFor.replace('{cveId}', target.cveId)),
        });
        await expect(vexForm).toBeVisible();
        await vexForm.locator('select').first().selectOption('not_affected');
        await vexForm.locator('select').nth(1).selectOption('component_not_present');
        await vexForm.getByPlaceholder(en.VexForm.impactPlaceholder).fill('Component is not used in production environment');
        await vexForm.getByRole('button', { name: en.VexForm.createVexStatement }).click();
        await expect(vexForm).toBeHidden();

        await expect(vexTab(page)).toHaveText('VEX (1)');
        const vexRow = page.locator('div.border.rounded-lg:not(.bg-card)').filter({ hasText: target.cveId });
        await expect(vexRow).toContainText('not affected');
        await expect(vexRow).toContainText('component not present');
        await expect(vexRow).toContainText('Component is not used in production environment');

        const vexRes = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vex`);
        expect(vexRes.status()).toBe(200);
        const vexList = (await vexRes.json()) as Array<Record<string, unknown>>;
        expect(vexList).toHaveLength(1);
        expect(vexList[0]).toMatchObject({
            vulnerability_cve_id: target.cveId,
            status: 'not_affected',
            justification: 'component_not_present',
        });

        // (There is no SSVC panel on the project page; SSVC is covered by
        // ssvc.spec.ts. The old step probed for one behind isVisible guards
        // and asserted nothing.)

        // ============================
        // Step 6: Verify dashboard
        // ============================
        await page.goto('/en/dashboard');
        await expect(
            page.getByRole('link', { name: projectName, exact: true }).first(),
        ).toHaveAttribute('href', `/en/projects/${projectId}`, { timeout: 10000 });

        // ============================
        // Step 7: Verify search
        // ============================
        await searchComponent(page, marker);
        const results = page.getByTestId('search-results');
        await expect(results.getByRole('row').filter({ hasText: marker })).toHaveCount(1);
        await expect(results.getByRole('link', { name: projectName, exact: true })).toHaveAttribute(
            'href',
            `/en/projects/${projectId}`,
        );

        // Sanity: the VEX step did not alter the vulnerability list.
        expect((await listVulns(request, projectId)).length).toBe(FIXTURE_CVES.length);
    });

    test('should handle SBOM version update workflow', async ({ page, request }) => {
        const project = await createProject(request, uniqueName('Version Update Test'), 'SBOM version update test');
        try {
            // Upload initial SBOM (version 1)
            await uploadSbom(request, project.id, {
                bomFormat: 'CycloneDX',
                specVersion: '1.4',
                version: 1,
                components: [
                    { type: 'library', name: 'lodash', version: '4.17.20', licenses: [{ license: { id: 'MIT' } }] },
                ],
            });

            await page.goto(`/en/projects/${project.id}`);
            await componentsTab(page).click();
            await expect(componentsTab(page)).toHaveText(`${en.Components.title} (1)`);
            await expect(componentRow(page, 'lodash')).toContainText('4.17.20');

            // Upload updated SBOM (version 2)
            await uploadSbom(request, project.id, {
                bomFormat: 'CycloneDX',
                specVersion: '1.4',
                version: 2,
                components: [
                    { type: 'library', name: 'lodash', version: '4.17.21', licenses: [{ license: { id: 'MIT' } }] },
                    { type: 'library', name: 'axios', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
                ],
            });

            await page.reload();
            await componentsTab(page).click();

            // The latest SBOM replaces the component view.
            await expect(componentsTab(page)).toHaveText(`${en.Components.title} (2)`);
            await expect(componentRow(page, 'lodash')).toHaveCount(1);
            await expect(componentRow(page, 'lodash')).toContainText('4.17.21');
            await expect(componentRow(page, 'axios')).toContainText('1.0.0');
            await expect(page.locator('tbody').getByText('4.17.20', { exact: true })).toHaveCount(0);
        } finally {
            await deleteProject(request, project.id);
        }
    });

    test('should handle multi-project comparison workflow', async ({ page, request }) => {
        const shared = `workflow-e2e-shared-${Date.now()}`;
        const project1 = await createProject(request, uniqueName('Compare Project 1'), 'First project');
        const project2 = await createProject(request, uniqueName('Compare Project 2'), 'Second project');
        try {
            await uploadSbom(request, project1.id, {
                bomFormat: 'CycloneDX',
                specVersion: '1.4',
                version: 1,
                components: [
                    { type: 'library', name: shared, version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
                    { type: 'library', name: 'express', version: '4.17.1', licenses: [{ license: { id: 'MIT' } }] },
                ],
            });
            await uploadSbom(request, project2.id, {
                bomFormat: 'CycloneDX',
                specVersion: '1.4',
                version: 1,
                components: [
                    { type: 'library', name: shared, version: '2.0.0', licenses: [{ license: { id: 'MIT' } }] },
                    { type: 'library', name: 'axios', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
                ],
            });

            // Both projects on the dashboard
            await page.goto('/en/dashboard');
            await expect(page.getByRole('link', { name: project1.name, exact: true }).first()).toBeVisible({
                timeout: 10000,
            });
            await expect(page.getByRole('link', { name: project2.name, exact: true }).first()).toBeVisible();

            // Search for the shared component: one row per project, each
            // with its own version.
            await searchComponent(page, shared);
            const results = page.getByTestId('search-results');
            await expect(results).toContainText(`Search results for "${shared}": 2 matches`);
            for (const [p, version] of [
                [project1, '1.0.0'],
                [project2, '2.0.0'],
            ] as const) {
                const row = results.getByRole('row').filter({
                    has: page.getByRole('link', { name: p.name, exact: true }),
                });
                await expect(row).toHaveCount(1);
                await expect(row.getByRole('cell').nth(2)).toHaveText(version);
                await expect(row.getByRole('link')).toHaveAttribute('href', `/en/projects/${p.id}`);
            }
        } finally {
            await deleteProject(request, project1.id);
            await deleteProject(request, project2.id);
        }
    });
});

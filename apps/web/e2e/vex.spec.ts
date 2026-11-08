import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import en from '../messages/en.json';
import {
    API_BASE_URL,
    FIXTURE_CVES,
    createProject,
    createVulnerableProject,
    deleteProject,
    uniqueName,
    type VulnerableProject,
} from './fixtures/vuln-project';

// Every test that needs vulnerabilities / statements creates its own
// project (createVulnerableProject: 4 fixture CVEs), so counts are exact
// and independent of test order and retries.

interface VexRow {
    id: string;
    vulnerability_cve_id: string;
    status: string;
    justification?: string;
    impact_statement?: string;
    action_statement?: string;
}

async function createVex(
    request: APIRequestContext,
    project: VulnerableProject,
    cveId: string,
    data: Record<string, string>,
): Promise<string> {
    const res = await request.post(`${API_BASE_URL}/api/v1/projects/${project.projectId}/vex`, {
        data: { vulnerability_id: project.vuln(cveId).id, ...data },
    });
    expect(res.status(), `VEX create for ${cveId}: ${await res.text()}`).toBe(201);
    return (await res.json()).id as string;
}

async function listVex(request: APIRequestContext, projectId: string): Promise<VexRow[]> {
    const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vex`);
    expect(res.status()).toBe(200);
    return ((await res.json()) ?? []) as VexRow[];
}

const vexTab = (page: Page, count: number) =>
    page.getByRole('button', { name: `VEX (${count})`, exact: true });

/** The "VEX Statements" card on the VEX tab. */
const vexPanel = (page: Page) =>
    page.locator('div.bg-card').filter({ has: page.getByRole('heading', { name: en.ProjectDetail.vexStatements }) });

/** One statement row in the VEX panel, keyed by CVE id. */
const vexRow = (page: Page, cveId: string) =>
    vexPanel(page).locator('div.border.rounded-lg').filter({ hasText: cveId });

/** Opens the VEXForm for `cveId` from its entry on the Vulnerabilities tab. */
async function openVexForm(page: Page, cveId: string) {
    await page
        .getByRole('button', { name: `${en.Vulnerabilities.title} (${FIXTURE_CVES.length})` })
        .click();
    await page
        .locator(`[data-vuln-cve-id="${cveId}"]`)
        .getByRole('button', { name: en.ProjectDetail.addVex, exact: true })
        .click();
    const form = page.locator('form').filter({
        has: page.getByRole('heading', { name: en.VexForm.createFor.replace('{cveId}', cveId) }),
    });
    await expect(form).toBeVisible();
    return form;
}

test.describe('VEX Statement Management', () => {
    // Plain project (no SBOM) shared by the read-only / route-mocked tests.
    let projectId: string;

    test.beforeAll(async ({ request }) => {
        projectId = (await createProject(request, uniqueName('VEX Test Project'))).id;
    });

    test.afterAll(async ({ request }) => {
        await deleteProject(request, projectId);
    });

    test('should display VEX tab in project detail', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}`);
        await expect(vexTab(page, 0)).toBeVisible({ timeout: 10000 });
    });

    test('should show the empty state for a project without statements', async ({ page, request }) => {
        expect(await listVex(request, projectId)).toEqual([]);

        await page.goto(`/en/projects/${projectId}`);
        await vexTab(page, 0).click();
        await expect(vexPanel(page)).toBeVisible();
        await expect(vexPanel(page).getByText(en.ProjectDetail.noVexStatements)).toBeVisible();
    });

    test.describe('with fixture vulnerabilities', () => {
        // Fresh project per test: these tests create / delete statements.
        let project: VulnerableProject;

        test.beforeEach(async ({ request }) => {
            project = await createVulnerableProject(request, 'VEX Statements Project');
        });

        test.afterEach(async ({ request }) => {
            await deleteProject(request, project?.projectId);
        });

        test('should show VEX statements list with count', async ({ page, request }) => {
            await createVex(request, project, 'CVE-2021-23337', {
                status: 'not_affected',
                justification: 'vulnerable_code_not_in_execute_path',
                impact_statement: 'Only the template helper is bundled.',
            });

            await page.goto(`/en/projects/${project.projectId}`);
            await vexTab(page, 1).click();

            const row = vexRow(page, 'CVE-2021-23337');
            await expect(row).toHaveCount(1);
            await expect(row).toContainText('not affected');
            await expect(row).toContainText('HIGH');
            await expect(row).toContainText(`${en.ProjectDetail.justification}: vulnerable code not in execute path`);
            await expect(row).toContainText(`${en.ProjectDetail.impact}: Only the template helper is bundled.`);
            await expect(vexPanel(page).locator('div.border.rounded-lg')).toHaveCount(1);
        });

        test('should create VEX statement via dialog', async ({ page, request }) => {
            const cveId = 'CVE-2021-44228';
            await page.goto(`/en/projects/${project.projectId}`);
            await expect(vexTab(page, 0)).toBeVisible({ timeout: 10000 });

            const form = await openVexForm(page, cveId);
            const selects = form.getByRole('combobox');
            // Justification is only asked for not_affected.
            await expect(selects).toHaveCount(1);
            await selects.first().selectOption('not_affected');
            await expect(selects).toHaveCount(2);
            await selects.nth(1).selectOption('component_not_present');
            await form.getByPlaceholder(en.VexForm.impactPlaceholder).fill('This component is not used in production.');
            await form.getByRole('button', { name: en.VexForm.createVexStatement }).click();

            await expect(form).toHaveCount(0);
            await expect(vexTab(page, 1)).toBeVisible();
            const row = vexRow(page, cveId);
            await expect(row).toContainText('not affected');
            await expect(row).toContainText(`${en.ProjectDetail.justification}: component not present`);
            await expect(row).toContainText('This component is not used in production.');

            const rows = await listVex(request, project.projectId);
            expect(rows).toHaveLength(1);
            expect(rows[0]).toMatchObject({
                vulnerability_cve_id: cveId,
                status: 'not_affected',
                justification: 'component_not_present',
                impact_statement: 'This component is not used in production.',
            });
        });

        test('should export VEX document', async ({ page, request }) => {
            await createVex(request, project, 'CVE-2021-44228', {
                status: 'affected',
                impact_statement: 'Exploitable via the logging endpoint.',
            });

            await page.goto(`/en/projects/${project.projectId}`);
            await vexTab(page, 1).click();

            const exportLink = vexPanel(page).getByRole('link', { name: en.ProjectDetail.exportVex });
            await expect(exportLink).toBeVisible();
            await expect(exportLink).toHaveAttribute('download', 'vex.json');
            const href = await exportLink.getAttribute('href');
            // Absolute URL on the build-time NEXT_PUBLIC_API_URL host.
            const exportPath = new URL(href!).pathname;
            expect(exportPath).toBe(`/api/v1/projects/${project.projectId}/vex/export`);

            // The link serves a CycloneDX VEX carrying the statement.
            const res = await request.get(`${API_BASE_URL}${exportPath}`);
            expect(res.status()).toBe(200);
            const doc = await res.json();
            expect(doc.bomFormat).toBe('CycloneDX');
            expect(doc.vulnerabilities).toEqual([
                expect.objectContaining({
                    id: 'CVE-2021-44228',
                    analysis: expect.objectContaining({
                        state: 'exploitable',
                        detail: 'Exploitable via the logging endpoint.',
                    }),
                }),
            ]);
        });

        test('should delete VEX statement and update count', async ({ page, request }) => {
            await createVex(request, project, 'CVE-2021-44228', { status: 'under_investigation' });
            await createVex(request, project, 'CVE-2020-8203', { status: 'fixed' });

            await page.goto(`/en/projects/${project.projectId}`);
            await vexTab(page, 2).click();

            const row = vexRow(page, 'CVE-2021-44228');
            await expect(row).toBeVisible();

            // Cancelling the native confirm keeps the statement.
            page.once('dialog', (dialog) => dialog.dismiss());
            await row.getByRole('button', { name: en.Common.delete, exact: true }).click();
            await expect(vexTab(page, 2)).toBeVisible();
            expect(await listVex(request, project.projectId)).toHaveLength(2);

            // Accepting it deletes exactly that statement.
            let confirmMessage: string | null = null;
            page.once('dialog', async (dialog) => {
                confirmMessage = `${dialog.type()}: ${dialog.message()}`;
                await dialog.accept();
            });
            await row.getByRole('button', { name: en.Common.delete, exact: true }).click();
            await expect.poll(() => confirmMessage).toBe(`confirm: ${en.ProjectDetail.deleteVexConfirm}`);

            await expect(vexTab(page, 1)).toBeVisible();
            await expect(row).toHaveCount(0);
            await expect(vexRow(page, 'CVE-2020-8203')).toBeVisible();
            const remaining = await listVex(request, project.projectId);
            expect(remaining.map((r) => r.vulnerability_cve_id)).toEqual(['CVE-2020-8203']);
        });

        test('should create VEX statement and verify in list', async ({ page, request }) => {
            // Second statement through the form: the default status
            // (under_investigation) needs no justification, and the count
            // goes from 1 to 2.
            await createVex(request, project, 'CVE-2021-23337', {
                status: 'not_affected',
                justification: 'component_not_present',
            });
            const cveId = 'CVE-2021-45046';

            await page.goto(`/en/projects/${project.projectId}`);
            await expect(vexTab(page, 1)).toBeVisible({ timeout: 10000 });

            const form = await openVexForm(page, cveId);
            await expect(form.getByRole('combobox')).toHaveCount(1);
            await expect(form.getByRole('combobox')).toHaveValue('under_investigation');
            await form.getByPlaceholder(en.VexForm.actionPlaceholder).fill('Upgrading to 2.17.1 next sprint.');
            await form.getByRole('button', { name: en.VexForm.createVexStatement }).click();

            await expect(vexTab(page, 2)).toBeVisible();
            await expect(vexRow(page, cveId)).toContainText('under investigation');
            await expect(vexRow(page, 'CVE-2021-23337')).toContainText('not affected');

            const created = (await listVex(request, project.projectId)).find((r) => r.vulnerability_cve_id === cveId);
            expect(created).toMatchObject({
                status: 'under_investigation',
                action_statement: 'Upgrading to 2.17.1 next sprint.',
            });
        });

        test('should display VEX status correctly for each statement', async ({ page, request }) => {
            const expected: Array<[string, string, string]> = [
                ['CVE-2021-44228', 'affected', 'affected'],
                ['CVE-2021-45046', 'fixed', 'fixed'],
                ['CVE-2021-23337', 'under_investigation', 'under investigation'],
                ['CVE-2020-8203', 'not_affected', 'not affected'],
            ];
            for (const [cveId, status] of expected) {
                await createVex(request, project, cveId, {
                    status,
                    ...(status === 'not_affected' ? { justification: 'component_not_present' } : {}),
                });
            }

            await page.goto(`/en/projects/${project.projectId}`);
            await vexTab(page, expected.length).click();

            for (const [cveId, , label] of expected) {
                const row = vexRow(page, cveId);
                await expect(row).toHaveCount(1);
                // The status badge is the element right after the CVE id.
                await expect(row.getByText(label, { exact: true })).toBeVisible();
            }
        });

        test('should render a real cross-project VEX suggestion (M26 F376)', async ({ page, request }) => {
            // Cross-project VEX suggestion aggregation (issue #131): a decision
            // made in another project of the tenant on the same vulnerability
            // surfaces on this project's triage page with its provenance.
            // `project` is the target; a second project is the source.
            const source = await createVulnerableProject(request, 'VEX Suggestion Source');
            try {
                const cveId = 'CVE-2020-8203';
                const statementId = await createVex(request, source, cveId, {
                    status: 'not_affected',
                    justification: 'vulnerable_code_not_present',
                    impact_statement: 'Suggestion source statement.',
                });

                // API: the suggestion for our CVE carries the source provenance.
                const res = await request.get(`${API_BASE_URL}/api/v1/projects/${project.projectId}/vex/suggestions`);
                expect(res.status()).toBe(200);
                const suggestions: Array<{ cve_id: string; source: { statement_id: string; project_name: string } }> =
                    (await res.json()).suggestions;
                const ours = suggestions.filter((s) => s.source.statement_id === statementId);
                expect(ours).toHaveLength(1);
                expect(ours[0].cve_id).toBe(cveId);
                expect(ours[0].source.project_name).toBe(source.projectName);

                // UI: the card from our source project. (Other projects of the
                // tenant may contribute more cards; scope to ours.)
                await page.goto(`/en/projects/${project.projectId}/triage`);
                await expect(page.getByTestId('triage-page')).toBeVisible({ timeout: 10000 });
                await expect(page.getByTestId('cross-project-suggestions')).toBeVisible();
                const card = page
                    .locator(`[data-testid="cross-project-suggestion-card"][data-cve-id="${cveId}"]`)
                    .filter({ hasText: source.projectName });
                await expect(card).toHaveCount(1);
                await expect(card).toHaveAttribute('data-match-type', /^(purl|vulnerability_only)$/);
                await expect(card).toContainText('Not affected');
                await expect(card).toContainText('vulnerable code not present');
                await expect(card).toContainText('Suggestion source statement.');
            } finally {
                await deleteProject(request, source.projectId);
            }
        });
    });

    test('should render no cross-project suggestions section for a project without vulnerabilities', async ({ page, request }) => {
        // Empty-state companion: nothing can match a project with no
        // vulnerabilities, so the API returns [] and the section (which
        // renders null when empty) is absent while the page still renders.
        const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vex/suggestions`);
        expect(res.status()).toBe(200);
        expect((await res.json()).suggestions).toEqual([]);

        await page.goto(`/en/projects/${projectId}/triage`);
        await expect(page.getByTestId('triage-page')).toBeVisible({ timeout: 10000 });
        await expect(page.getByText(en.Triage.Page.emptyTitle, { exact: true })).toBeVisible();
        await expect(page.getByTestId('cross-project-suggestions')).toHaveCount(0);
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

    test('should reuse a cross-project decision via confirm dialog (M27 F382)', async ({ page }) => {
        // Phase 2 of cross-project VEX (issue #133): the reviewer reuses a
        // suggestion, copying the source decision into this project. "AI drafts,
        // humans approve" — the single click only OPENS a confirm dialog; the
        // POST /vex/suggestions/apply fires only on confirmation. The web-e2e
        // seed never provisions cross-project data, so intercept both endpoints:
        // the GET returns the suggestion until it is applied, then empty (the
        // backend excludes an already-triaged finding), and the POST returns the
        // 201 apply envelope. The real apply semantics (match re-validation,
        // tenant isolation, provenance, audit, 409 idempotency) stay in the
        // Wave A real-PG integration tests; this pins only the web reuse flow:
        // confirm-gated apply → refetch → suggestion drops out.
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

        let applied = false;

        // POST apply — records applied=true so the subsequent suggestions
        // refetch returns empty, and returns the 201 contract envelope.
        await page.route('**/api/v1/projects/*/vex/suggestions/apply', route => {
            applied = true;
            route.fulfill({
                status: 201,
                contentType: 'application/json',
                body: JSON.stringify({
                    statement: {
                        id: '55555555-5555-4555-8555-555555555555',
                        project_id: '66666666-6666-4666-8666-666666666666',
                        vulnerability_id: suggestion.vulnerability_id,
                        component_id: suggestion.component.component_id,
                        status: 'not_affected',
                        created_by: 'tester',
                        created_at: '2026-07-04T00:00:00Z',
                        updated_at: '2026-07-04T00:00:00Z',
                    },
                    provenance: {
                        source_statement_id: suggestion.source.statement_id,
                        source_project_id: suggestion.source.project_id,
                        applied_at: '2026-07-04T00:00:00Z',
                    },
                }),
            });
        });

        // GET suggestions — the apply glob above is registered first so this
        // narrower glob (no trailing /apply) never shadows it; the two paths
        // are disjoint regardless.
        await page.route('**/api/v1/projects/*/vex/suggestions', route =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ suggestions: applied ? [] : [suggestion] }),
            })
        );

        await page.goto(`/en/projects/${projectId}/triage`);
        await page.waitForLoadState('networkidle');

        await expect(page.getByTestId('triage-page')).toBeVisible({ timeout: 10000 });
        const section = page.getByTestId('cross-project-suggestions');
        await expect(section).toBeVisible();
        const card = page.getByTestId('cross-project-suggestion-card').first();
        await expect(card).toBeVisible();

        // Single click opens the confirm dialog — it must NOT apply yet
        // (humans approve). The suggestion is still present behind the dialog.
        await card.getByTestId('cross-project-apply-button').click();
        const dialog = page.getByRole('dialog');
        await expect(dialog).toBeVisible();
        await expect(dialog).toContainText('Reuse this decision?');
        // Confirm copy renders the source provenance (interpolated project + status).
        await expect(dialog).toContainText('Mock Source Project');
        await expect(dialog).toContainText('Not affected');
        // Not applied on open — the section is still there.
        await expect(section).toBeVisible();

        // Confirm → POST apply → onApplied refetch → suggestion drops out.
        await dialog.getByRole('button', { name: 'Reuse decision' }).click();
        await expect(page.getByTestId('cross-project-suggestions')).toHaveCount(0);
        expect(applied).toBe(true);
    });

    test('should keep row A disabled while row B apply starts (per-row loading, M27 F387)', async ({ page }) => {
        // F387 (issue #133): apply loading state must be per-row. With a single
        // applyingKey, starting an apply on row B overwrote row A's in-flight
        // key, re-enabling A's button mid-flight so it could be re-triggered —
        // a duplicate apply POST (the backend 409s, but the UI contract was
        // wrong). This pins the fixed contract: with two suggestions, once A's
        // apply is in-flight A stays disabled even after B's apply also starts.
        //
        // Both apply POSTs are held behind a gate the test releases at the end,
        // so both rows are observably in-flight at the same time — the exact
        // concurrency the single-key bug mishandled.
        const mk = (n: string) => ({
            vulnerability_id: `${n}${n}${n}${n}${n}${n}${n}${n}-1111-4111-8111-111111111111`,
            cve_id: `CVE-2026-0${n.toUpperCase()}01`,
            component: {
                component_id: `${n}${n}${n}${n}${n}${n}${n}${n}-2222-4222-8222-222222222222`,
                name: 'libmock',
                version: '1.0.0',
                purl: `pkg:npm/lib${n}@1.0.0`,
            },
            match_type: 'purl',
            source: {
                project_id: '33333333-3333-4333-8333-333333333333',
                project_name: 'Mock Source Project',
                statement_id: `${n}${n}${n}${n}${n}${n}${n}${n}-4444-4444-8444-444444444444`,
                status: 'not_affected',
                created_at: '2026-07-01T00:00:00Z',
            },
        });
        const rowA = mk('a');
        const rowB = mk('b');

        // Hold every apply POST until the test releases the gate, so both rows
        // are simultaneously in-flight when we assert.
        let releaseApplies!: () => void;
        const appliesGate = new Promise<void>((resolve) => {
            releaseApplies = resolve;
        });
        await page.route('**/api/v1/projects/*/vex/suggestions/apply', async (route) => {
            await appliesGate;
            await route.fulfill({
                status: 201,
                contentType: 'application/json',
                body: JSON.stringify({
                    statement: {
                        id: '55555555-5555-4555-8555-555555555555',
                        project_id: '66666666-6666-4666-8666-666666666666',
                        vulnerability_id: rowA.vulnerability_id,
                        component_id: rowA.component.component_id,
                        status: 'not_affected',
                        created_by: 'tester',
                        created_at: '2026-07-04T00:00:00Z',
                        updated_at: '2026-07-04T00:00:00Z',
                    },
                    provenance: {
                        source_statement_id: rowA.source.statement_id,
                        source_project_id: rowA.source.project_id,
                        applied_at: '2026-07-04T00:00:00Z',
                    },
                }),
            });
        });

        // GET suggestions stays [A, B] for the whole test (registered after the
        // /apply glob; the two paths are disjoint regardless).
        await page.route('**/api/v1/projects/*/vex/suggestions', (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ suggestions: [rowA, rowB] }),
            })
        );

        await page.goto(`/en/projects/${projectId}/triage`);
        await page.waitForLoadState('networkidle');

        await expect(page.getByTestId('triage-page')).toBeVisible({ timeout: 10000 });
        await expect(page.getByTestId('cross-project-suggestions')).toBeVisible();

        const cardA = page.locator('[data-testid="cross-project-suggestion-card"][data-cve-id="CVE-2026-0A01"]');
        const cardB = page.locator('[data-testid="cross-project-suggestion-card"][data-cve-id="CVE-2026-0B01"]');
        await expect(cardA).toBeVisible();
        await expect(cardB).toBeVisible();

        const buttonA = cardA.getByTestId('cross-project-apply-button');
        const buttonB = cardB.getByTestId('cross-project-apply-button');

        // Start row A's apply (confirm-gated). Its POST is now held in-flight.
        await buttonA.click();
        await page.getByRole('dialog').getByRole('button', { name: 'Reuse decision' }).click();
        await expect(buttonA).toBeDisabled();
        // Row B is independent — still actionable.
        await expect(buttonB).toBeEnabled();

        // Start row B's apply while A is still in-flight.
        await buttonB.click();
        await page.getByRole('dialog').getByRole('button', { name: 'Reuse decision' }).click();

        // The F387 contract: A must STILL be disabled (a single-key impl would
        // have re-enabled it when B started), and B is disabled too.
        await expect(buttonA).toBeDisabled();
        await expect(buttonB).toBeDisabled();

        // Release both held applies so the page settles cleanly.
        releaseApplies();
    });
});

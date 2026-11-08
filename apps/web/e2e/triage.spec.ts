/**
 * AI VEX triage page (issue #28, M1 Wave M1-6).
 *
 * These tests exercise the /projects/:id/triage page end-to-end against
 * data they create themselves through the real API:
 *
 *   - The CI stack has no LLM configured (SBOMHUB_LLM_PROVIDER unset). With
 *     BYOK unset the LLM factory returns *llm.DisabledProvider as a VALUE
 *     (service/llm/factory.go) and POST /projects/:id/triage/run forks
 *     in-band (triage/runner.go runAIDisabled): it answers 201 and persists
 *     a pending `under_investigation` draft carrying one `ai_disabled`
 *     evidence row. That IS the product contract for "BYOK unset", and it
 *     gives us real vex_drafts rows without an LLM — so the approve flow is
 *     driven on drafts this spec created, never on the shared seed project.
 *   - The run endpoint needs a vulnerability that belongs to the project,
 *     which createVulnerableProject provides (fixture CVEs, see
 *     fixtures/vuln-project.ts).
 *   - The AIDisabledBanner is mounted only when a page call fails with
 *     503 + an "AI ... disabled" body (APIError.isAIDisabled). No endpoint
 *     of this backend produces that any more (see above), so the banner's
 *     render contract is pinned by intercepting the list call with that
 *     exact error shape; the real in-band BYOK-unset behaviour is pinned
 *     separately against the live backend.
 */

import { test, expect, type APIRequestContext } from '@playwright/test';
import en from '../messages/en.json';
import {
    API_BASE_URL,
    createProject,
    createVulnerableProject,
    deleteProject,
    uniqueName,
    type VulnerableProject,
} from './fixtures/vuln-project';

const AI_DISABLED_DETAIL = 'AI triage skipped: SBOMHUB_LLM_PROVIDER is not set (BYOK required)';

interface VexDraft {
    ID: string;
    CVEID: string;
    State: string;
    Decision: string;
    Provider: string;
    Evidence: Array<{ kind: string; description?: string }>;
}

/** Runs triage for one fixture CVE; with BYOK unset this yields one ai_disabled draft. */
async function runTriage(request: APIRequestContext, project: VulnerableProject, cveId: string): Promise<VexDraft> {
    const res = await request.post(`${API_BASE_URL}/api/v1/projects/${project.projectId}/triage/run`, {
        data: { cve_id: cveId, vulnerability_id: project.vuln(cveId).id },
    });
    expect(res.status(), `triage/run for ${cveId}: ${await res.text()}`).toBe(201);
    const body = await res.json();
    return body.draft as VexDraft;
}

async function listPendingDrafts(request: APIRequestContext, projectId: string): Promise<VexDraft[]> {
    const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vex-drafts?decision=pending`);
    expect(res.status()).toBe(200);
    return ((await res.json()).drafts ?? []) as VexDraft[];
}

test.describe('AI VEX Triage (M1-6)', () => {
    test.describe('empty project', () => {
        let projectId: string | null = null;

        test.beforeAll(async ({ request }) => {
            projectId = (await createProject(request, uniqueName('Triage Empty Project'))).id;
        });

        test.afterAll(async ({ request }) => {
            await deleteProject(request, projectId);
        });

        test('should render the triage page shell', async ({ page }) => {
            await page.goto(`/en/projects/${projectId}/triage`);

            await expect(page.getByTestId('triage-page')).toBeVisible({ timeout: 10000 });
            await expect(page.getByRole('heading', { name: en.Triage.Page.title })).toBeVisible();
            await expect(page.getByTestId('triage-refresh')).toBeVisible();
            await expect(page.getByTestId('triage-refresh')).toBeEnabled();
        });

        test('should show empty state when no AI drafts exist', async ({ page, request }) => {
            // A project created by this spec has no drafts — assert that, then the UI.
            expect(await listPendingDrafts(request, projectId!)).toEqual([]);

            await page.goto(`/en/projects/${projectId}/triage`);
            await expect(page.getByText(en.Triage.Page.emptyTitle, { exact: true })).toBeVisible({ timeout: 10000 });
            await expect(page.getByText(en.Triage.Page.emptyDescription)).toBeVisible();
            await expect(page.getByTestId('triage-draft-card')).toHaveCount(0);
        });

        test('should surface the AI-disabled banner when the backend reports BYOK unset', async ({ page }) => {
            // Render contract of AIDisabledBanner: a 503 whose body names the
            // disabled AI provider (the shape APIError.isAIDisabled matches)
            // mounts the banner with the backend reason and a settings link.
            const reason = 'SBOMHUB_LLM_PROVIDER is not set';
            await page.route(/\/api\/v1\/projects\/[^/]+\/vex-drafts(\?|$)/, (route) =>
                route.fulfill({
                    status: 503,
                    contentType: 'application/json',
                    body: JSON.stringify({ error: 'AI features are disabled', reason }),
                })
            );

            await page.goto(`/en/projects/${projectId}/triage`);
            await expect(page.getByTestId('triage-page')).toBeVisible({ timeout: 10000 });

            const banner = page.getByRole('alert').filter({ hasText: en.Triage.AIDisabledBanner.title });
            await expect(banner).toBeVisible();
            await expect(banner).toContainText(en.Triage.AIDisabledBanner.description);
            await expect(banner).toContainText(`${en.Triage.AIDisabledBanner.reasonLabel}: ${reason}`);
            await expect(banner.getByRole('link', { name: en.Triage.AIDisabledBanner.ctaLabel })).toHaveAttribute(
                'href',
                '/en/settings/llm'
            );
            // The disabled state is not reported as a generic load failure.
            await expect(page.getByTestId('triage-flash-errors')).toHaveCount(0);
        });
    });

    test.describe('with drafts from the BYOK-unset runner', () => {
        let project: VulnerableProject;

        test.beforeAll(async ({ request }) => {
            project = await createVulnerableProject(request, 'Triage Test Project');
        });

        test.afterAll(async ({ request }) => {
            await deleteProject(request, project?.projectId);
        });

        test('should persist an ai_disabled draft in-band and render it without the banner', async ({ page, request }) => {
            const cveId = 'CVE-2021-45046';
            const draft = await runTriage(request, project, cveId);
            // In-band BYOK-unset contract: a pending under_investigation draft
            // with ai_disabled evidence, never a confident AI verdict.
            expect(draft.CVEID).toBe(cveId);
            expect(draft.State).toBe('under_investigation');
            expect(draft.Decision).toBe('pending');
            expect(draft.Provider).toBe('disabled');
            expect(draft.Evidence.map((e) => e.kind)).toEqual(['ai_disabled']);

            await page.goto(`/en/projects/${project.projectId}/triage`);
            const card = page.locator(`[data-testid="triage-draft-card"][data-cve-id="${cveId}"]`);
            await expect(card).toBeVisible({ timeout: 10000 });
            await expect(card).toHaveAttribute('data-decision', 'pending');
            await expect(card).toContainText(en.Triage.State.under_investigation);
            await expect(card).toContainText(AI_DISABLED_DETAIL);
            await expect(card.getByTestId('triage-evidence-list')).toContainText('ai_disabled');
            await expect(card.getByTestId('triage-approve')).toBeEnabled();
            // The in-band path does not raise the AI-disabled banner.
            await expect(page.getByRole('alert').filter({ hasText: en.Triage.AIDisabledBanner.title })).toHaveCount(0);
        });

        test('should approve a draft and move it out of the pending queue', async ({ page, request }) => {
            // Acceptance criterion: triage 1 件を approve → 確定 VEX 一覧に出ること.
            const cveId = 'CVE-2021-44228';
            const draft = await runTriage(request, project, cveId);

            const vexBefore = await request.get(`${API_BASE_URL}/api/v1/projects/${project.projectId}/vex`);
            expect(vexBefore.status()).toBe(200);
            const vexCvesBefore = ((await vexBefore.json()) ?? []).map((v: { vulnerability_cve_id: string }) => v.vulnerability_cve_id);
            expect(vexCvesBefore).not.toContain(cveId);

            await page.goto(`/en/projects/${project.projectId}/triage`);
            const card = page.locator(`[data-testid="triage-draft-card"][data-cve-id="${cveId}"]`);
            await expect(card).toBeVisible({ timeout: 10000 });

            await card.getByTestId('triage-approve').click();

            // Optimistic removal, kept after the refetch of the pending list.
            await expect(card).toHaveCount(0);

            // Persisted decision.
            await expect
                .poll(async () => {
                    const res = await request.get(
                        `${API_BASE_URL}/api/v1/projects/${project.projectId}/vex-drafts/${draft.ID}`
                    );
                    return res.ok() ? (await res.json()).Decision : `HTTP ${res.status()}`;
                })
                .toBe('approved');
            expect((await listPendingDrafts(request, project.projectId)).map((d) => d.ID)).not.toContain(draft.ID);

            // The approved draft is mirrored into the confirmed VEX list.
            await expect
                .poll(async () => {
                    const res = await request.get(`${API_BASE_URL}/api/v1/projects/${project.projectId}/vex`);
                    const rows: Array<{ vulnerability_cve_id: string; status: string }> = (await res.json()) ?? [];
                    return rows.filter((r) => r.vulnerability_cve_id === cveId).map((r) => r.status);
                })
                .toEqual(['under_investigation']);
        });
    });
});

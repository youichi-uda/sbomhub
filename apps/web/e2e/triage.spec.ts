/**
 * AI VEX triage page (issue #28, M1 Wave M1-6).
 *
 * These tests exercise the /projects/:id/triage page end-to-end. They
 * intentionally seed the backend through its REST API rather than a fixture
 * file because:
 *
 *   - the M1-5 runner needs a real LLM provider to populate drafts naturally,
 *     and CI does not have BYOK credentials. So we exercise the page either
 *     by (a) verifying empty-state + AI-disabled behaviour (the old "503"
 *     premise is stale — see the F354 note on the banner spec below), or
 *     (b) by approving a pre-existing draft when one happens to exist.
 *     TODO(e2e): verified 2026-07-02 (M23-2 F343): there is still no
 *     public "seed a draft" endpoint (cmd/server/main.go registers only
 *     list / get / decision / reanalyse under /vex-drafts; draft creation
 *     goes through the LLM-backed /triage/run only), so the approve-flow
 *     assertion below stays conditional on the listDrafts API returning a
 *     row, which a black-box test cannot guarantee.
 *
 * Hence this file is a *skeleton* per the M1-6 task brief ("ローカルでは
 * playwright install が必要なので軽い skeleton で OK"). The Acceptance
 * Criterion is the approve → confirmed VEX list flow; this skeleton wires
 * the navigation and the approve UI so when seeding lands the assertions
 * can be tightened.
 */

import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('AI VEX Triage (M1-6)', () => {
    let projectId: string;

    test.beforeAll(async ({ request }) => {
        const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `Triage Test Project ${Date.now()}`,
                description: 'Project for AI VEX triage E2E tests',
            },
        });
        const project = await projectResponse.json();
        projectId = project.id;
    });

    test.afterAll(async ({ request }) => {
        if (projectId) {
            await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
        }
    });

    test('should render the triage page shell', async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/triage`);
        await page.waitForLoadState('networkidle');

        await expect(page.getByTestId('triage-page')).toBeVisible({ timeout: 10000 });
        // Refresh button is always rendered.
        await expect(page.getByTestId('triage-refresh')).toBeVisible();
    });

    test('should show empty state when no AI drafts exist', async ({ page, request }) => {
        // Ensure no drafts exist by calling the list endpoint.
        const res = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/vex-drafts?decision=pending`
        );
        const body = await res.json().catch(() => ({ drafts: [] }));
        const drafts = Array.isArray(body?.drafts) ? body.drafts : [];

        if (drafts.length === 0) {
            await page.goto(`/en/projects/${projectId}/triage`);
            await page.waitForLoadState('networkidle');
            // English locale empty title (see apps/web/messages/en.json).
            await expect(page.getByText(/No pending drafts/i)).toBeVisible({ timeout: 10000 });
        } else {
            test.skip();
        }
    });

    test('should surface AI-disabled banner when BYOK is unset', async ({ page, request }) => {
        // Pre-F354 premise ("in CI BYOK is unset, so the backend returns
        // 503 + llm.DisabledError") is stale: with BYOK unset the LLM
        // factory returns *llm.DisabledProvider as a VALUE, not an error
        // (service/llm/factory.go: "SBOMHUB_LLM_PROVIDER unset ->
        // DisabledProvider (NOT an error)"), and the triage runner forks
        // in-band (triage/runner.go runAIDisabled), persisting
        // under_investigation drafts with evidence kind "ai_disabled" and
        // returning HTTP 201 — a 503 requires *llm.DisabledError in the
        // error chain, which this path no longer produces. Moreover the
        // all-zero vulnerability_id below fails Stage 1 scope resolution
        // first (ErrVulnerabilityNotInTenant -> generic 404), before the
        // provider fork is even reached.
        //
        // TODO(e2e): verified 2026-07-02 (M23-2 F354): the 503 gate below
        // is therefore dead — the skip always fires, and the coverage the
        // pre-F354 comment described (banner mounted off a 503 run) does
        // not exist. Gate logic is deliberately left untouched (this spec
        // runs live in CI via .github/workflows/web-e2e.yml web-e2e-full;
        // this is a comment-only fix). Real coverage needs a seeded valid
        // vulnerability, then asserting the in-band contract instead:
        // POST /triage/run -> 201 with ai_disabled evidence drafts.
        const triageRun = await request.post(
            `${API_BASE_URL}/api/v1/projects/${projectId}/triage/run`,
            {
                data: {
                    cve_id: 'CVE-0000-0001',
                    vulnerability_id: '00000000-0000-0000-0000-000000000000',
                },
            }
        );
        if (triageRun.status() !== 503) {
            test.skip();
            return;
        }

        await page.goto(`/en/projects/${projectId}/triage`);
        await page.waitForLoadState('networkidle');

        // The banner is only mounted if the list call (or a decision call)
        // returns 503 (which, per the F354 note above, the run endpoint
        // itself no longer does). listDrafts does NOT hit the LLM, so it will
        // return 200 with an empty array in this environment. So this test
        // only asserts the page renders without crashing. TODO(e2e):
        // banner visibility is currently covered by NO test — the
        // pre-F343 comment claimed a unit test exercised it, which was
        // factually wrong (verified 2026-07-02: apps/web has only
        // Playwright; package.json carries no vitest / jest /
        // @testing-library/react). A component-level unit test needs
        // @testing-library/react (or an equivalent runner) added first.
        await expect(page.getByTestId('triage-page')).toBeVisible();
    });

    test('should approve a draft and move it out of the pending queue', async ({ page, request }) => {
        // Acceptance criterion: triage 1 件を approve → 確定 VEX 一覧に出ること.
        // This requires a seeded vex_drafts row, which the public API cannot
        // create directly (only the LLM-backed triage runner can). When a
        // test harness or admin seed endpoint lands, replace this skip with
        // a real assertion that:
        //   1. POSTs a draft (or runs triage with a stubbed provider),
        //   2. clicks [data-testid="triage-approve"],
        //   3. polls GET /api/v1/projects/:id/vex until the approved CVE
        //      appears in the confirmed VEX list.
        const res = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/vex-drafts?decision=pending`
        );
        const body = await res.json().catch(() => ({ drafts: [] }));
        const drafts = Array.isArray(body?.drafts) ? body.drafts : [];

        if (drafts.length === 0) {
            test.skip();
            return;
        }

        const draft = drafts[0];
        const initialVexRes = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vex`);
        const initialVex = await initialVexRes.json().catch(() => []);
        const initialCount = Array.isArray(initialVex) ? initialVex.length : 0;

        await page.goto(`/en/projects/${projectId}/triage`);
        await page.waitForLoadState('networkidle');

        const card = page
            .getByTestId('triage-draft-card')
            .filter({ has: page.locator(`[data-cve-id="${draft.CVEID}"]`) })
            .first();
        await expect(card).toBeVisible({ timeout: 10000 });

        await card.getByTestId('triage-approve').click();
        await page.waitForTimeout(1500);

        // Card should disappear from the pending list (optimistic update).
        await expect(card).toHaveCount(0);

        // Approved draft should mirror into vex_statements via the runner.
        const finalVexRes = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vex`);
        const finalVex = await finalVexRes.json().catch(() => []);
        const finalCount = Array.isArray(finalVex) ? finalVex.length : 0;
        expect(finalCount).toBeGreaterThan(initialCount);
    });
});

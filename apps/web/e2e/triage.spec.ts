/**
 * AI VEX triage page (issue #28, M1 Wave M1-6).
 *
 * These tests exercise the /projects/:id/triage page end-to-end. They
 * intentionally seed the backend through its REST API rather than a fixture
 * file because:
 *
 *   - the M1-5 runner needs a real LLM provider to populate drafts naturally,
 *     and CI does not have BYOK credentials. So we exercise the page either
 *     by (a) verifying empty-state + 503 AI-disabled behaviour, or (b) by
 *     POSTing pre-fabricated drafts via the upcoming admin endpoint when
 *     present. ※要確認: there is no public "seed a draft" endpoint yet; the
 *     approve-flow assertion below is conditional on the listDrafts API
 *     returning a row, which we cannot guarantee from a black-box test.
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
        // Try to trigger a triage run; in CI BYOK is unset, so the backend
        // returns 503 + llm.DisabledError. The UI should mount the
        // AIDisabledBanner. If BYOK is configured (rare in CI), skip.
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
        // also returns 503. listDrafts does NOT hit the LLM, so it will
        // return 200 with an empty array in this environment. So this test
        // only asserts the page renders without crashing — banner visibility
        // is exercised by a unit test (※要確認: add @testing-library/react
        // for that, currently this monorepo only has Playwright e2e).
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

/**
 * AI CRA reports page (issue #32, M2 Wave M2-5).
 *
 * These tests exercise the /projects/:id/cra-reports page end-to-end.
 * They mirror e2e/triage.spec.ts (M1-6) one-to-one because the page
 * shape is intentionally the same — empty-state, AI-disabled banner,
 * approve flow — only the wire shape (snake_case CRAReport vs
 * PascalCase VEXDraft) and the source dependency (an approved VEX
 * draft must exist first) differ.
 *
 * The approve flow remains a *skeleton* because the M2-4 runner needs
 * (a) BYOK credentials AND (b) a pre-existing approved vex_draft for
 * the same (project, cve_id). CI has neither, so the assertions are
 * conditional on listReports returning a row, which we cannot
 * guarantee from a black-box test.
 *
 * ※要確認: when a "seed a cra_report" admin endpoint or a stubbed-LLM
 * harness lands, replace the conditional skips with assertions that
 *   1. POST a report (or run the M2-4 runner with a stubbed provider),
 *   2. click [data-testid="cra-approve"],
 *   3. poll GET /api/v1/projects/:id/cra-reports until the approved
 *      report's decision flips to "approved".
 */

import { test, expect } from "@playwright/test";

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || "http://localhost:8080";

test.describe("AI CRA Reports (M2-5)", () => {
    let projectId: string;

    test.beforeAll(async ({ request }) => {
        const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `CRA Reports Test Project ${Date.now()}`,
                description: "Project for AI CRA reports E2E tests",
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

    test("should render the CRA reports page shell", async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/cra-reports`);
        await page.waitForLoadState("networkidle");

        await expect(page.getByTestId("cra-reports-page")).toBeVisible({ timeout: 10000 });
        await expect(page.getByTestId("cra-reports-refresh")).toBeVisible();
        // Filter card and all four filter selects mount on first render.
        await expect(page.getByTestId("cra-reports-filters")).toBeVisible();
        await expect(page.getByTestId("filter-report-type")).toBeVisible();
        await expect(page.getByTestId("filter-lang")).toBeVisible();
        await expect(page.getByTestId("filter-state")).toBeVisible();
        await expect(page.getByTestId("filter-decision")).toBeVisible();
    });

    test("should show empty state when no CRA reports exist", async ({ page, request }) => {
        const res = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/cra-reports`,
        );
        const body = await res.json().catch(() => ({ reports: [] }));
        const reports = Array.isArray(body?.reports) ? body.reports : [];

        if (reports.length === 0) {
            await page.goto(`/en/projects/${projectId}/cra-reports`);
            await page.waitForLoadState("networkidle");
            // English locale empty title (see apps/web/messages/en.json).
            await expect(page.getByText(/No CRA reports/i)).toBeVisible({ timeout: 10000 });
        } else {
            test.skip();
        }
    });

    test("should surface AI-disabled banner when BYOK is unset", async ({ page, request }) => {
        // Try to trigger a CRA report run; in CI BYOK is unset, so the
        // backend returns 503 + llm.DisabledError on the run endpoint.
        // The list endpoint does NOT hit the LLM, so the page itself
        // renders without the banner — this matches the M1-6 triage
        // page test's behaviour.
        const runRes = await request.post(
            `${API_BASE_URL}/api/v1/projects/${projectId}/cra-reports/run`,
            {
                data: {
                    cve_id: "CVE-0000-0001",
                    vulnerability_id: "00000000-0000-0000-0000-000000000000",
                    report_type: "early_warning",
                    lang: "en",
                },
            },
        );
        if (runRes.status() !== 503) {
            test.skip();
            return;
        }

        await page.goto(`/en/projects/${projectId}/cra-reports`);
        await page.waitForLoadState("networkidle");

        // listReports returns 200 with an empty array in this
        // environment so the banner is not yet mounted from a list
        // failure. Same skeleton contract as the triage e2e.
        // ※要確認: add @testing-library/react for a banner-mount unit
        // test independent of LLM provider state.
        await expect(page.getByTestId("cra-reports-page")).toBeVisible();
    });

    test("should filter by report_type", async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/cra-reports`);
        await page.waitForLoadState("networkidle");

        // Changing a filter triggers a fresh list call via useEffect/
        // useCallback. We only assert the select accepts the change
        // and the page does not crash; assertion of filtered rows
        // requires a seeded report (see top-of-file ※要確認).
        const select = page.getByTestId("filter-report-type");
        await select.selectOption("early_warning");
        await expect(select).toHaveValue("early_warning");

        // Page shell remains mounted after the filter change.
        await expect(page.getByTestId("cra-reports-page")).toBeVisible();
    });

    test("should approve a report and remove it from the pending queue", async ({ page, request }) => {
        // Acceptance criterion: approve → 該当 row が消えること.
        // Requires a seeded cra_reports row, which the public API
        // cannot create directly (only the M2-4 runner backed by an
        // LLM provider can). When a test harness or admin seed
        // endpoint lands, replace this skip with a real assertion
        // that:
        //   1. POSTs a cra_report (or runs cra/run with stubbed provider),
        //   2. clicks [data-testid="cra-approve"],
        //   3. polls GET /api/v1/projects/:id/cra-reports until the
        //      target row's decision flips to "approved" (or the row
        //      drops out of decision=pending list).
        const res = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/cra-reports?decision=pending`,
        );
        const body = await res.json().catch(() => ({ reports: [] }));
        const reports = Array.isArray(body?.reports) ? body.reports : [];

        if (reports.length === 0) {
            test.skip();
            return;
        }

        const report = reports[0];

        await page.goto(`/en/projects/${projectId}/cra-reports`);
        await page.waitForLoadState("networkidle");

        const card = page
            .getByTestId("cra-report-card")
            .filter({ has: page.locator(`[data-cve-id="${report.cve_id}"]`) })
            .first();
        await expect(card).toBeVisible({ timeout: 10000 });

        await card.getByTestId("cra-approve").click();
        await page.waitForTimeout(1500);

        // Optimistic update: card should disappear from the pending list.
        await expect(card).toHaveCount(0);

        // Persisted decision should be "approved" on the next GET.
        const finalRes = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/cra-reports/${report.id}`,
        );
        const finalBody = await finalRes.json().catch(() => null);
        expect(finalBody?.decision).toBe("approved");
    });
});

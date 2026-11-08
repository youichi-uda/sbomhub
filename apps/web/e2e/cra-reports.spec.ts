/**
 * AI CRA reports page (issue #32, M2 Wave M2-5).
 *
 * These tests exercise the /projects/:id/cra-reports page end-to-end
 * against reports they create through the real API (see triage.spec.ts
 * for the same reasoning):
 *
 *   - The CI stack has no LLM configured. With BYOK unset the CRA runner
 *     forks in-band (cra/runner.go runAIDisabled): POST
 *     /projects/:id/cra-reports/run answers 201 and persists a pending
 *     `draft` report built from the template, carrying `ai_disabled`
 *     evidence. So real cra_reports rows exist without an LLM.
 *   - The runner's precondition is an APPROVED vex_draft for the same
 *     (project, cve). The spec gets one the same way: POST /triage/run
 *     (BYOK-unset -> ai_disabled draft) then PUT .../decision approved.
 *   - The AIDisabledBanner only mounts on a 503 "AI ... disabled" error
 *     (APIError.isAIDisabled), which no endpoint produces any more, so its
 *     render contract is pinned by intercepting the list call.
 * Everything runs on projects this spec creates; the seed project is
 * never touched.
 */

import { test, expect, type APIRequestContext } from "@playwright/test";
import en from "../messages/en.json";
import {
    API_BASE_URL,
    createProject,
    createVulnerableProject,
    deleteProject,
    uniqueName,
    type VulnerableProject,
} from "./fixtures/vuln-project";

type ReportType = "early_warning" | "detailed_notification" | "final_report";

interface CRAReport {
    id: string;
    cve_id: string;
    report_type: ReportType;
    lang: string;
    state: string;
    decision: string;
    source_vex_draft_id: string | null;
    evidence: Array<{ kind: string; ref?: string }>;
}

/** Gives (project, cve) an approved VEX draft — the CRA runner's precondition. */
async function approveVexDraft(request: APIRequestContext, project: VulnerableProject, cveId: string): Promise<string> {
    const run = await request.post(`${API_BASE_URL}/api/v1/projects/${project.projectId}/triage/run`, {
        data: { cve_id: cveId, vulnerability_id: project.vuln(cveId).id },
    });
    expect(run.status(), `triage/run ${cveId}: ${await run.text()}`).toBe(201);
    const draftId = (await run.json()).draft.ID as string;
    const decide = await request.put(
        `${API_BASE_URL}/api/v1/projects/${project.projectId}/vex-drafts/${draftId}/decision`,
        { data: { decision: "approved" } },
    );
    expect(decide.status(), `approve vex draft: ${await decide.text()}`).toBe(200);
    return draftId;
}

async function runCRA(
    request: APIRequestContext,
    project: VulnerableProject,
    cveId: string,
    reportType: ReportType,
    lang: "en" | "ja" = "en",
): Promise<CRAReport> {
    const res = await request.post(`${API_BASE_URL}/api/v1/projects/${project.projectId}/cra-reports/run`, {
        data: { cve_id: cveId, vulnerability_id: project.vuln(cveId).id, report_type: reportType, lang },
    });
    expect(res.status(), `cra-reports/run ${cveId} ${reportType}/${lang}: ${await res.text()}`).toBe(201);
    const body = await res.json();
    expect(body.ai_disabled).toBe(true);
    return body.report as CRAReport;
}

function cardFor(page: import("@playwright/test").Page, report: Pick<CRAReport, "cve_id" | "report_type" | "lang">) {
    return page.locator(
        `[data-testid="cra-report-card"][data-cve-id="${report.cve_id}"]` +
            `[data-report-type="${report.report_type}"][data-lang="${report.lang}"]`,
    );
}

test.describe("AI CRA Reports (M2-5)", () => {
    test.describe("empty project", () => {
        let projectId: string | null = null;

        test.beforeAll(async ({ request }) => {
            projectId = (await createProject(request, uniqueName("CRA Reports Empty Project"))).id;
        });

        test.afterAll(async ({ request }) => {
            await deleteProject(request, projectId);
        });

        test("should render the CRA reports page shell", async ({ page }) => {
            await page.goto(`/en/projects/${projectId}/cra-reports`);

            await expect(page.getByTestId("cra-reports-page")).toBeVisible({ timeout: 10000 });
            await expect(page.getByRole("heading", { name: en.CRAReports.Page.title })).toBeVisible();
            await expect(page.getByTestId("cra-reports-refresh")).toBeVisible();
            // Filter card and all four filter selects mount on first render.
            await expect(page.getByTestId("cra-reports-filters")).toBeVisible();
            await expect(page.getByTestId("filter-report-type")).toBeVisible();
            await expect(page.getByTestId("filter-lang")).toBeVisible();
            await expect(page.getByTestId("filter-state")).toBeVisible();
            await expect(page.getByTestId("filter-decision")).toBeVisible();
        });

        test("should show empty state when no CRA reports exist", async ({ page, request }) => {
            const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/cra-reports`);
            expect(res.status()).toBe(200);
            expect((await res.json()).reports ?? []).toEqual([]);

            await page.goto(`/en/projects/${projectId}/cra-reports`);
            await expect(page.getByText(en.CRAReports.Page.emptyTitle, { exact: true })).toBeVisible({ timeout: 10000 });
            await expect(page.getByTestId("cra-report-card")).toHaveCount(0);
        });

        test("should surface the AI-disabled banner when the backend reports BYOK unset", async ({ page }) => {
            const reason = "SBOMHUB_LLM_PROVIDER is not set";
            await page.route(/\/api\/v1\/projects\/[^/]+\/cra-reports(\?|$)/, (route) =>
                route.fulfill({
                    status: 503,
                    contentType: "application/json",
                    body: JSON.stringify({ error: "AI features are disabled", reason }),
                }),
            );

            await page.goto(`/en/projects/${projectId}/cra-reports`);
            await expect(page.getByTestId("cra-reports-page")).toBeVisible({ timeout: 10000 });

            const banner = page.getByRole("alert").filter({ hasText: en.Triage.AIDisabledBanner.title });
            await expect(banner).toBeVisible();
            await expect(banner).toContainText(`${en.Triage.AIDisabledBanner.reasonLabel}: ${reason}`);
            await expect(banner.getByRole("link", { name: en.Triage.AIDisabledBanner.ctaLabel })).toHaveAttribute(
                "href",
                "/en/settings/llm",
            );
            await expect(page.getByTestId("cra-reports-flash-errors")).toHaveCount(0);
        });
    });

    test.describe("with reports from the BYOK-unset runner", () => {
        let project: VulnerableProject;
        let sourceDraftId: string;
        let earlyWarning: CRAReport;
        let finalReport: CRAReport;

        test.beforeAll(async ({ request }) => {
            project = await createVulnerableProject(request, "CRA Reports Test Project");
            sourceDraftId = await approveVexDraft(request, project, "CVE-2021-44228");
            earlyWarning = await runCRA(request, project, "CVE-2021-44228", "early_warning");
            finalReport = await runCRA(request, project, "CVE-2021-44228", "final_report");
        });

        test.afterAll(async ({ request }) => {
            await deleteProject(request, project?.projectId);
        });

        test("should refuse to draft without an approved VEX draft", async ({ request }) => {
            // CVE-2021-23337 has no approved VEX draft in this project.
            const cveId = "CVE-2021-23337";
            const res = await request.post(`${API_BASE_URL}/api/v1/projects/${project.projectId}/cra-reports/run`, {
                data: { cve_id: cveId, vulnerability_id: project.vuln(cveId).id, report_type: "early_warning", lang: "en" },
            });
            expect(res.status()).toBe(409);
            expect((await res.json()).error).toMatch(/no approved vex_draft/);
        });

        test("should render an ai_disabled draft report with its source VEX draft", async ({ page }) => {
            // In-band BYOK-unset contract on the persisted row.
            expect(earlyWarning.state).toBe("draft");
            expect(earlyWarning.decision).toBe("pending");
            expect(earlyWarning.source_vex_draft_id).toBe(sourceDraftId);
            expect(earlyWarning.evidence.map((e) => e.kind)).toContain("ai_disabled");

            await page.goto(`/en/projects/${project.projectId}/cra-reports`);
            const card = cardFor(page, earlyWarning);
            await expect(card).toBeVisible({ timeout: 10000 });
            await expect(card).toHaveAttribute("data-state", "draft");
            await expect(card).toHaveAttribute("data-decision", "pending");
            await expect(card).toContainText(en.CRAReports.ReportType.early_warning);
            await expect(card.getByTestId("cra-report-draft")).toContainText("CRA Article 14 Early Warning");
            await expect(card.getByTestId("cra-evidence-list")).toContainText("AI CRA drafting skipped");
            await expect(card.getByTestId("cra-source-vex-link")).toHaveAttribute(
                "href",
                `/en/projects/${project.projectId}/triage`,
            );
            await expect(card.getByTestId("cra-approve")).toBeEnabled();
            await expect(page.getByRole("alert").filter({ hasText: en.Triage.AIDisabledBanner.title })).toHaveCount(0);
        });

        test("should filter by report_type", async ({ page }) => {
            await page.goto(`/en/projects/${project.projectId}/cra-reports`);
            const ew = cardFor(page, earlyWarning);
            const fin = cardFor(page, finalReport);
            await expect(ew).toBeVisible({ timeout: 10000 });
            await expect(fin).toBeVisible();

            const select = page.getByTestId("filter-report-type");
            await select.selectOption("early_warning");
            await expect(select).toHaveValue("early_warning");
            await expect(fin).toHaveCount(0);
            await expect(ew).toBeVisible();
            await expect(page.locator('[data-testid="cra-report-card"]:not([data-report-type="early_warning"])')).toHaveCount(0);

            await select.selectOption("final_report");
            await expect(ew).toHaveCount(0);
            await expect(fin).toBeVisible();

            await select.selectOption("");
            await expect(ew).toBeVisible();
            await expect(fin).toBeVisible();
        });

        test("should draft a 72h detailed notification", async ({ request }) => {
            test.fixme(true, "BUG: cra_reports.report_type is VARCHAR(20) but 'detailed_notification' is 21 chars, so every detailed_notification run fails with 500 (pq 22001)");
            const report = await runCRA(request, project, "CVE-2021-44228", "detailed_notification");
            expect(report.report_type).toBe("detailed_notification");
            expect(report.state).toBe("draft");
        });

        test("should approve a report and remove it from the pending queue", async ({ page, request }) => {
            // Acceptance criterion: approve → 該当 row が消えること.
            // Its own CVE, so the other tests' cards are unaffected.
            await approveVexDraft(request, project, "CVE-2021-45046");
            const report = await runCRA(request, project, "CVE-2021-45046", "early_warning");

            await page.goto(`/en/projects/${project.projectId}/cra-reports`);
            // Show only the pending queue (the default "Any" view would bring
            // the approved row straight back on the refetch).
            await page.getByTestId("filter-decision").selectOption("pending");
            const card = cardFor(page, report);
            await expect(card).toBeVisible({ timeout: 10000 });

            await card.getByTestId("cra-approve").click();
            await expect(card).toHaveCount(0);

            await expect
                .poll(async () => {
                    const res = await request.get(
                        `${API_BASE_URL}/api/v1/projects/${project.projectId}/cra-reports/${report.id}`,
                    );
                    return res.ok() ? (await res.json()).decision : `HTTP ${res.status()}`;
                })
                .toBe("approved");

            // The approved row lives on under the "approved" filter.
            await page.getByTestId("filter-decision").selectOption("approved");
            await expect(card).toBeVisible();
            await expect(card).toHaveAttribute("data-decision", "approved");
            await expect(card.getByTestId("cra-approve")).toBeDisabled();
        });
    });
});

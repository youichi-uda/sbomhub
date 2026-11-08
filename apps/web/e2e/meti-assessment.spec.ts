/**
 * METI self-assessment page (issue #38, M3 Wave M3-5).
 *
 * These tests exercise the /projects/:id/meti page end-to-end against
 * projects they create themselves. The M3-4 evaluator fan-out runs
 * synchronously on POST /meti/assessment/refresh and always persists the
 * full 32-criterion catalog (service/meti/catalog_test.go pins 32). For a
 * fresh project the statuses are MIXED (mostly needs_review, plus
 * achieved / not_achieved / not_applicable — see service/meti/criteria/*),
 * so the tests read the rows back from the API and assert the page against
 * them rather than against hard-coded statuses.
 *
 * The CI stack is self-hosted anonymous mode: /refresh and PUT/DELETE
 * /override are writable, so every setup step is an `expect`, never a
 * skip. Each test gets its own project, so neither ordering nor retries
 * can leak state between them (the empty-state test needs a never-
 * refreshed project; the override tests need an un-overridden row).
 *
 * Still not covered: the meti_assessment_override_cleared audit row
 * (GET /api/v1/audit-logs is plan-gated), and an evaluator-driven status
 * flip on a known criterion (needs seeded evaluator preconditions).
 */

import { test, expect, type APIRequestContext, type Locator, type Page } from "@playwright/test";
import en from "../messages/en.json";
import { API_BASE_URL, createProject, deleteProject, uniqueName } from "./fixtures/vuln-project";

const tPage = en.METIAssessment.Page;
const tCard = en.METIAssessment.CriterionCard;
const tStatus = en.METIAssessment.Status as Record<string, string>;
const PHASES = ["env_setup", "sbom_creation", "sbom_operation"] as const;
const CATALOG_SIZE = 32;

interface MetiRow {
    criterion_id: string;
    criterion_phase: string;
    status: string;
    override_status?: string | null;
    override_note?: string | null;
}

async function listRows(request: APIRequestContext, projectId: string, query = ""): Promise<MetiRow[]> {
    const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment${query}`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body?.assessments), "assessments array").toBe(true);
    return body.assessments as MetiRow[];
}

async function refresh(request: APIRequestContext, projectId: string): Promise<MetiRow[]> {
    const res = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment/refresh`);
    expect(res.status(), "POST /meti/assessment/refresh").toBe(200);
    const body = await res.json();
    expect(body.refreshed).toBe(CATALOG_SIZE);
    return listRows(request, projectId);
}

function card(page: Page, criterionId: string): Locator {
    // data-criterion-id lives on the card root itself (M12-1 #82), so use a
    // compound attribute selector rather than filter({ has }).
    return page.locator(`[data-testid="meti-criterion-card"][data-criterion-id="${criterionId}"]`);
}

/** A row whose evaluator verdict is not `status`, so overriding to it is a visible flip. */
function rowNotIn(rows: MetiRow[], status: string): MetiRow {
    const row = rows.find((r) => r.status !== status && !r.override_status);
    expect(row, `a non-overridden row whose status is not ${status}`).toBeTruthy();
    return row as MetiRow;
}

test.describe("METI Self-Assessment (M3-5)", () => {
    const created: string[] = [];

    async function newProject(request: APIRequestContext): Promise<string> {
        const { id } = await createProject(request, uniqueName("METI Assessment Test Project"));
        created.push(id);
        return id;
    }

    test.afterAll(async ({ request }) => {
        for (const id of created) await deleteProject(request, id);
    });

    test("should render the METI assessment page shell", async ({ page, request }) => {
        const projectId = await newProject(request);
        await page.goto(`/en/projects/${projectId}/meti`);

        await expect(page.getByTestId("meti-assessment-page")).toBeVisible({ timeout: 10000 });
        await expect(page.getByRole("heading", { name: tPage.title, level: 1 })).toBeVisible();
        await expect(page.getByTestId("meti-refresh")).toHaveText(tPage.refresh);
        // Filter card and all three filter selects mount on first render.
        await expect(page.getByTestId("meti-filters")).toBeVisible();
        await expect(page.getByTestId("filter-phase")).toBeVisible();
        await expect(page.getByTestId("filter-status")).toBeVisible();
        await expect(page.getByTestId("filter-has-override")).toBeVisible();
    });

    test("should show empty state before /refresh has been run, and the matrix after Re-evaluate", async ({
        page,
        request,
    }) => {
        const projectId = await newProject(request);
        expect(await listRows(request, projectId)).toHaveLength(0);

        await page.goto(`/en/projects/${projectId}/meti`);
        const empty = page.getByTestId("meti-empty-state");
        await expect(empty).toBeVisible({ timeout: 10000 });
        await expect(empty).toContainText(tPage.emptyTitle);
        await expect(page.getByTestId("meti-summary")).toHaveCount(0);

        // The page's own Re-evaluate button runs the evaluator.
        await page.getByTestId("meti-refresh").click();
        await expect(page.getByTestId("meti-criterion-card")).toHaveCount(CATALOG_SIZE, { timeout: 15000 });
        await expect(empty).toHaveCount(0);
        await expect(page.getByTestId("meti-flash-errors")).toContainText(
            tPage.refreshSuccess.replace("{count}", String(CATALOG_SIZE)).split("{version}")[0],
        );
        expect(await listRows(request, projectId)).toHaveLength(CATALOG_SIZE);
    });

    test("should filter by phase", async ({ page, request }) => {
        const projectId = await newProject(request);
        const rows = await refresh(request, projectId);
        const envSetup = rows.filter((r) => r.criterion_phase === "env_setup");
        expect(envSetup.length).toBeGreaterThan(0);
        expect(envSetup.length).toBeLessThan(rows.length);

        await page.goto(`/en/projects/${projectId}/meti`);
        const cards = page.getByTestId("meti-criterion-card");
        await expect(cards).toHaveCount(rows.length, { timeout: 10000 });

        const select = page.getByTestId("filter-phase");
        await select.selectOption("env_setup");
        await expect(select).toHaveValue("env_setup");

        // Only env_setup rows remain, and all of them.
        await expect(cards).toHaveCount(envSetup.length);
        await expect(page.locator('[data-testid="meti-criterion-card"]:not([data-phase="env_setup"])')).toHaveCount(0);
        await expect(page.getByTestId("meti-list-sbom_creation")).toHaveCount(0);

        await select.selectOption("");
        await expect(cards).toHaveCount(rows.length);
    });

    test("should render the per-phase accordion after /refresh", async ({ page, request }) => {
        const projectId = await newProject(request);
        const rows = await refresh(request, projectId);

        await page.goto(`/en/projects/${projectId}/meti`);
        await expect(page.getByTestId("meti-phase-accordion")).toBeVisible({ timeout: 10000 });

        for (const phase of PHASES) {
            const item = page.getByTestId(`meti-phase-${phase}`);
            await expect(item).toBeVisible();
            await expect(item).toContainText(en.METIAssessment.Phase[phase]);
            const expected = rows.filter((r) => r.criterion_phase === phase).length;
            await expect(item.getByTestId("meti-criterion-card")).toHaveCount(expected);
        }

        // Summary strip counts match the API rows (no overrides yet).
        const summary = page.getByTestId("meti-summary");
        const count = (s: string) => rows.filter((r) => r.status === s).length;
        await expect(summary).toContainText(tPage.summaryAchieved.replace("{count}", String(count("achieved"))));
        await expect(summary).toContainText(tPage.summaryNotAchieved.replace("{count}", String(count("not_achieved"))));
        await expect(summary).toContainText(tPage.summaryNeedsReview.replace("{count}", String(count("needs_review"))));
        await expect(summary).toContainText(tPage.summaryOverridden.replace("{count}", "0"));
        await expect(page.getByTestId("meti-improvement-toggle")).toBeVisible();

        // Each card shows its evaluator verdict.
        const sample = rows[0];
        await expect(card(page, sample.criterion_id)).toHaveAttribute("data-effective-status", sample.status);
        await expect(card(page, sample.criterion_id)).toContainText(tStatus[sample.status]);
    });

    test("should open the override form on a criterion card", async ({ page, request }) => {
        const projectId = await newProject(request);
        // A row whose verdict is not the form's fallback, so the
        // "starts at the evaluator verdict" check is discriminating.
        const target = rowNotIn(await refresh(request, projectId), "needs_review");

        await page.goto(`/en/projects/${projectId}/meti`);
        const c = card(page, target.criterion_id);
        await expect(c).toBeVisible({ timeout: 10000 });

        await c.getByTestId("meti-override-trigger").click();
        await expect(c.getByTestId("meti-override-form")).toBeVisible();
        // The status select starts at the evaluator verdict.
        await expect(c.getByTestId("meti-override-status-select")).toHaveValue(target.status);
        await expect(c.getByTestId("meti-override-submit")).toHaveText(tCard.overrideSubmit);
        await expect(c.getByTestId("meti-override-cancel")).toBeVisible();

        // Cancel returns to view mode without mutating state.
        await c.getByTestId("meti-override-cancel").click();
        await expect(c.getByTestId("meti-override-form")).toHaveCount(0);
        await expect(c).toHaveAttribute("data-overridden", "false");
        const persisted = (await listRows(request, projectId)).find((r) => r.criterion_id === target.criterion_id);
        expect(persisted?.override_status ?? "").toBe("");
    });

    // Used to skip every run: the override form calls the note
    // "(optional)" and the test left it blank, but PUT /override requires
    // a 1..4096-char note, so the save 400'd, the card never flipped and
    // the `count() === 0 → skip` guard hid it. The operator flow with a
    // reason is tested here; the blank-note path is the fixme'd bug below.
    test("should apply a manual override and surface override badge", async ({ page, request }) => {
        const projectId = await newProject(request);
        const target = rowNotIn(await refresh(request, projectId), "not_applicable");
        const note = "E2E override: vendor attestation reviewed";

        await page.goto(`/en/projects/${projectId}/meti`);
        const c = card(page, target.criterion_id);
        await expect(c).toHaveAttribute("data-overridden", "false", { timeout: 10000 });

        await c.getByTestId("meti-override-trigger").click();
        await c.getByTestId("meti-override-status-select").selectOption("not_applicable");
        await c.getByLabel(tCard.overrideFormNoteLabel).fill(note);
        await c.getByTestId("meti-override-submit").click();

        await expect(c).toHaveAttribute("data-overridden", "true", { timeout: 10000 });
        await expect(c).toHaveAttribute("data-effective-status", "not_applicable");
        await expect(c).toHaveAttribute("data-status", target.status);
        await expect(c.getByTestId("meti-override-form")).toHaveCount(0);
        await expect(c.getByText(tCard.overrideBadge, { exact: true })).toBeVisible();
        await expect(c).toContainText(note);
        await expect(page.getByTestId("meti-summary")).toContainText(tPage.summaryOverridden.replace("{count}", "1"));
        await expect(page.getByTestId("meti-flash-errors")).toHaveCount(0);

        // Persisted, per the REST source of truth.
        const persisted = (await listRows(request, projectId)).find((r) => r.criterion_id === target.criterion_id);
        expect(persisted?.override_status).toBe("not_applicable");
        expect(persisted?.override_note).toBe(note);
    });

    test("should save an override whose optional reason is left blank", async ({ page, request }) => {
        test.fixme(
            true,
            'BUG: the override form labels the note "Override reason (optional)" and its zod schema allows blank, but PUT /meti/assessment/:criterion/override answers 400 "override_note is required" — the save always fails with "Manual override failed"',
        );
        const projectId = await newProject(request);
        const target = rowNotIn(await refresh(request, projectId), "not_applicable");

        await page.goto(`/en/projects/${projectId}/meti`);
        const c = card(page, target.criterion_id);
        await c.getByTestId("meti-override-trigger").click();
        await c.getByTestId("meti-override-status-select").selectOption("not_applicable");
        await c.getByTestId("meti-override-submit").click();

        await expect(c).toHaveAttribute("data-overridden", "true", { timeout: 10000 });
        await expect(page.getByTestId("meti-flash-errors")).toHaveCount(0);
        const persisted = (await listRows(request, projectId)).find((r) => r.criterion_id === target.criterion_id);
        expect(persisted?.override_status).toBe("not_applicable");
    });

    test("should toggle improvement-actions-only filter", async ({ page, request }) => {
        const projectId = await newProject(request);
        const rows = await refresh(request, projectId);
        const actionsRes = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/meti/improvement-actions`);
        expect(actionsRes.status()).toBe(200);
        const actions = ((await actionsRes.json()).actions ?? []) as Array<{ criterion_id: string }>;
        // Discriminating only if the toggle hides some rows but not all.
        expect(actions.length).toBeGreaterThan(0);
        expect(actions.length).toBeLessThan(rows.length);

        await page.goto(`/en/projects/${projectId}/meti`);
        const cards = page.getByTestId("meti-criterion-card");
        await expect(cards).toHaveCount(rows.length, { timeout: 10000 });
        await expect(page.getByTestId("meti-improvement-toggle-label")).toContainText(
            tPage.improvementCount.replace("{count}", String(actions.length)),
        );

        const toggle = page.getByTestId("meti-improvement-toggle");
        await toggle.check();
        await expect(toggle).toBeChecked();
        await expect(cards).toHaveCount(actions.length);
        const shown = await cards.evaluateAll((els) => els.map((e) => e.getAttribute("data-criterion-id")).sort());
        expect(shown).toEqual(actions.map((a) => a.criterion_id).sort());

        await toggle.uncheck();
        await expect(toggle).not.toBeChecked();
        await expect(cards).toHaveCount(rows.length);
    });

    // M3 Codex review #F35 — clear-override flow. The spec seeds its own
    // override row through the public PUT /override and walks the clear
    // form to a REST readback of the cleared override_status.
    test("should expose the clear-override flow on an overridden row", async ({ page, request }) => {
        const projectId = await newProject(request);
        const target = rowNotIn(await refresh(request, projectId), "not_applicable");

        const overrideRes = await request.put(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment/${encodeURIComponent(target.criterion_id)}/override`,
            {
                data: {
                    override_status: "not_applicable",
                    override_note: "E2E seed override (clear-override flow)",
                },
            },
        );
        expect(overrideRes.status(), await overrideRes.text()).toBe(200);

        await page.goto(`/en/projects/${projectId}/meti`);
        const c = card(page, target.criterion_id);
        await expect(c).toHaveAttribute("data-overridden", "true", { timeout: 10000 });
        await expect(c).toHaveAttribute("data-effective-status", "not_applicable");

        const clearTrigger = c.getByTestId("meti-clear-override-trigger");
        await expect(clearTrigger).toHaveText(tCard.clearOverrideButton);
        await clearTrigger.click();

        await expect(c.getByTestId("meti-clear-override-form")).toBeVisible();
        await expect(c.getByTestId("meti-clear-override-confirm")).toHaveText(tCard.clearOverrideConfirm);

        // Submit stays disabled until a non-whitespace note is typed.
        const submit = c.getByTestId("meti-clear-override-submit");
        await expect(submit).toBeDisabled();
        await c.getByTestId("meti-clear-override-note").fill("   ");
        await expect(submit).toBeDisabled();
        await c.getByTestId("meti-clear-override-note").fill(
            "E2E clear: re-evaluated, the original override was wrong",
        );
        await expect(submit).toBeEnabled();
        await submit.click();

        await expect(c).toHaveAttribute("data-overridden", "false", { timeout: 10000 });
        await expect(c).toHaveAttribute("data-effective-status", target.status);
        await expect(c.getByTestId("meti-clear-override-trigger")).toHaveCount(0);
        await expect(c.getByText(tCard.overrideBadge, { exact: true })).toHaveCount(0);
        await expect(page.getByTestId("meti-flash-errors")).toHaveCount(0);

        const persisted = (await listRows(request, projectId)).find((r) => r.criterion_id === target.criterion_id);
        expect(persisted?.override_status ?? "").toBe("");
    });
});

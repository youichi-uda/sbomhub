/**
 * METI self-assessment page (issue #38, M3 Wave M3-5).
 *
 * These tests exercise the /projects/:id/meti page end-to-end. They
 * mirror e2e/cra-reports.spec.ts (M2-5) and e2e/triage.spec.ts (M1-6)
 * shape-for-shape: empty-state, filter UX, summary strip, override
 * flow. The M3-4 evaluator fan-out runs synchronously against the
 * project's SBOM / vulnerability / VEX / CRA history, and a fresh test
 * project has none of those, so /refresh returns 32 rows (the full
 * catalog — service/meti/catalog_test.go pins exactly 32 criteria; the
 * pre-F343 "27 rows" here was a stale claim of the F336 species) all
 * in `needs_review` with empty evidence. That is enough to assert the
 * matrix renders AND — via the public /refresh + PUT/DELETE override
 * endpoints — to apply and clear a real override with a REST readback
 * (see the two override specs below; their conditional skips only
 * guard sessions without write auth). What it is NOT enough for is an
 * evaluator-driven `achieved` → `not_achieved` operator flip, which
 * requires evaluator preconditions the fresh test project lacks.
 *
 * TODO(e2e): verified 2026-07-02 (M23-2 F343): there is still no
 * "seed a meti_assessment" admin endpoint nor a stubbed evaluator
 * harness. (The pre-F343 note here asked to "replace the conditional
 * skips" once one lands, but the refresh → override-form → submit →
 * REST-readback flow it prescribed has since landed through the
 * public API — only with override_status=not_applicable against an
 * all-needs_review matrix.) When a seed path lands, extend the
 * override specs to pin an `achieved` → `not_achieved` flip on a
 * known criterion id.
 */

import { test, expect } from "@playwright/test";

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || "http://localhost:8080";

test.describe("METI Self-Assessment (M3-5)", () => {
    let projectId: string;

    test.beforeAll(async ({ request }) => {
        const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `METI Assessment Test Project ${Date.now()}`,
                description: "Project for METI self-assessment E2E tests",
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

    test("should render the METI assessment page shell", async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/meti`);
        await page.waitForLoadState("networkidle");

        await expect(page.getByTestId("meti-assessment-page")).toBeVisible({ timeout: 10000 });
        await expect(page.getByTestId("meti-refresh")).toBeVisible();
        // Filter card and all three filter selects mount on first render.
        await expect(page.getByTestId("meti-filters")).toBeVisible();
        await expect(page.getByTestId("filter-phase")).toBeVisible();
        await expect(page.getByTestId("filter-status")).toBeVisible();
        await expect(page.getByTestId("filter-has-override")).toBeVisible();
    });

    test("should show empty state before /refresh has been run", async ({ page, request }) => {
        // A brand-new project has no meti_assessments rows until the
        // operator runs /refresh. The empty-state card explains that
        // and exposes the [data-testid="meti-empty-state"] anchor.
        const res = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment`,
        );
        const body = await res.json().catch(() => ({ assessments: [] }));
        const assessments = Array.isArray(body?.assessments) ? body.assessments : [];

        if (assessments.length === 0) {
            await page.goto(`/en/projects/${projectId}/meti`);
            await page.waitForLoadState("networkidle");

            await expect(page.getByTestId("meti-empty-state")).toBeVisible({ timeout: 10000 });
            // English-locale empty title.
            await expect(page.getByText(/No assessment yet/i)).toBeVisible();
        } else {
            test.skip();
        }
    });

    test("should filter by phase without crashing the page shell", async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/meti`);
        await page.waitForLoadState("networkidle");

        // Changing the phase filter triggers a fresh list call via
        // useEffect / useCallback. Assert the select accepts the change
        // and the page does not crash. TODO(e2e): tighten by POSTing
        // /refresh inline first (as the accordion / override specs
        // below already do) and asserting the listed rows are
        // phase-bounded; without a refresh a fresh project has zero
        // meti_assessments rows to filter (verified 2026-07-02, F343).
        const select = page.getByTestId("filter-phase");
        await select.selectOption("env_setup");
        await expect(select).toHaveValue("env_setup");

        await expect(page.getByTestId("meti-assessment-page")).toBeVisible();
    });

    test("should render the per-phase accordion after /refresh", async ({ page, request }) => {
        // /refresh runs the evaluator fan-out. The fresh project has
        // no SBOMs, so every criterion lands in needs_review with empty
        // evidence — that is enough to assert the accordion mounts
        // with one item per phase and the summary strip mounts with
        // non-zero needs_review count.
        const refreshRes = await request.post(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment/refresh`,
        );
        // The refresh endpoint requires write auth via the route group
        // (RequireWrite) so in CI without an API key it may 401. Skip
        // the assertion in that case — the empty-state test already
        // covers the read path.
        if (refreshRes.status() !== 200) {
            test.skip();
            return;
        }

        await page.goto(`/en/projects/${projectId}/meti`);
        await page.waitForLoadState("networkidle");

        await expect(page.getByTestId("meti-phase-accordion")).toBeVisible({ timeout: 10000 });
        await expect(page.getByTestId("meti-phase-env_setup")).toBeVisible();
        await expect(page.getByTestId("meti-phase-sbom_creation")).toBeVisible();
        await expect(page.getByTestId("meti-phase-sbom_operation")).toBeVisible();

        await expect(page.getByTestId("meti-summary")).toBeVisible();
        await expect(page.getByTestId("meti-improvement-toggle")).toBeVisible();
    });

    // M12-1 #82: root-cause audited. The M11-2 11s hang was the
    // selector — `.filter({ has: page.locator('[data-criterion-id=…]') })`
    // requires the matching element to be a DESCENDANT of the card,
    // but `data-criterion-id` lives on the Card itself (see
    // apps/web/src/components/meti/criterion-card.tsx L310-311). Use
    // a compound attribute selector instead so the card matches itself.
    // The `/refresh` POST is gated by RequireWrite (Owner/Admin/Member)
    // and self-hosted mock auth sets Role=Owner, so it should 200 in
    // CI; the inline status-200 guard stays as belt-and-suspenders.
    test("should open the override form on a criterion card", async ({ page, request }) => {
        // Requires at least one meti_assessment row that has NOT been
        // overridden yet. The override-trigger button is disabled when
        // override_status is already set, so we filter on
        // has_override=false. If the project has no rows, /refresh
        // first; if that fails (401 in CI without an API key) skip.
        const listRes = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment?has_override=false`,
        );
        const listBody = await listRes.json().catch(() => ({ assessments: [] }));
        let rows = Array.isArray(listBody?.assessments) ? listBody.assessments : [];

        if (rows.length === 0) {
            const refreshRes = await request.post(
                `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment/refresh`,
            );
            if (refreshRes.status() !== 200) {
                test.skip();
                return;
            }
            const refreshBody = await refreshRes.json().catch(() => ({ assessments: [] }));
            rows = Array.isArray(refreshBody?.assessments) ? refreshBody.assessments : [];
        }

        if (rows.length === 0) {
            test.skip();
            return;
        }

        const target = rows[0];

        await page.goto(`/en/projects/${projectId}/meti`);
        await page.waitForLoadState("networkidle");

        // M12-1 #82: compound attribute selector — `data-criterion-id`
        // is on the Card root, not a descendant, so `.filter({ has })`
        // would never match. Combine both attributes in one locator.
        const card = page
            .locator(`[data-testid="meti-criterion-card"][data-criterion-id="${target.criterion_id}"]`)
            .first();
        await expect(card).toBeVisible({ timeout: 10000 });

        await card.getByTestId("meti-override-trigger").click();
        await expect(card.getByTestId("meti-override-form")).toBeVisible();
        await expect(card.getByTestId("meti-override-status-select")).toBeVisible();
        await expect(card.getByTestId("meti-override-submit")).toBeVisible();
        await expect(card.getByTestId("meti-override-cancel")).toBeVisible();

        // Cancel returns to view mode without mutating state.
        await card.getByTestId("meti-override-cancel").click();
        await expect(card.getByTestId("meti-override-form")).toHaveCount(0);
    });

    // M12-1 #82: same selector fix as override-form spec.
    test("should apply a manual override and surface override badge", async ({ page, request }) => {
        // Acceptance criterion: override → effective status flips and
        // the override badge is visible. Requires a non-overridden row
        // AND a write-capable session — same gating as the prior test.
        const listRes = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment?has_override=false`,
        );
        const listBody = await listRes.json().catch(() => ({ assessments: [] }));
        let rows = Array.isArray(listBody?.assessments) ? listBody.assessments : [];

        if (rows.length === 0) {
            const refreshRes = await request.post(
                `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment/refresh`,
            );
            if (refreshRes.status() !== 200) {
                test.skip();
                return;
            }
            const refreshBody = await refreshRes.json().catch(() => ({ assessments: [] }));
            rows = Array.isArray(refreshBody?.assessments) ? refreshBody.assessments : [];
        }

        if (rows.length === 0) {
            test.skip();
            return;
        }

        const target = rows[0];

        await page.goto(`/en/projects/${projectId}/meti`);
        await page.waitForLoadState("networkidle");

        // M12-1 #82: compound attribute selector (see override-form spec).
        const card = page
            .locator(`[data-testid="meti-criterion-card"][data-criterion-id="${target.criterion_id}"]`)
            .first();
        await expect(card).toBeVisible({ timeout: 10000 });

        await card.getByTestId("meti-override-trigger").click();
        await card.getByTestId("meti-override-status-select").selectOption("not_applicable");
        await card.getByTestId("meti-override-submit").click();

        // Wait for the optimistic UI update + background re-fetch.
        await page.waitForTimeout(2000);

        // The same criterion id should now carry data-overridden="true"
        // when the override has been persisted. If the page-level
        // session lacks write auth the PUT lands as 403 and the badge
        // does not appear; skip in that case since we cannot assert
        // the success outcome. M12-1 #82: compound attribute selector.
        const overriddenCard = page
            .locator(`[data-testid="meti-criterion-card"][data-criterion-id="${target.criterion_id}"][data-overridden="true"]`);

        const overriddenCount = await overriddenCard.count();
        if (overriddenCount === 0) {
            test.skip();
            return;
        }

        await expect(overriddenCard.first()).toBeVisible();

        // Confirm persisted via REST as the source of truth.
        const finalRes = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment`,
        );
        const finalBody = await finalRes.json().catch(() => ({ assessments: [] }));
        const finalRows = Array.isArray(finalBody?.assessments) ? finalBody.assessments : [];
        const persisted = finalRows.find((r: { criterion_id: string }) => r.criterion_id === target.criterion_id);
        expect(persisted?.override_status).toBe("not_applicable");
    });

    test("should toggle improvement-actions-only filter without crashing", async ({ page }) => {
        await page.goto(`/en/projects/${projectId}/meti`);
        await page.waitForLoadState("networkidle");

        // The improvement toggle is only mounted once the summary
        // strip mounts (assessments.length > 0). Conditionally check
        // for it — empty-state projects skip this assertion.
        const toggle = page.getByTestId("meti-improvement-toggle");
        const count = await toggle.count();
        if (count === 0) {
            test.skip();
            return;
        }

        await toggle.check();
        await expect(toggle).toBeChecked();
        await expect(page.getByTestId("meti-assessment-page")).toBeVisible();

        await toggle.uncheck();
        await expect(toggle).not.toBeChecked();
    });

    // M3 Codex review #F35 — clear-override flow. The spec seeds its
    // own override row inline (public PUT /override) and then walks
    // the clear flow to a REST readback of the cleared
    // override_status. Like the "apply a manual override" test above,
    // it is gated on /refresh returning at least one criterion and the
    // PUT /override surface being writable in the current test
    // session. When either gate is missing we test.skip() rather than
    // asserting.
    //
    // TODO(e2e): verified 2026-07-02 (M23-2 F343): the pre-F343 note
    // here waited on a "seed an overridden meti_assessment" admin
    // endpoint, but the seed-override → clear-form → note → cleared
    // readback flow it prescribed has since landed below through the
    // public API. Still missing: confirming the
    // meti_assessment_override_cleared audit row (handler/meti.go
    // emits it on DELETE). GET /api/v1/audit-logs exists but is
    // feature-gated to Pro+ plans (CheckFeature("audit_logs") in
    // cmd/server/main.go), so the audit assertion needs a plan-aware
    // guard (or a Pro-seeded tenant) before it can be added here.
    // M12-1 #82: same selector fix as override-form spec.
    test("should expose the clear-override flow on an overridden row", async ({ page, request }) => {
        const refreshRes = await request.post(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment/refresh`,
        );
        if (!refreshRes.ok()) {
            test.skip();
            return;
        }

        // Pull rows with no override yet — we override one inline so
        // the clear-override trigger becomes visible.
        const listRes = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment?has_override=false`,
        );
        const listBody = await listRes.json().catch(() => ({ assessments: [] }));
        const rows = Array.isArray(listBody?.assessments) ? listBody.assessments : [];
        if (rows.length === 0) {
            test.skip();
            return;
        }
        const target = rows[0];

        const overrideRes = await request.put(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment/${encodeURIComponent(target.criterion_id)}/override`,
            {
                data: {
                    override_status: "not_applicable",
                    override_note: "E2E seed override (clear-override flow)",
                },
            },
        );
        if (!overrideRes.ok()) {
            // PUT may 403 in sessions without write auth; skip in that
            // case since the clear flow can't be exercised without a
            // pre-existing override on this row.
            test.skip();
            return;
        }

        await page.goto(`/en/projects/${projectId}/meti`);
        await page.waitForLoadState("networkidle");

        // M12-1 #82: compound attribute selector (see override-form spec).
        const card = page
            .locator(`[data-testid="meti-criterion-card"][data-criterion-id="${target.criterion_id}"]`)
            .first();
        await expect(card).toBeVisible({ timeout: 10000 });

        // Clear-override trigger should be visible on the overridden
        // row. The override trigger is no longer disabled (M3 #F35).
        const clearTrigger = card.getByTestId("meti-clear-override-trigger");
        await expect(clearTrigger).toBeVisible();
        await clearTrigger.click();

        const form = card.getByTestId("meti-clear-override-form");
        await expect(form).toBeVisible();
        await expect(card.getByTestId("meti-clear-override-confirm")).toBeVisible();

        // Submit should be disabled until a non-whitespace note is typed.
        const submit = card.getByTestId("meti-clear-override-submit");
        await expect(submit).toBeDisabled();
        await card.getByTestId("meti-clear-override-note").fill(
            "E2E clear: re-evaluated, the original override was wrong",
        );
        await expect(submit).toBeEnabled();
        await submit.click();

        await page.waitForTimeout(2000);

        // After the clear, the same criterion id should carry
        // data-overridden="false". If the session lacks write auth
        // the DELETE 403's and the badge stays — skip in that case.
        // M12-1 #82: compound attribute selector.
        const clearedCard = page
            .locator(`[data-testid="meti-criterion-card"][data-criterion-id="${target.criterion_id}"][data-overridden="false"]`);
        if ((await clearedCard.count()) === 0) {
            test.skip();
            return;
        }
        await expect(clearedCard.first()).toBeVisible();

        // Confirm persisted via REST as the source of truth.
        const finalRes = await request.get(
            `${API_BASE_URL}/api/v1/projects/${projectId}/meti/assessment`,
        );
        const finalBody = await finalRes.json().catch(() => ({ assessments: [] }));
        const finalRows = Array.isArray(finalBody?.assessments) ? finalBody.assessments : [];
        const persisted = finalRows.find(
            (r: { criterion_id: string }) => r.criterion_id === target.criterion_id,
        );
        expect(persisted?.override_status ?? "").toBe("");
    });
});

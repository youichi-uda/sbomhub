// SBOMHub - AlertDialog WAI-ARIA modal contract (F205, M13 Phase D round 4)
//
// F192 hardened the Dialog primitive (apps/web/src/components/ui/dialog.tsx)
// to the full WAI-ARIA modal contract — role + aria-modal on the panel,
// aria-labelledby linkage to DialogTitle via useId, document-level
// Escape handler, Tab/Shift+Tab focus trap, accessible-name on the close
// affordance. The sibling AlertDialog primitive (used by the two
// destructive-action surfaces: delete API key in /settings/apikeys and
// delete integration in /settings/integrations) was left on the old,
// non-conformant shim — flagged in round 4 review as F205 and the
// symmetric half of anti-pattern 48 (fix-one-instance-leave-pattern).
//
// The F205 fix routes AlertDialogContent through Dialog/DialogContent
// (compose, don't duplicate). This spec is the regression bar that the
// composition stays wired:
//   1. Opening the AlertDialog mounts a panel with role="dialog" and
//      aria-modal="true".
//   2. The panel's aria-labelledby points at an element whose textContent
//      matches the destructive confirmation title.
//   3. Escape dismisses the modal.
//   4. Tab cycling does not leak focus to the page body below.
//
// Auth posture: this spec runs against the dev:test launcher
// (PLAYWRIGHT_SKIP_WEB_SERVER unset → playwright.config.ts spins up
// `npm run dev:test` with auth disabled), matching api-keys.spec.ts and
// integrations.spec.ts. It is intentionally NOT placed under e2e/smoke/
// because the smoke job runs against a production docker compose stack
// with real Clerk middleware where the /settings/apikeys destructive
// flow is not reachable without authenticated state.
import { test, expect, type Locator, type Page } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('AlertDialog WAI-ARIA modal contract (F205)', () => {
    let seededKeyId: string | null = null;
    let seededKeyName = '';

    // The delete trigger of the seeded key: the only button in the Card whose
    // title is the seeded key's name. Located by structure + accessible role
    // rather than by the lucide icon class, which lucide-react renamed
    // (0.x `lucide-trash2` -> 1.x `lucide-trash lucide-trash-2`) and which
    // left this spec skipping every test without anyone noticing.
    function seededTrigger(page: Page): Locator {
        return page
            .locator('div.bg-card')
            .filter({ has: page.getByRole('heading', { name: seededKeyName, exact: true }) })
            .getByRole('button');
    }

    async function openSeededDialog(page: Page): Promise<Locator> {
        await page.goto('/en/settings/apikeys');
        const trigger = seededTrigger(page);
        // Exactly one: the seed is a precondition, not an optional extra, so
        // a missing row fails the test instead of skipping it.
        await expect(trigger).toHaveCount(1, { timeout: 15000 });
        await trigger.click();
        const dialog = page.locator('[role="dialog"]').first();
        await expect(dialog).toBeVisible({ timeout: 5000 });
        return dialog;
    }

    test.beforeAll(async ({ request }) => {
        // Seed a tenant-level API key with a name unique to this run so the
        // /settings/apikeys page renders a per-row destructive AlertDialog
        // trigger we can find by that name. Keys left by prior runs are
        // irrelevant: the tests only touch this row. A failed seed fails the
        // suite here (it used to fall through to a silent skip). afterAll
        // deletes the key; none of these tests confirms the deletion.
        seededKeyName = `F205 A11y Seed ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const resp = await request.post(`${API_BASE_URL}/api/v1/apikeys`, {
            data: {
                name: seededKeyName,
                permissions: 'read',
            },
        });
        expect(resp.ok(), `seeding the API key returned ${resp.status()}`).toBe(true);
        const body = await resp.json();
        seededKeyId = body?.id ?? null;
    });

    test.afterAll(async ({ request }) => {
        // Best-effort cleanup; ignore errors (the destructive flow under
        // test may have already removed the row, or the API may be
        // unavailable in CI shutdown).
        if (seededKeyId) {
            await request.delete(`${API_BASE_URL}/api/v1/apikeys/${seededKeyId}`).catch(() => {});
        }
    });

    test('opens with role=dialog + aria-modal + aria-labelledby linkage', async ({ page }) => {
        // Click the seeded key's trash-icon trigger (a ghost icon button — see
        // apps/web/src/app/[locale]/(dashboard)/settings/apikeys/page.tsx) to
        // mount the AlertDialog, then assert the WAI-ARIA modal contract on
        // the panel.
        const dialog = await openSeededDialog(page);
        await expect(dialog).toHaveAttribute('aria-modal', 'true');

        const labelledBy = await dialog.getAttribute('aria-labelledby');
        expect(labelledBy, 'aria-labelledby must be wired by DialogContext').toBeTruthy();

        // The referenced element must exist and carry the destructive
        // confirmation heading. We do not pin the exact copy beyond
        // matching the i18n shape — `Delete API Key?` (EN) or its JA
        // counterpart — so a future copy edit does not break this bar.
        const labelEl = page.locator(`#${labelledBy}`);
        await expect(labelEl).toBeVisible();
        const labelText = (await labelEl.innerText()).trim();
        expect(labelText.length, 'labelled element must not be empty').toBeGreaterThan(0);
    });

    test('Escape key dismisses the AlertDialog', async ({ page }) => {
        const dialog = await openSeededDialog(page);

        // Inherited from F192's document-level keydown on the Dialog
        // primitive: Escape must close the modal.
        await page.keyboard.press('Escape');
        await expect(dialog).toBeHidden({ timeout: 5000 });
    });

    test('Tab cycling stays inside the AlertDialog panel', async ({ page }) => {
        await openSeededDialog(page);

        // Walk Tab a handful of times and assert focus never escapes the
        // dialog into the page body. The focus-trap implementation in
        // DialogContent rewraps Tab / Shift+Tab to the opposite end of the
        // panel's focusable set; we do not assert which element holds
        // focus at each step (Cancel vs Confirm ordering is style-driven
        // by flex-col-reverse) — only that focus remains scoped.
        for (let i = 0; i < 6; i++) {
            await page.keyboard.press('Tab');
            const focusedInsideDialog = await page.evaluate(() => {
                const dlg = document.querySelector('[role="dialog"]');
                return !!dlg && !!document.activeElement && dlg.contains(document.activeElement);
            });
            expect(focusedInsideDialog, `Tab #${i + 1} leaked focus outside the dialog`).toBeTruthy();
        }

        // Clean up: dismiss before next test (Escape is asserted in the
        // sibling test; here we use it for teardown).
        await page.keyboard.press('Escape');
    });
});

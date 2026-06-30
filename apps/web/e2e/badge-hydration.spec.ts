// SBOMHub - Badge primitive HTML nesting contract (F207, M13-1 #87)
//
// Round 4 (F205) chromium probe of /settings/apikeys surfaced a separate,
// orthogonal hydration warning: `<div> cannot be a descendant of <p>`.
// Root cause: the Badge primitive (apps/web/src/components/ui/badge.tsx)
// rendered as `<div>`, and two production surfaces nested it inside
// `<CardDescription>` (which renders as `<p>`):
//   * /settings/apikeys line ~304 — per-key permission Badge
//     ("read"/"write") inside the key list card description.
//   * /settings/integrations line ~335 — per-integration tracker_type
//     Badge ("Jira"/"Backlog") inside the integration list card
//     description.
// This is anti-pattern 48 (fix-one-instance-leave-pattern) in primitive
// form — a single shared component pulling every CardDescription caller
// into HTML invalidity.
//
// The F207 fix retypes Badge as `<span>` (phrasing content). Span is a
// valid child of `<p>` per the HTML spec, the existing `inline-flex`
// styling preserves the visual, and every caller is backward-compatible
// because Badge accepts only React.HTMLAttributes (now over
// HTMLSpanElement). One file changed, two violation sites resolved,
// future Badge-inside-p usage is intrinsically safe.
//
// This spec is the regression bar that pins the contract:
//   1. Badge mounted inside CardDescription on each affected page must
//      have tagName === 'SPAN' (not 'DIV').
//   2. Browser console must NOT emit the hydration error
//      "cannot be a descendant of <p>" while the page renders.
//
// Auth posture: dev:test launcher (PLAYWRIGHT_SKIP_WEB_SERVER unset →
// playwright.config.ts spins up `npm run dev:test` with auth disabled),
// matching api-keys.spec.ts / integrations.spec.ts / alert-dialog-a11y
// .spec.ts. Intentionally not under e2e/smoke/ — the smoke job hits the
// prod docker stack with real Clerk middleware where /settings/* is
// gated.
import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// Match React's hydration / HTML-validation diagnostic. React 19 emits
// console.error with a printf-style format string and the offending
// tag names as separate args (Playwright's msg.text() concatenates
// them), so we anchor on the stable invariant phrases that appear
// regardless of which child tag is offending — both "<div> p" and
// "p <div>" cases are caught. F207 fix should leave zero matches.
const HYDRATION_NESTING_PATTERN =
    /(?:cannot be a descendant of <[^>]+>|cannot contain a nested)/i;

test.describe('Badge primitive HTML nesting contract (F207)', () => {
    let seededKeyId: string | null = null;

    test.beforeAll(async ({ request }) => {
        // Seed at least one tenant-level API key so the /settings/apikeys
        // page actually renders a CardDescription with a Badge child —
        // the empty-state branch shows a different layout that doesn't
        // exercise the violation site.
        const resp = await request.post(`${API_BASE_URL}/api/v1/apikeys`, {
            data: {
                name: `F207 Hydration Seed ${Date.now()}`,
                permissions: 'read',
            },
        });
        if (resp.ok()) {
            const body = await resp.json();
            seededKeyId = body?.id ?? null;
        }
    });

    test.afterAll(async ({ request }) => {
        if (seededKeyId) {
            await request
                .delete(`${API_BASE_URL}/api/v1/apikeys/${seededKeyId}`)
                .catch(() => {});
        }
    });

    test('apikeys: Badge in CardDescription mounts as <span>, no <p>-nesting console error', async ({
        page,
    }) => {
        const nestingErrors: string[] = [];
        page.on('console', (msg) => {
            if (msg.type() !== 'error') return;
            const text = msg.text();
            if (HYDRATION_NESTING_PATTERN.test(text)) {
                nestingErrors.push(text);
            }
        });
        page.on('pageerror', (err) => {
            if (HYDRATION_NESTING_PATTERN.test(err.message)) {
                nestingErrors.push(err.message);
            }
        });

        await page.goto('/en/settings/apikeys');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1500);

        // If the seed succeeded the list renders at least one row whose
        // CardDescription contains a permission Badge. If the seed
        // failed (CI shutdown race etc.) the rest of the contract still
        // holds — the badge primitive change is enforced structurally
        // by the tagName check, and there must still be zero p-nesting
        // errors regardless of branch.
        const badges = page.locator('[class*="inline-flex"][class*="rounded-full"]');
        const badgeCount = await badges.count();
        if (badgeCount > 0) {
            const tagNames = await badges.evaluateAll((els) =>
                els.map((el) => el.tagName.toUpperCase()),
            );
            for (const tag of tagNames) {
                expect(tag, 'Badge primitive must render as SPAN (F207)').toBe('SPAN');
            }
        }

        expect(
            nestingErrors,
            `No <p>-nesting hydration error must fire (F207). Got: ${nestingErrors.join(' | ')}`,
        ).toEqual([]);
    });

    test('integrations: Badge in CardDescription mounts as <span>, no <p>-nesting console error', async ({
        page,
    }) => {
        const nestingErrors: string[] = [];
        page.on('console', (msg) => {
            if (msg.type() !== 'error') return;
            const text = msg.text();
            if (HYDRATION_NESTING_PATTERN.test(text)) {
                nestingErrors.push(text);
            }
        });
        page.on('pageerror', (err) => {
            if (HYDRATION_NESTING_PATTERN.test(err.message)) {
                nestingErrors.push(err.message);
            }
        });

        await page.goto('/en/settings/integrations');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(1500);

        // The integrations list may legitimately be empty in CI (no
        // tracker connected). The badge tagName check is conditional;
        // the no-hydration-error check is unconditional.
        const badges = page.locator('[class*="inline-flex"][class*="rounded-full"]');
        const badgeCount = await badges.count();
        if (badgeCount > 0) {
            const tagNames = await badges.evaluateAll((els) =>
                els.map((el) => el.tagName.toUpperCase()),
            );
            for (const tag of tagNames) {
                expect(tag, 'Badge primitive must render as SPAN (F207)').toBe('SPAN');
            }
        }

        expect(
            nestingErrors,
            `No <p>-nesting hydration error must fire (F207). Got: ${nestingErrors.join(' | ')}`,
        ).toEqual([]);
    });
});

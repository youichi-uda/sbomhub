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
import { test, expect, type Locator, type Page } from '@playwright/test';
import en from '../messages/en.json';

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

// Integrations: the hermetic stack cannot create a tracker connection
// (POST /integrations performs a live connection test against Jira /
// Backlog / GitHub, and the SSRF guard rejects local hosts), so the
// integrations test serves the connection LIST from a page.route stub.
// The contract under test is purely the frontend's DOM nesting, which
// is rendered from that list exactly as from a real response.
const STUB_CONNECTION = {
    id: '11111111-2222-3333-4444-555555555555',
    tenant_id: '00000000-0000-0000-0000-000000000001',
    tracker_type: 'jira',
    name: 'F207 Stub Jira',
    base_url: 'https://f207-stub.atlassian.net',
    auth_type: 'api_token',
    auth_email: 'f207@example.com',
    is_active: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
};

function collectNestingErrors(page: Page): string[] {
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
    return nestingErrors;
}

/** The Badge must be a <span> whose parent is the CardDescription <p>. */
async function expectSpanBadgeInsideP(badge: Locator) {
    await expect(badge).toBeVisible({ timeout: 15000 });
    const shape = await badge.evaluate((el) => ({
        tag: el.tagName.toUpperCase(),
        parentTag: el.parentElement?.tagName.toUpperCase() ?? null,
    }));
    expect(shape.tag, 'Badge primitive must render as SPAN (F207)').toBe('SPAN');
    // Pins that this really is the CardDescription violation site.
    expect(shape.parentTag, 'Badge must sit inside CardDescription <p>').toBe('P');
}

test.describe('Badge primitive HTML nesting contract (F207)', () => {
    let seededKeyId: string | null = null;
    const seededKeyName = `F207 Hydration Seed ${Date.now()}`;

    test.beforeAll(async ({ request }) => {
        // Seed a tenant-level API key so the /settings/apikeys page
        // renders a CardDescription with a permission Badge child.
        const resp = await request.post(`${API_BASE_URL}/api/v1/apikeys`, {
            data: { name: seededKeyName, permissions: 'read' },
        });
        expect(resp.status(), `seed API key: ${await resp.text()}`).toBe(201);
        const body = await resp.json();
        expect(typeof body?.id).toBe('string');
        seededKeyId = body.id;
    });

    test.afterAll(async ({ request }) => {
        if (seededKeyId) {
            await request.delete(`${API_BASE_URL}/api/v1/apikeys/${seededKeyId}`);
        }
    });

    test('apikeys: Badge in CardDescription mounts as <span>, no <p>-nesting console error', async ({
        page,
    }) => {
        const nestingErrors = collectNestingErrors(page);

        await page.goto('/en/settings/apikeys');
        await page.waitForLoadState('networkidle');

        const card = page.locator('div.rounded-lg', { hasText: seededKeyName }).filter({
            has: page.getByText(en.Settings.APIKeys.permissionRead, { exact: true }),
        }).last();
        await expectSpanBadgeInsideP(card.getByText(en.Settings.APIKeys.permissionRead, { exact: true }));

        expect(
            nestingErrors,
            `No <p>-nesting hydration error must fire (F207). Got: ${nestingErrors.join(' | ')}`,
        ).toEqual([]);
    });

    test('integrations: Badge in CardDescription mounts as <span>, no <p>-nesting console error', async ({
        page,
    }) => {
        await page.route('**/api/v1/integrations', async (route) => {
            if (route.request().method() !== 'GET') return route.fallback();
            await route.fulfill({ json: { connections: [STUB_CONNECTION] } });
        });
        const nestingErrors = collectNestingErrors(page);

        await page.goto('/en/settings/integrations');
        await page.waitForLoadState('networkidle');

        const card = page.locator('div.rounded-lg', { hasText: STUB_CONNECTION.name }).filter({
            has: page.getByText(STUB_CONNECTION.base_url),
        }).last();
        await expectSpanBadgeInsideP(card.getByText('Jira', { exact: true }));

        expect(
            nestingErrors,
            `No <p>-nesting hydration error must fire (F207). Got: ${nestingErrors.join(' | ')}`,
        ).toEqual([]);
    });
});

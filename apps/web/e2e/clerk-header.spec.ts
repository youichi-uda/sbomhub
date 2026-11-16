import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import ja from '../messages/ja.json';
import {
  CLERK_BASE_URL,
  routeFakeClerkJs,
  signIn,
  startFakeBackendApi,
  type FakeOrg,
} from './fixtures/fake-clerk';

// Login mode (Clerk configured): the dashboard header adds Clerk's
// OrganizationSwitcher and a Logout button next to the menu button and the
// locale toggle. At 320px they did not fit: nothing in the row could shrink,
// so the header (and the page) scrolled sideways. The anonymous-mode reflow
// spec (narrow-viewport.spec.ts) cannot see this — the switcher and Logout
// only render when Clerk is configured and the user is signed in.
//
// Needs a web app BUILT in Clerk mode with the fake key and pointed at the
// fake Backend API — see e2e/fixtures/fake-clerk.ts — and its URL in
// PLAYWRIGHT_CLERK_BASE_URL. The regular CI stack is built without a Clerk
// key, so there the tests skip at test level (never at collection, see
// skip-reachability.spec.ts), each naming what it needs.

const WIDTH = 320;
const ORG: FakeOrg = { id: 'org_e2e_fake', name: 'Acme Precision Manufacturing Co., Ltd.', slug: 'acme-precision' };
const NEEDS = 'PLAYWRIGHT_CLERK_BASE_URL: a Clerk-mode build (see e2e/fixtures/fake-clerk.ts)';

// One worker owns the fake Backend API port and the signing key.
test.describe.configure({ mode: 'serial' });

let bapi: Awaited<ReturnType<typeof startFakeBackendApi>> | undefined;
test.beforeAll(async () => {
  if (CLERK_BASE_URL) bapi = await startFakeBackendApi();
});
test.afterAll(async () => {
  await new Promise((r) => (bapi ? bapi.close(r) : r(undefined)));
});

async function openSignedIn(page: Page, path: string) {
  const token = await signIn(page.context(), CLERK_BASE_URL, ORG);
  const { scripts } = await routeFakeClerkJs(page, ORG, token);
  const response = await page.goto(new URL(path, CLERK_BASE_URL).toString());
  // The middleware let a signed-in user through (no redirect to sign-in).
  expect(new URL(page.url()).pathname, `redirected: ${page.url()}`).toBe(path);
  expect(response?.status()).toBe(200);
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({ timeout: 15_000 });
  // The stub clerk-js was loaded and mounted the switcher.
  const switcher = page.locator('header [data-fake-clerk="organization-switcher"]');
  await expect(switcher).toBeVisible();
  expect(scripts.some((s) => /clerk/.test(s))).toBe(true);
  return switcher;
}

async function headerLayout(page: Page) {
  return page.evaluate(() => {
    const vw = document.documentElement.clientWidth;
    const header = document.querySelector('header')!;
    const outside = Array.from(header.querySelectorAll<HTMLElement>('button, a, [data-fake-clerk]'))
      .filter((el) => {
        const r = el.getBoundingClientRect();
        return r.width > 0 && (r.left < -0.5 || r.right > vw + 0.5);
      })
      .map((el) => `${el.tagName.toLowerCase()} "${(el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 30)}" right=${Math.round(el.getBoundingClientRect().right)}`);
    return {
      pageExtra: document.documentElement.scrollWidth - vw,
      headerOverrun: header.scrollWidth - header.clientWidth,
      outside,
    };
  });
}

for (const locale of ['en', 'ja'] as const) {
  test(`${locale}: the signed-in header fits ${WIDTH}px with the organization switcher and Logout`, async ({ page }) => {
    test.skip(!CLERK_BASE_URL, NEEDS);
    await page.setViewportSize({ width: WIDTH, height: 800 });
    await openSignedIn(page, `/${locale}/dashboard`);
    const logout = page.getByRole('button', { name: locale === 'en' ? 'Logout' : 'ログアウト' });
    await expect(logout).toBeVisible();
    await expect(page.getByRole('button', { name: (locale === 'en' ? en : ja).Navigation.openMenu })).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(await headerLayout(page)).toEqual({ pageExtra: 0, headerOverrun: 0, outside: [] });
  });
}

test('the organization name is still there at full width', async ({ page }) => {
  test.skip(!CLERK_BASE_URL, NEEDS);
  await page.setViewportSize({ width: 1280, height: 800 });
  const switcher = await openSignedIn(page, '/en/dashboard');
  // Not truncated when there is room.
  const name = switcher.getByText(ORG.name, { exact: true });
  await expect(name).toBeVisible();
  expect(await name.evaluate((el) => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
  await expect(page.getByRole('button', { name: 'Logout' })).toContainText('Logout');
  expect(await headerLayout(page)).toEqual({ pageExtra: 0, headerOverrun: 0, outside: [] });
});

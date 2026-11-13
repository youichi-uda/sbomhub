import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { createProject, createVulnerableProject, deleteProject, type VulnerableProject } from './fixtures/vuln-project';

// At a 320px viewport (the narrowest phone width WCAG 1.4.10 reflow asks
// for) no page may scroll sideways. The dashboard shell had a fixed 256px
// sidebar, leaving 64px for the page, so every dashboard page scrolled; the
// project page's action and tab rows, page headers, the landing page's
// command cards, the legal table and the MCP docs paths overflowed too.
// Below `md` the sidebar now opens from a menu button.
//
// Pages are checked once their <h1> (share: its list title) is on screen, so a loading placeholder
// cannot pass for the page. The seed project (docker/seed/web-e2e.sql) is
// only read; the vulnerability list uses a project this spec creates.

const SEED_PROJECT = '00000000-0000-0000-0000-000000000010';
const WIDTH = 320;

const PAGES = [
  '/en',
  '/ja',
  '/en/legal',
  '/en/docs/mcp',
  '/en/dashboard',
  '/ja/dashboard',
  '/en/projects',
  `/en/projects/${SEED_PROJECT}`,
  `/en/projects/${SEED_PROJECT}/triage`,
  `/en/projects/${SEED_PROJECT}/cra-reports`,
  `/en/projects/${SEED_PROJECT}/meti`,
  `/en/projects/${SEED_PROJECT}/compliance`,
  `/en/projects/${SEED_PROJECT}/diff`,
  `/en/projects/${SEED_PROJECT}/share`,
  '/en/analytics',
  '/en/audit',
  '/en/reports',
  '/en/search',
  '/en/billing',
  '/en/settings/apikeys',
  '/en/settings/integrations',
  '/en/settings/llm',
  '/en/settings/ipa',
  '/en/settings/scan',
  '/en/settings/sso',
  '/en/settings/reports',
  '/en/settings/diff-webhook',
];

/** Document width beyond the viewport, plus the elements that cause it. */
async function horizontalOverflow(page: Page): Promise<{ extra: number; culprits: string[] }> {
  return page.evaluate(() => {
    const vw = document.documentElement.clientWidth;
    const extra = document.documentElement.scrollWidth - vw;
    const culprits: string[] = [];
    if (extra > 0) {
      for (const el of Array.from(document.querySelectorAll<HTMLElement>('body *'))) {
        const r = el.getBoundingClientRect();
        if (r.width && r.right > vw + 0.5 && culprits.length < 5) {
          culprits.push(`${el.tagName.toLowerCase()}.${String(el.className).slice(0, 60)} right=${Math.round(r.right)}`);
        }
      }
    }
    return { extra, culprits };
  });
}

/**
 * Content cut off by an `overflow: hidden / clip` box that does not scroll
 * (Codex R1 Medium-2: the reports table sat in a rounded `overflow-hidden`
 * card, so at 320px its Download column was unreachable — the document did
 * not widen, so the page-scroll check alone could not see it).
 */
async function clippedContent(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>('body *'))) {
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height) continue;
      for (let a = el.parentElement; a && a !== document.body; a = a.parentElement) {
        const ox = getComputedStyle(a).overflowX;
        if (ox === 'visible') continue;
        if (ox === 'auto' || ox === 'scroll') break; // reachable by scrolling
        const ar = a.getBoundingClientRect();
        // A 1px sr-only box clips by design.
        if (ar.width > 2 && r.right > ar.right + 1 && r.left < ar.right && out.length < 5) {
          out.push(`${el.tagName.toLowerCase()}.${String(el.className).slice(0, 50)} right=${Math.round(r.right)} clipped by ${a.tagName.toLowerCase()}.${String(a.className).slice(0, 50)} right=${Math.round(ar.right)}`);
        }
        break;
      }
    }
    return out;
  });
}

async function expectNoHorizontalScroll(page: Page, what: string): Promise<void> {
  const { extra, culprits } = await horizontalOverflow(page);
  expect(extra, `${what} scrolls ${extra}px sideways at ${WIDTH}px:\n  ${culprits.join('\n  ')}`).toBeLessThanOrEqual(0);
  const clipped = await clippedContent(page);
  expect(clipped, `${what} cuts content off at ${WIDTH}px with no way to scroll to it`).toEqual([]);
}

test.describe(`no horizontal page scroll at ${WIDTH}px`, () => {
  test.use({ viewport: { width: WIDTH, height: 800 } });

  for (const path of PAGES) {
    test(path, async ({ page }) => {
      await page.goto(path);
      // The share page has no <h1>; its list card's title is the signal.
      const ready = path.endsWith('/share')
        ? page.getByRole('heading', { name: 'Public Links' })
        : page.getByRole('heading', { level: 1 }).first();
      await expect(ready).toBeVisible({ timeout: 15_000 });
      await page.waitForLoadState('networkidle');
      await expectNoHorizontalScroll(page, path);
    });
  }

  test('every tab of the project page, including the vulnerability list', async ({ page, request }) => {
    let project: VulnerableProject | undefined;
    try {
      project = await createVulnerableProject(request, 'Narrow Viewport Project');
      await page.goto(`/en/projects/${project.projectId}`);
      await expect(page.getByRole('heading', { level: 1, name: project.projectName })).toBeVisible();
      const tabs = [
        en.Projects.upload,
        en.Components.title,
        en.Vulnerabilities.title,
        'VEX',
        en.Components.license,
        en.ProjectDetail.notifications,
        en.ProjectDetail.apiKeys,
      ];
      for (const name of tabs) {
        await page.getByRole('button', { name: new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}( \\(\\d+\\))?$`) }).click();
        if (name === en.Vulnerabilities.title) {
          await expect(page.getByTestId('vuln-entry')).toHaveCount(4, { timeout: 15_000 });
        }
        await page.waitForLoadState('networkidle');
        await expectNoHorizontalScroll(page, `project tab "${name}"`);
      }
    } finally {
      await deleteProject(request, project?.projectId);
    }
  });

  // Codex R1 Medium-3: an unbroken project name (a hash, a repository id)
  // kept its min-content width inside the wrapped header rows.
  test('a long unbroken project name wraps on every project page', async ({ page, request }) => {
    const name = `narrow-${'x'.repeat(90)}-${Date.now()}`;
    const project = await createProject(request, name);
    try {
      const base = `/en/projects/${project.id}`;
      for (const path of ['/en/projects', '/en/dashboard', base, `${base}/triage`, `${base}/cra-reports`, `${base}/meti`, `${base}/compliance`, `${base}/diff`, `${base}/share`]) {
        await page.goto(path);
        await page.waitForLoadState('networkidle');
        // The name is on screen (not a loading placeholder) where the page shows it.
        // (The list pages may page it out among other specs' projects.)
        if (path === base || /\/(triage|cra-reports|meti)$/.test(path)) {
          await expect(page.getByText(name, { exact: true }).first()).toBeVisible();
        }
        await expectNoHorizontalScroll(page, `${path} with a long project name`);
      }
    } finally {
      await deleteProject(request, project.id);
    }
  });

  test('the reports table scrolls inside its card, so the Download action is reachable', async ({ page }) => {
    const report = {
      id: '00000000-0000-0000-0000-00000000beef',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      report_type: 'executive',
      format: 'pdf',
      title: 'Executive summary report with a fairly long title',
      period_start: '2026-10-01T00:00:00Z',
      period_end: '2026-10-31T00:00:00Z',
      file_path: '',
      file_size: 123456,
      status: 'completed',
      created_at: '2026-11-01T00:00:00Z',
    };
    await page.route(
      (url) => url.pathname === '/api/v1/reports',
      (route) =>
        route.request().method() === 'GET'
          ? route.fulfill({
              contentType: 'application/json',
              body: JSON.stringify({ reports: [report], total: 1, page: 1, limit: 20, total_pages: 1 }),
            })
          : route.fallback(),
    );
    await page.goto('/en/reports');
    const download = page.getByRole('button', { name: en.Reports.download });
    await expect(download).toHaveCount(1);
    await expectNoHorizontalScroll(page, 'reports with a row');
    await download.scrollIntoViewIfNeeded();
    const box = (await download.boundingBox())!;
    expect(box.x, 'Download left edge').toBeGreaterThanOrEqual(0);
    expect(box.x + box.width, 'Download right edge').toBeLessThanOrEqual(WIDTH);
  });

  test('the component search form wraps', async ({ page }) => {
    await page.goto('/en/search');
    await page.getByRole('tab', { name: en.Search.componentSearch }).click();
    await expect(page.getByPlaceholder(en.Search.versionPlaceholder)).toBeVisible();
    await expectNoHorizontalScroll(page, 'component search');
  });
});

test.describe('dashboard navigation below md', () => {
  test('the sidebar is replaced by a menu button that opens the same links', async ({ page }) => {
    await page.setViewportSize({ width: WIDTH, height: 800 });
    await page.goto('/en/dashboard');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    const toggle = page.getByRole('button', { name: en.Navigation.openMenu });
    await expect(toggle).toBeVisible();
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    // The desktop sidebar's links are not on screen.
    await expect(page.getByRole('link', { name: en.Navigation.audit })).toBeHidden();

    await toggle.click();
    const menu = page.getByRole('dialog', { name: en.Navigation.mainMenu });
    await expect(menu).toBeVisible();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
    // The panel itself fits the viewport.
    const box = (await menu.boundingBox())!;
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(WIDTH);

    // Escape closes it and returns focus to the button.
    await page.keyboard.press('Escape');
    await expect(menu).toBeHidden();
    await expect(toggle).toBeFocused();

    // A link navigates and closes it.
    await toggle.click();
    await menu.getByRole('link', { name: en.Navigation.audit }).click();
    await expect(page).toHaveURL(/\/en\/audit$/);
    await expect(menu).toBeHidden();
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

    // A link to the page already shown closes it too.
    await toggle.click();
    await menu.getByRole('link', { name: en.Navigation.audit }).click();
    await expect(menu).toBeHidden();
  });

  // Codex R1 Medium-1: the menu must not come back after Back / Forward, and
  // must close (focus trap and Escape listener included) when the viewport
  // grows past md while it is open.
  test('Back / Forward and growing past md close the menu for good', async ({ page }) => {
    await page.setViewportSize({ width: WIDTH, height: 800 });
    await page.goto('/en/dashboard');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    const toggle = page.getByRole('button', { name: en.Navigation.openMenu });
    const menu = page.getByRole('dialog', { name: en.Navigation.mainMenu });

    await toggle.click();
    await menu.getByRole('link', { name: en.Navigation.audit }).click();
    await expect(page).toHaveURL(/\/en\/audit$/);
    await toggle.click();
    await expect(menu).toBeVisible();
    await page.goBack();
    await expect(page).toHaveURL(/\/en\/dashboard$/);
    await expect(menu).toHaveCount(0);
    await page.goForward();
    await expect(page).toHaveURL(/\/en\/audit$/);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(menu).toHaveCount(0);

    await toggle.click();
    await expect(menu).toBeVisible();
    await page.setViewportSize({ width: 1280, height: 800 });
    await expect(menu).toHaveCount(0);
    await page.setViewportSize({ width: WIDTH, height: 800 });
    await expect(menu).toHaveCount(0);
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  });

  test('from md up the sidebar is shown and the menu button is not', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/en/dashboard');
    await expect(page.getByRole('heading', { level: 1, name: en.Dashboard.title })).toBeVisible();
    await expect(page.getByRole('link', { name: en.Navigation.audit })).toBeVisible();
    await expect(page.getByRole('button', { name: en.Navigation.openMenu })).toBeHidden();
  });
});

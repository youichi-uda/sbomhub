import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { createVulnerableProject, deleteProject, type VulnerableProject } from './fixtures/vuln-project';

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

async function expectNoHorizontalScroll(page: Page, what: string): Promise<void> {
  const { extra, culprits } = await horizontalOverflow(page);
  expect(extra, `${what} scrolls ${extra}px sideways at ${WIDTH}px:\n  ${culprits.join('\n  ')}`).toBeLessThanOrEqual(0);
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

  test('from md up the sidebar is shown and the menu button is not', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/en/dashboard');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.getByRole('link', { name: en.Navigation.audit })).toBeVisible();
    await expect(page.getByRole('button', { name: en.Navigation.openMenu })).toBeHidden();
  });
});

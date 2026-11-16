import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { lowContrast } from './fixtures/contrast';
import { createVulnerableProject, deleteProject, type VulnerableProject } from './fixtures/vuln-project';

// WCAG 1.4.3 (contrast, AA): text needs 4.5:1 against its background (3:1
// from 24px, or 18.66px bold). Measured on the rendered page, for EVERY
// visible piece of text (e2e/fixtures/contrast.ts says what is exempt).
//
// What this has caught (ratios on the light theme, the only one rendered):
//   - text-yellow-500 1.9:1, text-green-500 2.3:1, white on bg-yellow-500 /
//     bg-green-500 (UPGRADE §33: -700 shades, black on yellow);
//   - white on the red-500 / orange-500 severity badges 3.6 / 2.7:1, red-500
//     / orange-500 severity text 3.8 / 2.8:1 (and 3.1 / 2.5:1 on their -100
//     chips), blue-500 links 3.7:1, the shadcn muted-foreground on --muted
//     4.34:1 (inactive tabs, key chips) (UPGRADE §36).

const SEED_PROJECT = '00000000-0000-0000-0000-000000000010';

async function expectReadable(page: Page, what: string) {
  await page.waitForLoadState('networkidle');
  const failures = await lowContrast(page);
  expect(failures, `${what}: text below WCAG AA contrast`).toEqual([]);
}

async function openPage(page: Page, path: string) {
  await page.goto(path);
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({ timeout: 15_000 });
}

test.describe('text meets WCAG AA contrast', () => {
  let project: VulnerableProject | undefined;
  test.beforeAll(async ({ request }) => {
    project = await createVulnerableProject(request, 'Contrast Project');
  });
  test.afterAll(async ({ request }) => {
    await deleteProject(request, project?.projectId);
  });

  for (const path of [
    '/en/dashboard',
    '/en/projects',
    '/en/analytics',
    '/en/audit',
    '/en/reports',
    '/en/search',
    '/en/settings/apikeys',
    '/en/settings/diff-webhook',
    '/en/settings/integrations',
    '/en/settings/ipa',
    '/en/settings/llm',
    '/en/settings/reports',
    '/en/settings/scan',
    '/en/settings/sso',
    `/en/projects/${SEED_PROJECT}/compliance`,
    `/en/projects/${SEED_PROJECT}/cra-reports`,
    `/en/projects/${SEED_PROJECT}/meti`,
    `/en/projects/${SEED_PROJECT}/triage`,
    '/en/sunset',
    '/en/terms',
    '/en/privacy',
  ]) {
    test(path, async ({ page }) => {
      await openPage(page, path);
      await expectReadable(page, path);
    });
  }

  test('landing page', async ({ page }) => {
    await page.goto('/en');
    await expect(page.locator('h1').first()).toBeVisible({ timeout: 15_000 });
    await expectReadable(page, '/en');
  });

  test('compliance: expanded categories and the checklist', async ({ page }) => {
    await openPage(page, `/en/projects/${SEED_PROJECT}/compliance`);
    for (const name of Object.values(en.Compliance.category)) {
      const trigger = page.locator('button', { hasText: name });
      if ((await trigger.count()) > 0) await trigger.click();
    }
    await expectReadable(page, 'compliance overview, expanded');
    await page.getByRole('tab', { name: en.Compliance.tabChecklist }).click();
    await expectReadable(page, 'compliance checklist');
  });

  test('project page: every tab', async ({ page }) => {
    await page.goto(`/en/projects/${project!.projectId}`);
    await expect(page.getByRole('heading', { level: 1, name: project!.projectName })).toBeVisible();
    await expectReadable(page, 'upload tab');
    await page.getByRole('button', { name: new RegExp(`^${en.Components.title} \\(`) }).click();
    await expectReadable(page, 'components tab');
    await page.getByRole('button', { name: new RegExp(`^${en.Vulnerabilities.title} \\(`) }).click();
    await expect(page.getByTestId('vuln-entry')).toHaveCount(4, { timeout: 15_000 });
    await expectReadable(page, 'vulnerabilities tab (severity badges, remediation chips)');
    for (const [what, name] of [
      ['VEX tab', /^VEX \(/],
      ['license tab', new RegExp(`^${en.Components.license} \\(`)],
      ['notifications tab', new RegExp(`^${en.ProjectDetail.notifications}$`)],
      ['API keys tab', new RegExp(`^${en.ProjectDetail.apiKeys} \\(`)],
    ] as const) {
      await page.getByRole('button', { name }).click();
      await expectReadable(page, what);
    }
  });

  for (const sub of ['triage', 'cra-reports', 'meti', 'diff']) {
    test(`vulnerable project: ${sub}`, async ({ page }) => {
      await page.goto(`/en/projects/${project!.projectId}/${sub}`);
      await expect(page.getByRole('heading').first()).toBeVisible({ timeout: 15_000 });
      await expectReadable(page, sub);
    });
  }

  test('CVE search results (severity badges)', async ({ page }) => {
    await page.goto('/en/search');
    await page.getByPlaceholder(en.Search.cvePlaceholder).fill('CVE-2021-23337');
    await page.getByPlaceholder(en.Search.cvePlaceholder).press('Enter');
    await expect(page.getByText(project!.projectName).first()).toBeVisible({ timeout: 15_000 });
    await expectReadable(page, 'CVE search');
  });
});

// The measurement itself, on fixed markup: a regression in the fixture must
// not turn every test above into a vacuous pass.
test.describe('the contrast measurement', () => {
  const CASES = `
    <div style="background:#fff">
      <p id="red500" style="color:#ef4444">white-bg red-500 3.76</p>
      <p id="red700" style="color:#b91c1c">white-bg red-700 6.47</p>
      <span id="badge" style="background:#f97316;color:#f8fafc">orange badge 2.68</span>
      <span id="tint" style="background:rgb(239 68 68 / 0.1)"><b id="tinted" style="color:#ef4444;font-weight:400">red-500 on red/10 3.3</b></span>
      <span id="oklab" style="background:color-mix(in oklab, #0f172a 80%, transparent)"><i id="onoklab" style="color:#64748b">slate-500 on slate-900/80</i></span>
      <button disabled style="color:#d1d5db">disabled 1.5</button>
      <p id="faded" style="color:#111827;opacity:0.3">faded</p>
      <p style="background-image:linear-gradient(#000,#fff);color:#777">over a gradient</p>
      <p id="big" style="color:#ef4444;font-size:24px">large red-500 3.76</p>
    </div>`;

  test('reports what fails, with its ratio, and only that', async ({ page }) => {
    await page.setContent(CASES);
    const failures = await lowContrast(page);
    const byText = Object.fromEntries(failures.map((f) => [f.text, f.ratio]));
    expect(byText).toEqual({
      'white-bg red-500 3.76': 3.76,
      'orange badge 2.68': 2.68,
      'red-500 on red/10 3.3': 3.3,
      'slate-500 on slate-900/80': expect.any(Number),
      faded: expect.any(Number),
    });
    expect(byText['slate-500 on slate-900/80']).toBeLessThan(4.5);
    expect(byText.faded).toBeLessThan(4.5);
  });
});

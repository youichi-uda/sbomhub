import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { API_BASE_URL, createVulnerableProject, deleteProject, type VulnerableProject } from './fixtures/vuln-project';

// The project page's Components, VEX and License tabs rendered their normal
// empty state ("No components found…", "No VEX statements…", "No license
// policies…") when their own GET failed, and the tab counters read "(0)" —
// an outage of one route looked like an empty project. The notification tab
// rendered its form with DEFAULT values (Critical + High, no webhooks) over a
// failed load, so Save would have overwritten the real settings. Each tab now
// shows an error with Retry; its counter says the load failed.
//
// Only the one route under test fails (the project itself loads), unlike
// project-load-error.spec.ts, which fails the project too.

const T = en.ProjectDetail;

/** Answers 500 to GETs of exactly `path` while `state.fail` is true. */
async function failGet(page: Page, path: string, state: { fail: boolean }) {
  await page.route(
    (url) => url.pathname === path,
    (route) =>
      route.request().method() === 'GET' && state.fail
        ? route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'internal error' }) })
        : route.fallback(),
  );
}

function tabButton(page: Page, label: string) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return page.getByRole('button', { name: new RegExp(`^${escaped}( \\(.*\\))?$`) });
}

test.describe('project page: one tab’s own load fails', () => {
  let project: VulnerableProject | undefined;

  test.beforeAll(async ({ request }) => {
    project = await createVulnerableProject(request, 'Tab Load Error Project');
    // One VEX statement and one license policy, so a recovered tab has rows
    // (and its counter a non-zero count) to come back to.
    const vex = await request.post(`${API_BASE_URL}/api/v1/projects/${project.projectId}/vex`, {
      data: { vulnerability_id: project.vuln('CVE-2021-44228').id, status: 'under_investigation' },
    });
    expect(vex.status(), `VEX create: ${await vex.text()}`).toBe(201);
    const policy = await request.post(`${API_BASE_URL}/api/v1/projects/${project.projectId}/licenses`, {
      data: { license_id: 'MIT', license_name: 'MIT License', policy_type: 'allowed' },
    });
    expect(policy.status(), `license policy create: ${await policy.text()}`).toBe(201);
  });
  test.afterAll(async ({ request }) => {
    await deleteProject(request, project?.projectId);
  });

  const CASES = [
    {
      name: 'components',
      route: 'components',
      tab: en.Components.title,
      testId: 'components-load-error',
      message: T.componentsLoadFailed,
      empty: T.noComponents,
      recovered: (page: Page) => expect(page.locator('main table tbody tr')).toHaveCount(2),
      count: 2,
    },
    {
      name: 'VEX',
      route: 'vex',
      tab: 'VEX',
      testId: 'vex-load-error',
      message: T.vexLoadFailed,
      empty: T.noVexStatements,
      recovered: (page: Page) => expect(page.getByText('CVE-2021-44228', { exact: true })).toBeVisible(),
      count: 1,
    },
    {
      name: 'license policies',
      route: 'licenses',
      tab: en.Components.license,
      testId: 'license-policies-load-error',
      message: T.licensePoliciesLoadFailed,
      empty: T.noLicensePolicies,
      recovered: (page: Page) => expect(page.getByText('MIT License', { exact: true })).toBeVisible(),
      count: 1,
    },
    {
      name: 'API keys',
      route: 'apikeys',
      tab: T.apiKeys,
      testId: 'project-apikeys-load-error',
      message: T.apiKeysLoadFailed,
      empty: T.noApiKeys,
      recovered: (page: Page) => expect(page.getByText(T.noApiKeys, { exact: true })).toBeVisible(),
      count: 0,
    },
  ];

  for (const c of CASES) {
    test(`${c.name}: an error with Retry, not the empty state, and no "(0)" on the tab`, async ({ page }) => {
      const state = { fail: true };
      await failGet(page, `/api/v1/projects/${project!.projectId}/${c.route}`, state);
      await page.goto(`/en/projects/${project!.projectId}`);
      await expect(page.getByRole('heading', { level: 1, name: project!.projectName })).toBeVisible();

      // The counter says the load failed — never a count.
      const tab = tabButton(page, c.tab);
      await expect(tab).toHaveText(new RegExp(`\\(${en.ProjectDetail.tabCountLoadFailed}\\)$`));
      await expect(tab).not.toHaveText(/\(\d+\)$/);

      await tab.click();
      const error = page.getByTestId(c.testId);
      await expect(error).toBeVisible();
      await expect(error).toContainText(c.message);
      await expect(page.getByText(c.empty, { exact: true })).toHaveCount(0);

      // The route recovers: Retry loads the real list and the real count.
      state.fail = false;
      await error.getByRole('button', { name: en.Common.retry }).click();
      await expect(error).toHaveCount(0);
      await c.recovered(page);
      await expect(tab).toHaveText(new RegExp(`\\(${c.count}\\)$`));
    });
  }

  test('a refetch that fails keeps the rows under a banner, and the count is marked', async ({ page }) => {
    const state = { fail: false };
    await failGet(page, `/api/v1/projects/${project!.projectId}/components`, state);
    await page.goto(`/en/projects/${project!.projectId}`);
    const tab = tabButton(page, en.Components.title);
    await expect(tab).toHaveText(/\(2\)$/);
    await tab.click();
    await expect(page.locator('main table tbody tr')).toHaveCount(2);

    // Leave and come back: the tab refetches, and that refetch fails.
    state.fail = true;
    await tabButton(page, 'VEX').click();
    await tab.click();
    const banner = page.getByTestId('components-load-error');
    await expect(banner).toBeVisible();
    await expect(page.locator('main table tbody tr')).toHaveCount(2);
    await expect(tab).toHaveText(new RegExp(`\\(${en.ProjectDetail.tabCountRefreshFailed.replace('{count}', '2')}\\)$`));
  });

  // Codex R3 Low: while the API key list was still loading, the tab body
  // said "No API keys" (the counter already said "…").
  test('API keys: a slow load shows loading, not "no API keys"', async ({ page }) => {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    await page.route(
      (url) => url.pathname === `/api/v1/projects/${project!.projectId}/apikeys`,
      async (route) => {
        if (route.request().method() !== 'GET') return route.fallback();
        await held;
        return route.fallback();
      },
    );
    await page.goto(`/en/projects/${project!.projectId}`);
    await expect(page.getByRole('heading', { level: 1, name: project!.projectName })).toBeVisible();
    const tab = tabButton(page, T.apiKeys);
    await expect(tab).toHaveText(/\(…\)$/);
    await tab.click();
    await expect(page.getByText(en.Common.loading, { exact: true })).toBeVisible();
    await expect(page.getByText(T.noApiKeys, { exact: true })).toHaveCount(0);
    release();
    await expect(page.getByText(T.noApiKeys, { exact: true })).toBeVisible();
    await expect(tab).toHaveText(/\(0\)$/);
  });

  test('notifications: a failed settings load is an error, not a form of defaults that Save would write', async ({ page }) => {
    const state = { fail: true };
    const path = `/api/v1/projects/${project!.projectId}/notifications`;
    await failGet(page, path, state);
    const writes: string[] = [];
    page.on('request', (r) => {
      if (new URL(r.url()).pathname === path && r.method() !== 'GET') writes.push(r.method());
    });
    await page.goto(`/en/projects/${project!.projectId}`);
    await expect(page.getByRole('heading', { level: 1, name: project!.projectName })).toBeVisible();
    await tabButton(page, T.notifications).click();

    const error = page.getByTestId('notification-settings-load-error');
    await expect(error).toBeVisible();
    await expect(error).toContainText(T.notificationSettingsLoadFailed);
    // No editable form (and so no Save) over the failed load.
    await expect(page.locator('input[name="slack_webhook"]')).toHaveCount(0);
    await expect(page.getByRole('button', { name: en.Common.save, exact: true })).toHaveCount(0);
    expect(writes).toEqual([]);

    state.fail = false;
    await error.getByRole('button', { name: en.Common.retry }).click();
    await expect(error).toHaveCount(0);
    await expect(page.locator('input[name="slack_webhook"]')).toBeVisible();
  });

  test('notifications: a failed history load is shown, not an empty history', async ({ page }) => {
    const state = { fail: true };
    await failGet(page, `/api/v1/projects/${project!.projectId}/notifications/logs`, state);
    await page.goto(`/en/projects/${project!.projectId}`);
    await expect(page.getByRole('heading', { level: 1, name: project!.projectName })).toBeVisible();
    await tabButton(page, T.notifications).click();
    const error = page.getByTestId('notification-logs-load-error');
    await expect(error).toBeVisible();
    await expect(error).toContainText(T.notificationLogsLoadFailed);
    // The settings form itself loaded fine and stays usable.
    await expect(page.locator('input[name="slack_webhook"]')).toBeVisible();

    state.fail = false;
    await error.getByRole('button', { name: en.Common.retry }).click();
    await expect(error).toHaveCount(0);
  });
});

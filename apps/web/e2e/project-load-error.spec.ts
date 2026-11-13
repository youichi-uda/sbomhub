import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import {
  createProject,
  createVulnerableProject,
  deleteProject,
  FIXTURE_CVES,
  uniqueName,
  type VulnerableProject,
} from './fixtures/vuln-project';

// GET /api/v1/projects/:id answers 404 only for a missing project (or another
// tenant's) and 500 {"error":"failed to get project"} for a database failure.
// The project page rendered "Project not found" for ANY failed load, so a DB
// outage told the operator the project had been deleted. A 404 still says
// not found; anything else is a load error with a Retry that recovers.

/** Fails only the project's own GET (not /components, /vulnerabilities, ...). */
async function failProjectGet(page: Page, projectId: string, status: number, body: object) {
  const path = `/api/v1/projects/${projectId}`;
  await page.route(
    (url) => url.pathname === path,
    (route) =>
      route.request().method() === 'GET'
        ? route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
        : route.fallback(),
  );
  return path;
}

test.describe('project page load failures', () => {
  let projectId: string | undefined;
  let projectName: string;

  test.beforeAll(async ({ request }) => {
    projectName = uniqueName('Load Error Project');
    projectId = (await createProject(request, projectName)).id;
  });
  test.afterAll(async ({ request }) => {
    await deleteProject(request, projectId);
  });

  test('a 500 is a load error with Retry, not "Project not found"', async ({ page }) => {
    await failProjectGet(page, projectId!, 500, { error: 'failed to get project' });
    await page.goto(`/en/projects/${projectId}`);

    const alert = page.getByTestId('project-load-error');
    await expect(alert).toBeVisible();
    await expect(alert).toContainText(en.Common.projectLoadFailed);
    await expect(page.getByText(en.Common.projectNotFound, { exact: true })).toHaveCount(0);

    // The outage ends: Retry loads the real project.
    await page.unrouteAll();
    await alert.getByRole('button', { name: en.Common.retry }).click();
    await expect(page.getByRole('heading', { level: 1, name: projectName })).toBeVisible();
    await expect(alert).toHaveCount(0);
  });

  test('a network failure is a load error too', async ({ page }) => {
    await page.route(
      (url) => url.pathname === `/api/v1/projects/${projectId}`,
      (route) => (route.request().method() === 'GET' ? route.abort('connectionrefused') : route.fallback()),
    );
    await page.goto(`/en/projects/${projectId}`);
    await expect(page.getByTestId('project-load-error')).toBeVisible();
    await expect(page.getByText(en.Common.projectNotFound, { exact: true })).toHaveCount(0);
  });

  test('a 404 still says "Project not found", without a Retry', async ({ page }) => {
    await failProjectGet(page, projectId!, 404, { error: 'project not found' });
    await page.goto(`/en/projects/${projectId}`);
    await expect(page.getByText(en.Common.projectNotFound, { exact: true })).toBeVisible();
    await expect(page.getByTestId('project-load-error')).toHaveCount(0);
  });

  test('a malformed project id (API 400) is "Project not found", without a Retry', async ({ page }) => {
    // The API answers 400 {"error":"invalid project id"}: no project can
    // exist at that URL, so retrying cannot help.
    await page.goto('/en/projects/not-a-project-id');
    await expect(page.getByText(en.Common.projectNotFound, { exact: true })).toBeVisible();
    await expect(page.getByTestId('project-load-error')).toHaveCount(0);
  });

  test('an unknown project id is "Project not found" from the real API', async ({ page }) => {
    await page.goto('/en/projects/00000000-0000-0000-0000-00000000dead');
    await expect(page.getByText(en.Common.projectNotFound, { exact: true })).toBeVisible();
    await expect(page.getByTestId('project-load-error')).toHaveCount(0);
  });
});

// Integration Codex review 2026-11-13 (Medium): Retry refetched only the
// project's own GET. In a real outage EVERY project route fails at once, and
// react-query retries are off (src/lib/query/client.ts), so after the API
// recovered the components / vulnerabilities / VEX / ... queries stayed
// failed and the tabs showed zero. Retry now refetches all of them.
test.describe('project page: full outage, then Retry', () => {
  let project: VulnerableProject | undefined;

  test.beforeAll(async ({ request }) => {
    project = await createVulnerableProject(request, 'Full Outage Project');
  });
  test.afterAll(async ({ request }) => {
    await deleteProject(request, project?.projectId);
  });

  test('every project route fails, the API recovers: Retry restores every tab', async ({ page }) => {
    const prefix = `/api/v1/projects/${project!.projectId}`;
    const failed = new Set<string>();
    await page.route(
      (url) => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`),
      (route) => {
        if (route.request().method() !== 'GET') return route.fallback();
        failed.add(new URL(route.request().url()).pathname);
        return route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'internal error' }) });
      },
    );
    await page.goto(`/en/projects/${project!.projectId}`);
    const alert = page.getByTestId('project-load-error');
    await expect(alert).toBeVisible();
    // The outage really covered the sibling routes, not just the project.
    await expect.poll(() => failed.size).toBeGreaterThan(3);
    // (the vulnerability list is read after the latest SBOM, which failed)
    expect([...failed]).toEqual(expect.arrayContaining([`${prefix}/components`, `${prefix}/sbom`]));

    await page.unrouteAll();
    await alert.getByRole('button', { name: en.Common.retry }).click();
    await expect(page.getByRole('heading', { level: 1, name: project!.projectName })).toBeVisible();
    // Counts come from the sibling queries: without the fix they stay 0.
    await expect(page.getByRole('button', { name: `${en.Components.title} (2)` })).toBeVisible();
    await expect(
      page.getByRole('button', { name: `${en.Vulnerabilities.title} (${FIXTURE_CVES.length})` }),
    ).toBeVisible();
    // And the scan status recovered too: no "could not load" notice left.
    await expect(page.locator('[data-scan-state="unavailable"]')).toHaveCount(0);
  });

  // Codex R1 Medium: the project GET fails fast while sibling requests are
  // still in flight. Retry must not reuse those (react-query v5 hands back a
  // no-data in-flight request): they fail after the API has recovered.
  test('sibling requests still in flight at Retry are not reused', async ({ page }) => {
    const prefix = `/api/v1/projects/${project!.projectId}`;
    let outage = true;
    let release: () => void = () => {};
    const held = new Promise<void>((r) => (release = r));
    let heldCount = 0;
    await page.route(
      (url) => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`),
      async (route) => {
        if (route.request().method() !== 'GET' || !outage) return route.fallback();
        const body = { status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'internal error' }) };
        if (new URL(route.request().url()).pathname === prefix) return route.fulfill(body);
        heldCount++;
        await held; // answered (500) only after Retry
        return route.fulfill(body);
      },
    );
    await page.goto(`/en/projects/${project!.projectId}`);
    const alert = page.getByTestId('project-load-error');
    await expect(alert).toBeVisible();
    await expect.poll(() => heldCount).toBeGreaterThan(3);

    outage = false;
    await alert.getByRole('button', { name: en.Common.retry }).click();
    await expect(page.getByRole('heading', { level: 1, name: project!.projectName })).toBeVisible();
    release();
    await expect(page.getByRole('button', { name: `${en.Components.title} (2)` })).toBeVisible();
    await expect(
      page.getByRole('button', { name: `${en.Vulnerabilities.title} (${FIXTURE_CVES.length})` }),
    ).toBeVisible();
    // and they stay right after the stale 500s have landed
    await page.waitForTimeout(1_000);
    await expect(page.getByRole('button', { name: `${en.Components.title} (2)` })).toBeVisible();
  });
});

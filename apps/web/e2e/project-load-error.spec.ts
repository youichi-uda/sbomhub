import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { createProject, deleteProject, uniqueName } from './fixtures/vuln-project';

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

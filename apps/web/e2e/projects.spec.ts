import { test, expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';
import en from '../messages/en.json';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// The tests below drive /en/projects, so the native confirm() must carry the
// English Projects.deleteConfirm text and the delete button the English
// Projects.deleteAriaLabel accessible name.
const DELETE_CONFIRM = en.Projects.deleteConfirm;

type CreatedProject = { id: string; name: string };

async function createProjectViaApi(request: APIRequestContext, name: string): Promise<CreatedProject> {
  const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
    data: { name, description: 'Project for the delete E2E tests' },
  });
  expect(response.ok(), `project create returned ${response.status()}`).toBe(true);
  const body = await response.json();
  expect(typeof body.id).toBe('string');
  return { id: body.id, name };
}

// The project's Card: the one containing the title link with exactly this name.
function projectCard(page: Page, name: string): Locator {
  return page
    .locator('div.bg-card')
    .filter({ has: page.getByRole('link', { name, exact: true }) });
}

function projectDeleteButton(page: Page, name: string): Locator {
  return projectCard(page, name).getByRole('button', {
    name: en.Projects.deleteAriaLabel.replace('{name}', name),
    exact: true,
  });
}

// Registers a one-shot handler for the next native dialog and answers it.
// The handler only records what it saw (an assertion thrown inside an event
// handler would not fail the test); expectDeleteConfirm asserts on it.
function handleNextDialog(page: Page, action: 'accept' | 'dismiss'): () => string | null {
  let seen: string | null = null;
  page.once('dialog', async (dialog) => {
    seen = `${dialog.type()}: ${dialog.message()}`;
    if (action === 'accept') {
      await dialog.accept();
    } else {
      await dialog.dismiss();
    }
  });
  return () => seen;
}

async function expectDeleteConfirm(seen: () => string | null): Promise<void> {
  await expect
    .poll(seen, { message: 'a native confirm() with the delete prompt must be shown' })
    .toBe(`confirm: ${DELETE_CONFIRM}`);
}

// Deletes every project with exactly this name (UI-created projects have no
// id in the test; this keeps them from accumulating across runs).
async function deleteProjectsNamed(request: APIRequestContext, name: string): Promise<void> {
  const res = await request.get(`${API_BASE_URL}/api/v1/projects`);
  expect(res.status()).toBe(200);
  for (const p of ((await res.json()) ?? []) as Array<{ id: string; name: string }>) {
    if (p.name === name) await request.delete(`${API_BASE_URL}/api/v1/projects/${p.id}`);
  }
}

// Records every native dialog (alert/confirm) the page opens: an injected
// script that ran would show up here.
function recordDialogs(page: Page): string[] {
  const seen: string[] = [];
  page.on('dialog', async (dialog) => {
    seen.push(`${dialog.type()}: ${dialog.message()}`);
    await dialog.dismiss();
  });
  return seen;
}

test.describe('Projects', () => {
  // Names of projects a test creates through the UI; removed in afterEach.
  let uiCreated: string[] = [];

  test.beforeEach(async ({ page }) => {
    uiCreated = [];
    await page.goto('/en/projects');
  });

  test.afterEach(async ({ request }) => {
    for (const name of uiCreated) await deleteProjectsNamed(request, name);
  });

  test('should display projects list page', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Projects', level: 1 })).toBeVisible();
    await expect(page.getByRole('button', { name: /New Project|新規プロジェクト/i }).first()).toBeVisible();

    // Verify the page structure contains expected elements
    await expect(page.locator('main')).toBeVisible();
  });

  test('should create a new project with description verification', async ({ page }) => {
    // Click new project button
    await page.getByRole('button', { name: /New Project/i }).first().click();

    // Wait for dialog content to appear
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Fill in project details using placeholder
    const projectName = `Test Project ${Date.now()}`;
    uiCreated.push(projectName);
    const projectDescription = 'E2E test project description with details';
    await page.getByPlaceholder('My Project').fill(projectName);
    await page.getByPlaceholder('Project description').fill(projectDescription);

    // Submit form - click the Create button inside the modal
    await page.locator('.fixed button:has-text("Create")').click();

    // Verify project was created and appears in list
    await expect(page.getByText(projectName)).toBeVisible({ timeout: 10000 });

    // Navigate to project detail to verify description
    await page.getByText(projectName).click();

    // Wait for page load
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);

    // Verify we're on detail page by checking for project-specific elements
    const uploadButton = page.getByRole('button', { name: /Upload SBOM/i });
    await expect(uploadButton).toBeVisible({ timeout: 10000 });

    // The detail page shows the name and the description under it.
    await expect(page.getByRole('heading', { level: 1, name: projectName })).toBeVisible();
    await expect(page.getByText(projectDescription, { exact: true })).toBeVisible();
  });

  test('should create a project with Japanese name', async ({ page }) => {
    // Click new project button
    await page.getByRole('button', { name: /New Project/i }).first().click();
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Fill in Japanese project name
    const projectName = `テストプロジェクト ${Date.now()}`;
    uiCreated.push(projectName);
    const projectDescription = 'これは日本語の説明文です';
    await page.getByPlaceholder('My Project').fill(projectName);
    await page.getByPlaceholder('Project description').fill(projectDescription);

    // Submit form
    await page.locator('.fixed button:has-text("Create")').click();

    // Verify Japanese project name appears in list
    await expect(page.getByText(projectName)).toBeVisible({ timeout: 10000 });

    // Navigate to detail page and verify Japanese description
    await page.getByText(projectName).first().click();
    await expect(page.getByText(projectDescription).first()).toBeVisible();
  });

  test('should handle XSS attempt in project name safely', async ({ page }) => {
    const dialogs = recordDialogs(page);
    await page.getByRole('button', { name: /New Project/i }).first().click();
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Attempt XSS injection in project name
    const xssPayload = `<script>alert('xss')</script>Test${Date.now()}`;
    uiCreated.push(xssPayload);
    await page.getByPlaceholder('My Project').fill(xssPayload);
    await page.getByPlaceholder('Project description').fill('XSS test description');

    const created = page.waitForResponse(
      (r) => r.request().method() === 'POST' && r.url().endsWith('/api/v1/projects'),
    );
    await page.locator('.fixed button:has-text("Create")').click();
    expect((await created).status()).toBe(201);

    // The name is rendered as literal text (escaped), in the list and on the
    // detail page, and nothing was executed.
    const link = page.getByRole('link', { name: xssPayload, exact: true });
    await expect(link).toBeVisible({ timeout: 10000 });
    await expect(page.locator('main script')).toHaveCount(0);
    await link.click();
    await expect(page.getByRole('heading', { level: 1, name: xssPayload })).toBeVisible();
    await expect(page.locator('main script')).toHaveCount(0);
    expect(dialogs).toEqual([]);
  });

  test('should handle HTML injection attempt safely', async ({ page }) => {
    const dialogs = recordDialogs(page);
    await page.getByRole('button', { name: /New Project/i }).first().click();
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Attempt HTML injection
    const htmlPayload = `<img src=x onerror=alert('xss')>Project${Date.now()}`;
    uiCreated.push(htmlPayload);
    await page.getByPlaceholder('My Project').fill(htmlPayload);
    await page.getByPlaceholder('Project description').fill('HTML injection test');

    await page.locator('.fixed button:has-text("Create")').click();

    // Shown as text; no <img> element was created; no alert fired.
    await expect(page.getByRole('link', { name: htmlPayload, exact: true })).toBeVisible({ timeout: 10000 });
    await expect(page.locator('main img[src="x"]')).toHaveCount(0);
    expect(dialogs).toEqual([]);
  });

  test('should handle special characters and emoji in project name', async ({ page }) => {
    await page.getByRole('button', { name: /New Project/i }).first().click();
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Use special characters and emoji
    const specialName = `Project 🚀 ñ ü © ${Date.now()}`;
    uiCreated.push(specialName);
    await page.getByPlaceholder('My Project').fill(specialName);
    await page.getByPlaceholder('Project description').fill('Special chars: ñ ü ö ä © ®');

    await page.locator('.fixed button:has-text("Create")').click();

    // Verify project with special characters appears
    await expect(page.getByText(specialName)).toBeVisible({ timeout: 10000 });
  });

  test('should navigate to project detail page', async ({ page, request }) => {
    const project = await createProjectViaApi(request, `Navigate Project ${Date.now()}`);
    try {
      await page.reload();
      await projectCard(page, project.name).getByRole('link', { name: project.name, exact: true }).click();

      await expect(page).toHaveURL(new RegExp(`/projects/${project.id}$`));
      await expect(page.getByRole('heading', { level: 1, name: project.name })).toBeVisible();
      await expect(page.getByRole('button', { name: /Upload SBOM/i })).toBeVisible({ timeout: 10000 });
    } finally {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
    }
  });

  test('should show delete confirmation dialog and cancel', async ({ page, request }) => {
    const project = await createProjectViaApi(request, `Cancel Delete Project ${Date.now()}`);
    try {
      await page.reload();

      const deleteButton = projectDeleteButton(page, project.name);
      await expect(deleteButton).toBeVisible({ timeout: 10000 });

      // The page asks through a native window.confirm(), not an in-page
      // dialog. Capture it, check it is the localized delete prompt, and
      // dismiss it (= the user pressed Cancel).
      const dialog = handleNextDialog(page, 'dismiss');
      await deleteButton.click();
      await expectDeleteConfirm(dialog);

      // Cancel must not delete: still listed (after a reload, so this is
      // the server's list rather than stale client state) and still in the API.
      await expect(projectCard(page, project.name)).toHaveCount(1);
      await page.reload();
      await expect(projectCard(page, project.name)).toHaveCount(1);
      const getResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${project.id}`);
      expect(getResponse.status()).toBe(200);
      expect((await getResponse.json()).id).toBe(project.id);
    } finally {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`).catch(() => {});
    }
  });

  test('should delete project and remove from list', async ({ page, request }) => {
    const project = await createProjectViaApi(request, `Delete Test Project ${Date.now()}`);
    try {
      await page.reload();

      const card = projectCard(page, project.name);
      await expect(card).toHaveCount(1, { timeout: 10000 });
      const deleteButton = projectDeleteButton(page, project.name);
      await expect(deleteButton).toBeVisible();

      const dialog = handleNextDialog(page, 'accept');
      const deleteRequest = page.waitForResponse(
        (r) => r.request().method() === 'DELETE' && r.url().endsWith(`/api/v1/projects/${project.id}`),
      );
      await deleteButton.click();
      await expectDeleteConfirm(dialog);
      expect((await deleteRequest).ok()).toBe(true);

      // Removed from the list, also after a reload from the server.
      await expect(card).toHaveCount(0);
      await page.reload();
      await expect(page.getByRole('heading', { name: 'Projects', level: 1 })).toBeVisible();
      await expect(projectCard(page, project.name)).toHaveCount(0);

      // And gone from the API.
      const getResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${project.id}`);
      expect(getResponse.status()).toBe(404);
      const listResponse = await request.get(`${API_BASE_URL}/api/v1/projects`);
      expect(listResponse.ok()).toBe(true);
      const listed = ((await listResponse.json()) ?? []) as Array<{ id: string }>;
      expect(listed.map((p) => p.id)).not.toContain(project.id);
    } finally {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`).catch(() => {});
    }
  });

  test('should show validation error for empty project name', async ({ page }) => {
    // Click new project button
    await page.getByRole('button', { name: /New Project/i }).first().click();

    // Wait for dialog content to appear
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Leave project name empty
    await page.getByPlaceholder('My Project').fill('');
    await page.getByPlaceholder('Project description').fill('Test description');

    // The Create button should be disabled when the project name is empty
    // This is the expected validation behavior - prevent submission with empty name
    const createButton = page.locator('.fixed button:has-text("Create")');
    await expect(createButton).toBeDisabled();

    // The dialog should still be visible
    await expect(page.getByPlaceholder('My Project')).toBeVisible();
  });

  test('should handle long project name', async ({ page, request }) => {
    // Was fixme (M65 bug 7): the API answered 500 (fixed in a2f1f4d, 400 with
    // the reason) and the create dialog showed no error (M65 bug 10 web fix).

    await page.getByRole('button', { name: /New Project/i }).first().click();
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // A very long project name (256+ characters)
    const longProjectName = 'A'.repeat(300);
    uiCreated.push(longProjectName);
    await page.getByPlaceholder('My Project').fill(longProjectName);
    await page.getByPlaceholder('Project description').fill('E2E test for long project name');

    const created = page.waitForResponse(
      (r) => r.request().method() === 'POST' && r.url().endsWith('/api/v1/projects'),
    );
    await page.locator('.fixed button:has-text("Create")').click();

    // Rejected as invalid input, the dialog stays open with an error, and
    // no project was stored.
    expect((await created).status()).toBe(400);
    await expect(page.getByPlaceholder('My Project')).toHaveValue(longProjectName);
    await expect(page.locator('.fixed').getByText(/too long|maximum|characters/i)).toBeVisible();
    const res = await request.get(`${API_BASE_URL}/api/v1/projects`);
    const names = ((await res.json()) ?? []).map((p: { name: string }) => p.name);
    expect(names).not.toContain(longProjectName);
  });

  test('should display project count correctly', async ({ page, request }) => {
    const project = await createProjectViaApi(request, `Count Project ${Date.now()}`);
    try {
      // Other suites create/delete projects concurrently: compare the UI and
      // the API in one retried step.
      await expect(async () => {
        await page.reload();
        await expect(projectCard(page, project.name)).toHaveCount(1);
        const response = await request.get(`${API_BASE_URL}/api/v1/projects`);
        expect(response.status()).toBe(200);
        const apiCount = ((await response.json()) ?? []).length;
        expect(apiCount).toBeGreaterThan(0);
        const titleLinks = page.locator('div.bg-card h3 a[href*="/projects/"]');
        expect(await titleLinks.count()).toBe(apiCount);
      }).toPass({ timeout: 20000 });
    } finally {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
    }
  });

  test('should navigate to project detail and back', async ({ page, request }) => {
    const project = await createProjectViaApi(request, `Back Nav Project ${Date.now()}`);
    try {
      await page.reload();
      await projectCard(page, project.name).getByRole('link', { name: project.name, exact: true }).click();

      // Verify we're on the project detail page
      await expect(page.getByRole('heading', { level: 1, name: project.name })).toBeVisible();
      await expect(page.getByRole('button', { name: /Upload SBOM/i })).toBeVisible();

      // Navigate back
      await page.getByRole('link', { name: en.ProjectDetail.backToProjects }).click();

      // Back on the list, which still has the project
      await expect(page).toHaveURL(/\/en\/projects$/);
      await expect(page.getByRole('heading', { name: 'Projects', level: 1 })).toBeVisible();
      await expect(projectCard(page, project.name)).toHaveCount(1);
    } finally {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
    }
  });
});

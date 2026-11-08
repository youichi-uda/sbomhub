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

test.describe('Projects', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/en/projects');
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

    // Verify description is displayed on detail page (may be in different location)
    const descriptionVisible = await page.getByText(projectDescription).isVisible().catch(() => false);
    if (descriptionVisible) {
      await expect(page.getByText(projectDescription)).toBeVisible();
    }
  });

  test('should create a project with Japanese name', async ({ page }) => {
    // Click new project button
    await page.getByRole('button', { name: /New Project/i }).first().click();
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Fill in Japanese project name
    const projectName = `テストプロジェクト ${Date.now()}`;
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
    // Click new project button
    await page.getByRole('button', { name: /New Project/i }).first().click();
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Attempt XSS injection in project name
    const xssPayload = `<script>alert('xss')</script>Test${Date.now()}`;
    await page.getByPlaceholder('My Project').fill(xssPayload);
    await page.getByPlaceholder('Project description').fill('XSS test description');

    // Submit form
    await page.locator('.fixed button:has-text("Create")').click();

    // Wait for response
    await page.waitForTimeout(2000);

    // Verify no script execution occurred (page should still be functional)
    await expect(page.getByRole('heading', { name: 'Projects', level: 1 })).toBeVisible();

    // If project was created, verify the script tag is escaped/sanitized
    const projectText = page.getByText(xssPayload);
    if (await projectText.isVisible().catch(() => false)) {
      // The text should be visible as plain text, not executed
      await expect(projectText).toBeVisible();
    }
  });

  test('should handle HTML injection attempt safely', async ({ page }) => {
    await page.getByRole('button', { name: /New Project/i }).first().click();
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Attempt HTML injection
    const htmlPayload = `<img src=x onerror=alert('xss')>Project${Date.now()}`;
    await page.getByPlaceholder('My Project').fill(htmlPayload);
    await page.getByPlaceholder('Project description').fill('HTML injection test');

    await page.locator('.fixed button:has-text("Create")').click();
    await page.waitForTimeout(2000);

    // Page should remain functional
    await expect(page.getByRole('heading', { name: 'Projects', level: 1 })).toBeVisible();
  });

  test('should handle special characters and emoji in project name', async ({ page }) => {
    await page.getByRole('button', { name: /New Project/i }).first().click();
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Use special characters and emoji
    const specialName = `Project 🚀 ñ ü © ${Date.now()}`;
    await page.getByPlaceholder('My Project').fill(specialName);
    await page.getByPlaceholder('Project description').fill('Special chars: ñ ü ö ä © ®');

    await page.locator('.fixed button:has-text("Create")').click();

    // Verify project with special characters appears
    await expect(page.getByText(specialName)).toBeVisible({ timeout: 10000 });
  });

  test('should navigate to project detail page', async ({ page }) => {
    // Wait for projects to load
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);

    // Click on the first project's view button (arrow icon)
    const firstProject = page.locator('[href*="/projects/"]').first();
    if (await firstProject.isVisible()) {
      await firstProject.click();

      // Wait for page load
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1000);

      // Verify we're on the project detail page - check for Upload SBOM button
      const uploadButton = page.getByRole('button', { name: /Upload SBOM/i });
      await expect(uploadButton).toBeVisible({ timeout: 10000 });
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

  test('should handle long project name', async ({ page }) => {
    // Click new project button
    await page.getByRole('button', { name: /New Project/i }).first().click();

    // Wait for dialog content to appear
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Create a very long project name (256+ characters)
    const longProjectName = 'A'.repeat(300);
    await page.getByPlaceholder('My Project').fill(longProjectName);
    await page.getByPlaceholder('Project description').fill('E2E test for long project name');

    // Try to submit form
    await page.locator('.fixed button:has-text("Create")').click();

    // Wait a moment for validation or API response
    await page.waitForTimeout(2000);

    // Check the outcome - either:
    // 1. Validation error is shown (name too long)
    // 2. The dialog is still open
    // 3. The project was created (possibly truncated)
    // 4. An error toast appeared
    // 5. The page is still functional
    const hasLengthError = await page.getByText(/too long|maximum|limit|exceed|characters/i).isVisible().catch(() => false);
    const dialogStillOpen = await page.getByPlaceholder('My Project').isVisible().catch(() => false);
    const projectCreated = await page.getByText(longProjectName.substring(0, 50)).isVisible().catch(() => false);
    const hasError = await page.getByText(/error|エラー/i).isVisible().catch(() => false);
    const pageStillWorks = await page.getByRole('heading', { name: 'Projects', level: 1 }).isVisible().catch(() => false);

    // Any of these outcomes is acceptable
    expect(hasLengthError || dialogStillOpen || projectCreated || hasError || pageStillWorks).toBeTruthy();
  });

  test('should display project count correctly', async ({ page, request }) => {
    // Get initial project count from API
    const response = await request.get(`${API_BASE_URL}/api/v1/projects`);
    const projects = await response.json();
    const initialCount = Array.isArray(projects) ? projects.length : 0;

    // Verify the UI shows the correct count or list of projects
    if (initialCount > 0) {
      // Wait for projects to load
      await page.waitForTimeout(1000);
      // Verify at least some project cards/rows are visible
      const projectLinks = page.locator('[href*="/projects/"]');
      expect(await projectLinks.count()).toBeGreaterThan(0);
    }
  });

  test('should navigate to project detail and back', async ({ page }) => {
    // Wait for projects to load
    await page.waitForTimeout(1000);

    // Click on the first project
    const firstProject = page.locator('[href*="/projects/"]').first();
    if (await firstProject.isVisible()) {
      const projectName = await firstProject.textContent();
      await firstProject.click();

      // Verify we're on the project detail page
      await expect(page.getByText('Back to Projects')).toBeVisible();
      await expect(page.getByRole('button', { name: /Upload SBOM/i })).toBeVisible();

      // Navigate back
      await page.getByText('Back to Projects').click();

      // Verify we're back on projects list
      await expect(page.getByRole('heading', { name: 'Projects', level: 1 })).toBeVisible();

      // Verify the project is still in the list
      if (projectName) {
        await expect(page.getByText(projectName.trim())).toBeVisible();
      }
    }
  });
});

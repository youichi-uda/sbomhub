import { test, expect } from '@playwright/test';

test.describe('Projects', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/en/projects');
  });

  test('should display projects list page', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();
    await expect(page.getByRole('button', { name: /New Project|新規プロジェクト/i })).toBeVisible();
  });

  test('should create a new project', async ({ page }) => {
    // Click new project button
    await page.getByRole('button', { name: /New Project/i }).click();

    // Wait for dialog content to appear
    await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

    // Fill in project details using placeholder
    const projectName = `Test Project ${Date.now()}`;
    await page.getByPlaceholder('My Project').fill(projectName);
    await page.getByPlaceholder('Project description').fill('E2E test project description');

    // Submit form - click the Create button inside the modal
    await page.locator('.fixed button:has-text("Create")').click();

    // Verify project was created and appears in list
    await expect(page.getByText(projectName)).toBeVisible({ timeout: 10000 });
  });

  test('should navigate to project detail page', async ({ page }) => {
    // Wait for projects to load
    await page.waitForTimeout(1000);

    // Click on the first project's view button (arrow icon)
    const firstProject = page.locator('[href*="/projects/"]').first();
    if (await firstProject.isVisible()) {
      await firstProject.click();

      // Verify we're on the project detail page
      await expect(page.getByText('Back to Projects')).toBeVisible();
      await expect(page.getByRole('button', { name: /Upload SBOM/i })).toBeVisible();
    }
  });

  test('should show delete confirmation dialog', async ({ page }) => {
    // Wait for projects to load
    await page.waitForTimeout(1000);

    // Find and click delete button on first project
    const deleteButton = page.locator('button').filter({ has: page.locator('svg.lucide-trash-2') }).first();
    if (await deleteButton.isVisible()) {
      await deleteButton.click();

      // Verify delete confirmation dialog appears
      await expect(page.getByText(/Are you sure/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /Cancel/i })).toBeVisible();
      await expect(page.getByRole('button', { name: /Delete/i })).toBeVisible();

      // Cancel deletion
      await page.getByRole('button', { name: /Cancel/i }).click();
    }
  });
});

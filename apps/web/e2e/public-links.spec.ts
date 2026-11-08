import { test, expect } from '@playwright/test';

import { API_BASE_URL, createProject, deleteProject, uniqueName, uploadSbom } from './fixtures/vuln-project';

test.describe('Public Links', () => {
  let projectId = '';

  test.beforeAll(async ({ request }) => {
    const project = await createProject(request, uniqueName('Public Link Project'), 'Project for public link E2E tests');
    projectId = project.id;
    await uploadSbom(request, projectId, {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      components: [
        { type: 'library', name: 'public-link-component', version: '1.2.3', licenses: [{ license: { id: 'MIT' } }] },
      ],
    });
  });

  test.afterAll(async ({ request }) => {
    await deleteProject(request, projectId);
  });

  test('should create and access a password-protected public link', async ({ page, request }) => {
    const linkName = `Customer Share ${Date.now()}`;
    const password = 'e2e-pass-123';

    await page.goto(`/en/projects/${projectId}/share`);

    // Fill the create form (the share page is English-only).
    const nameInput = page.getByPlaceholder('e.g., Customer A');
    await expect(nameInput).toBeVisible({ timeout: 15000 });
    await nameInput.fill(linkName);
    await page.locator('input[type="date"]').fill(futureDate());
    await page.locator('input[type="number"]').fill('2');
    await page.locator('input[type="password"]').fill(password);
    await expect(page.locator('#is-active')).toBeChecked();

    const createButton = page.getByRole('button', { name: 'Create Link' });
    await expect(createButton).toBeEnabled();
    const created = page.waitForResponse(
      (r) => r.request().method() === 'POST' && r.url().endsWith(`/api/v1/projects/${projectId}/public-links`),
    );
    await createButton.click();
    expect((await created).status()).toBe(201);

    // The new link is listed with its settings; the form is reset.
    const row = page.locator('div.border.rounded.p-3', { hasText: linkName });
    await expect(row).toHaveCount(1, { timeout: 10000 });
    await expect(row).toContainText('Status: Active');
    await expect(row).toContainText('Views: 0 / Downloads: 0');
    await expect(row.getByText('Limit 2', { exact: true })).toBeVisible();
    await expect(nameInput).toHaveValue('');

    // The token in the UI is the one the API stored, with the same settings.
    const linksResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/public-links`);
    expect(linksResponse.status()).toBe(200);
    const links = (await linksResponse.json()) as Array<{ name: string; token: string; allowed_downloads?: number; is_active: boolean }>;
    const stored = links.find((l) => l.name === linkName);
    expect(stored, 'link created through the UI must be stored').toBeTruthy();
    expect(stored!.is_active).toBe(true);
    expect(stored!.allowed_downloads).toBe(2);
    const publicToken = stored!.token;
    expect(publicToken).toBeTruthy();
    await expect(row.locator('code')).toHaveText(new RegExp(`/en/public/${publicToken}$`));

    // The public page asks for the password...
    await page.goto(`/en/public/${publicToken}`);
    await expect(page.getByText('Public SBOM Access')).toBeVisible({ timeout: 15000 });
    await expect(page.getByText('public-link-component')).toHaveCount(0);

    // ...rejects a wrong one...
    const accessPasswordInput = page.locator('input[type="password"]');
    await accessPasswordInput.fill('wrong-password');
    await page.getByRole('button', { name: 'Access' }).click();
    await expect(page.getByText('Access denied. Password may be required.')).toBeVisible();
    await expect(page.getByText('public-link-component')).toHaveCount(0);

    // ...and shows the SBOM's components for the right one.
    await accessPasswordInput.fill(password);
    await page.getByRole('button', { name: 'Access' }).click();
    await expect(page.getByText('public-link-component')).toBeVisible({ timeout: 15000 });
    await expect(page.getByText('1.2.3')).toBeVisible();
  });
});

function futureDate() {
  const date = new Date();
  date.setDate(date.getDate() + 7);
  return date.toISOString().slice(0, 10);
}

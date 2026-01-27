import { test, expect } from '@playwright/test';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('Public Links', () => {
  let projectId: string;
  let publicToken: string;

  test.beforeAll(async ({ request }) => {
    const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `Public Link Project ${Date.now()}`,
        description: 'Project for public link E2E tests',
      },
    });
    const project = await projectResponse.json();
    projectId = project.id;

    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      components: [
        {
          type: 'library',
          name: 'public-link-component',
          version: '1.2.3',
          licenses: [{ license: { id: 'MIT' } }],
        },
      ],
    };

    await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
      data: JSON.stringify(sbom),
      headers: { 'Content-Type': 'application/json' },
    });
  });

  test.afterAll(async ({ request }) => {
    if (projectId) {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    }
  });

  test('should create and access a password-protected public link', async ({ page, request }) => {
    const linkName = `Customer Share ${Date.now()}`;
    const password = 'e2e-pass-123';

    await page.goto(`/en/projects/${projectId}/share`);

    await page.getByPlaceholder('e.g., Customer A').fill(linkName);
    await page.locator('input[type="date"]').fill(futureDate());
    await page.locator('input[type="number"]').fill('2');
    await page.locator('input[type="password"]').fill(password);
    await page.getByRole('checkbox', { name: 'Active' }).check();

    await page.getByRole('button', { name: /Create Link/i }).click();
    await expect(page.getByText(linkName)).toBeVisible({ timeout: 10000 });

    const linksResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/public-links`);
    const links = await linksResponse.json();
    const created = links.find((link: { name: string }) => link.name === linkName);
    publicToken = created?.token;
    expect(publicToken).toBeTruthy();

    await page.goto(`/public/${publicToken}`);
    await expect(page.getByText('Public SBOM Access')).toBeVisible();
    await page.locator('input[type="password"]').fill(password);
    await page.getByRole('button', { name: 'Access' }).click();

    await expect(page.getByText('public-link-component')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('1.2.3')).toBeVisible();
  });
});

function futureDate() {
  const date = new Date();
  date.setDate(date.getDate() + 7);
  return date.toISOString().slice(0, 10);
}

import { test, expect } from '@playwright/test';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('SBOM Diff', () => {
  let projectId: string;

  test.beforeAll(async ({ request }) => {
    const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `SBOM Diff Project ${Date.now()}`,
        description: 'Project for SBOM diff E2E tests',
      },
    });
    const project = await projectResponse.json();
    projectId = project.id;

    const baseSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      components: [
        { type: 'library', name: 'alpha-lib', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
        { type: 'library', name: 'shared-lib', version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
      ],
    };
    const targetSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 2,
      components: [
        { type: 'library', name: 'beta-lib', version: '2.0.0', licenses: [{ license: { id: 'MIT' } }] },
        { type: 'library', name: 'shared-lib', version: '1.1.0', licenses: [{ license: { id: 'MIT' } }] },
      ],
    };

    await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
      data: JSON.stringify(baseSbom),
      headers: { 'Content-Type': 'application/json' },
    });

    await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
      data: JSON.stringify(targetSbom),
      headers: { 'Content-Type': 'application/json' },
    });
  });

  test.afterAll(async ({ request }) => {
    if (projectId) {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    }
  });

  test('should compare two sboms and show added/removed/updated components', async ({ page }) => {
    await page.goto(`/en/projects/${projectId}/diff`);

    await expect(page.getByRole('heading', { name: 'SBOM Diff' })).toBeVisible();
    await page.getByRole('button', { name: 'Compare' }).click();

    await expect(page.getByText('Added Components')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('beta-lib@2.0.0')).toBeVisible();
    await expect(page.getByText('Removed Components')).toBeVisible();
    await expect(page.getByText('alpha-lib@1.0.0')).toBeVisible();
    await expect(page.getByText('Updated Components')).toBeVisible();
    await expect(page.getByText('shared-lib')).toBeVisible();
  });
});

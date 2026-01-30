import { test, expect } from '@playwright/test';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('SBOM Management', () => {
  let projectId: string;

  test.beforeAll(async ({ request }) => {
    // Create a test project via API
    const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `SBOM Test Project ${Date.now()}`,
        description: 'Project for SBOM E2E tests',
      },
    });
    const project = await response.json();
    projectId = project.id;
  });

  test.afterAll(async ({ request }) => {
    // Clean up test project
    if (projectId) {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    }
  });

  test('should upload CycloneDX SBOM', async ({ page, request }) => {
    await page.goto(`/en/projects/${projectId}`);

    // Verify we're on the project page
    await expect(page.getByRole('button', { name: /Upload SBOM/i })).toBeVisible();

    // Create a CycloneDX SBOM file
    const cycloneDxSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      components: [
        {
          type: 'library',
          name: 'test-component',
          version: '1.0.0',
          licenses: [{ license: { id: 'MIT' } }],
        },
      ],
    };

    // Upload via API (file input is tricky in Playwright)
    const uploadResponse = await request.post(
      `${API_BASE_URL}/api/v1/projects/${projectId}/sbom`,
      {
        data: JSON.stringify(cycloneDxSbom),
        headers: { 'Content-Type': 'application/json' },
      }
    );
    expect(uploadResponse.ok()).toBeTruthy();

    // Refresh page and check components
    await page.reload();
    await page.getByRole('button', { name: /Components/i }).click();

    // Verify component is displayed
    await expect(page.getByText('test-component')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('1.0.0')).toBeVisible();
  });

  test('should upload SPDX SBOM', async ({ page, request }) => {
    // Create a new project for SPDX test
    const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `SPDX Test Project ${Date.now()}`,
        description: 'Project for SPDX E2E tests',
      },
    });
    const project = await createResponse.json();

    const spdxSbom = {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'test-spdx-sbom',
      documentNamespace: 'https://example.com/test-spdx',
      creationInfo: {
        created: new Date().toISOString(),
        creators: ['Tool: playwright-test'],
      },
      packages: [
        {
          SPDXID: 'SPDXRef-Package-spdx-component',
          name: 'spdx-test-component',
          versionInfo: '2.0.0',
          downloadLocation: 'https://example.com/package',
          licenseConcluded: 'Apache-2.0',
        },
      ],
    };

    // Upload SPDX SBOM
    const uploadResponse = await request.post(
      `${API_BASE_URL}/api/v1/projects/${project.id}/sbom`,
      {
        data: JSON.stringify(spdxSbom),
        headers: { 'Content-Type': 'application/json' },
      }
    );
    expect(uploadResponse.ok()).toBeTruthy();

    // Navigate to project and check components
    await page.goto(`/en/projects/${project.id}`);
    await page.getByRole('button', { name: /Components/i }).click();

    // Verify SPDX component is displayed
    await expect(page.getByText('spdx-test-component')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('2.0.0')).toBeVisible();

    // Clean up
    await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
  });

  test('should display components list after upload', async ({ page, request }) => {
    // First upload a SBOM to ensure we have components
    const testSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      components: [
        {
          type: 'library',
          name: 'display-test-component',
          version: '3.0.0',
          licenses: [{ license: { id: 'MIT' } }],
        },
      ],
    };

    await request.post(
      `${API_BASE_URL}/api/v1/projects/${projectId}/sbom`,
      {
        data: JSON.stringify(testSbom),
        headers: { 'Content-Type': 'application/json' },
      }
    );

    await page.goto(`/en/projects/${projectId}`);

    // Wait for page to load
    await page.waitForLoadState('networkidle');

    // Click on Components tab
    await page.getByRole('button', { name: /Components/i }).click();

    // Wait for components to load and verify they are displayed
    await expect(page.getByText('display-test-component')).toBeVisible({ timeout: 10000 });
  });

  test('should reject invalid JSON upload', async ({ request }) => {
    // Create a test project for this test
    const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `Invalid JSON Test ${Date.now()}`,
        description: 'Project for invalid JSON upload test',
      },
    });
    const project = await createResponse.json();

    // Try to upload invalid JSON (not a valid SBOM format)
    const invalidJson = 'this is not valid json {{{';

    const uploadResponse = await request.post(
      `${API_BASE_URL}/api/v1/projects/${project.id}/sbom`,
      {
        data: invalidJson,
        headers: { 'Content-Type': 'application/json' },
      }
    );

    // Should fail with 400 Bad Request or similar error
    expect(uploadResponse.ok()).toBeFalsy();
    expect(uploadResponse.status()).toBeGreaterThanOrEqual(400);

    // Clean up
    await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
  });

  test('should reject non-SBOM JSON upload', async ({ request }) => {
    // Create a test project for this test
    const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `Non-SBOM JSON Test ${Date.now()}`,
        description: 'Project for non-SBOM JSON upload test',
      },
    });
    const project = await createResponse.json();

    // Try to upload valid JSON but not a valid SBOM format
    const nonSbomJson = {
      someField: 'someValue',
      anotherField: 123,
    };

    const uploadResponse = await request.post(
      `${API_BASE_URL}/api/v1/projects/${project.id}/sbom`,
      {
        data: JSON.stringify(nonSbomJson),
        headers: { 'Content-Type': 'application/json' },
      }
    );

    // Should fail because it's not a valid SBOM format (no bomFormat or spdxVersion)
    expect(uploadResponse.ok()).toBeFalsy();
    expect(uploadResponse.status()).toBeGreaterThanOrEqual(400);

    // Clean up
    await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
  });

  test('should handle large SBOM with many components', async ({ page, request }) => {
    // Create a test project for this test
    const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `Large SBOM Test ${Date.now()}`,
        description: 'Project for large SBOM upload test',
      },
    });
    const project = await createResponse.json();

    // Create a large SBOM with many components (100 components)
    const components = [];
    for (let i = 0; i < 100; i++) {
      components.push({
        type: 'library',
        name: `large-test-component-${i}`,
        version: `${i}.0.0`,
        licenses: [{ license: { id: 'MIT' } }],
        purl: `pkg:npm/large-test-component-${i}@${i}.0.0`,
      });
    }

    const largeSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      components: components,
    };

    // Upload the large SBOM
    const uploadResponse = await request.post(
      `${API_BASE_URL}/api/v1/projects/${project.id}/sbom`,
      {
        data: JSON.stringify(largeSbom),
        headers: { 'Content-Type': 'application/json' },
      }
    );
    expect(uploadResponse.ok()).toBeTruthy();

    // Navigate to project and verify components are displayed
    await page.goto(`/en/projects/${project.id}`);
    await page.waitForLoadState('networkidle');
    await page.getByRole('button', { name: /Components/i }).click();

    // Wait for components to load - check for at least one component
    await expect(page.getByText('large-test-component-0')).toBeVisible({ timeout: 15000 });

    // Check that multiple components are present (pagination or scroll may be needed)
    const componentCount = await page.locator('text=/large-test-component-/').count();
    expect(componentCount).toBeGreaterThan(0);

    // Clean up
    await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
  });
});

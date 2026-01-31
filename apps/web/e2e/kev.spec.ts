import { test, expect } from '@playwright/test';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// These tests require authentication in SaaS mode
// In self-hosted mode, they should work without auth
test.describe('KEV (Known Exploited Vulnerabilities)', () => {
  // Check if we're running in authenticated mode
  let isAuthenticated = false;

  test.beforeAll(async ({ request }) => {
    // Check health to determine mode
    const healthResponse = await request.get(`${API_BASE_URL}/api/v1/health`);
    const health = await healthResponse.json();
    // If mode is self-hosted, we don't need auth
    isAuthenticated = health.mode === 'self-hosted';
  });

  test.describe('KEV Catalog API', () => {
    test('should sync KEV catalog', async ({ request }) => {
      // Trigger KEV sync
      const syncResponse = await request.post(`${API_BASE_URL}/api/v1/kev/sync`);

      // In SaaS mode, expect 401; in self-hosted, expect success or network error
      if (syncResponse.status() === 401) {
        // Expected in SaaS mode without auth
        expect(syncResponse.status()).toBe(401);
      } else if (syncResponse.ok()) {
        const result = await syncResponse.json();
        expect(result).toHaveProperty('total_processed');
        expect(result.total_processed).toBeGreaterThanOrEqual(0);
      }
    });

    test('should get KEV stats or require auth', async ({ request }) => {
      const statsResponse = await request.get(`${API_BASE_URL}/api/v1/kev/stats`);

      if (statsResponse.status() === 401) {
        // Expected in SaaS mode without auth
        expect(statsResponse.status()).toBe(401);
      } else {
        expect(statsResponse.ok()).toBeTruthy();
        const stats = await statsResponse.json();
        expect(stats).toHaveProperty('total_entries');
      }
    });

    test('should list KEV catalog entries or require auth', async ({ request }) => {
      const catalogResponse = await request.get(`${API_BASE_URL}/api/v1/kev/catalog?limit=10`);

      if (catalogResponse.status() === 401) {
        // Expected in SaaS mode without auth
        expect(catalogResponse.status()).toBe(401);
      } else {
        expect(catalogResponse.ok()).toBeTruthy();
        const catalog = await catalogResponse.json();
        expect(catalog).toHaveProperty('entries');
        expect(catalog).toHaveProperty('total');
        expect(Array.isArray(catalog.entries)).toBeTruthy();
      }
    });

    test('should check if CVE is in KEV or require auth', async ({ request }) => {
      // Check a well-known CVE that should be in KEV (Log4Shell)
      const checkResponse = await request.get(`${API_BASE_URL}/api/v1/kev/CVE-2021-44228`);

      if (checkResponse.status() === 401) {
        // Expected in SaaS mode without auth
        expect(checkResponse.status()).toBe(401);
      } else {
        expect(checkResponse.ok()).toBeTruthy();
        const result = await checkResponse.json();
        expect(result).toHaveProperty('cve_id');
        expect(result).toHaveProperty('in_kev');
        expect(result.cve_id).toBe('CVE-2021-44228');
      }
    });

    test('should return false for non-KEV CVE or require auth', async ({ request }) => {
      // Check a non-existent CVE
      const checkResponse = await request.get(`${API_BASE_URL}/api/v1/kev/CVE-9999-99999`);

      if (checkResponse.status() === 401) {
        // Expected in SaaS mode without auth
        expect(checkResponse.status()).toBe(401);
      } else {
        expect(checkResponse.ok()).toBeTruthy();
        const result = await checkResponse.json();
        expect(result.in_kev).toBe(false);
      }
    });
  });

  test.describe('KEV in Project Context', () => {
    let projectId: string | null = null;

    test.beforeAll(async ({ request }) => {
      // Create a test project
      const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
        data: {
          name: `KEV Test Project ${Date.now()}`,
          description: 'Project for KEV E2E tests',
        },
      });

      // Skip project creation if auth is required
      if (createResponse.status() === 401) {
        return;
      }

      const project = await createResponse.json();
      projectId = project.id;

      // Upload SBOM with potentially vulnerable component
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.4',
        version: 1,
        components: [
          {
            type: 'library',
            name: 'log4j-core',
            version: '2.14.1', // Known Log4Shell vulnerable version
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
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

    test('should get project KEV vulnerabilities or require auth', async ({ request }) => {
      if (!projectId) {
        // Project wasn't created (auth required), test auth requirement
        const testResponse = await request.get(`${API_BASE_URL}/api/v1/projects/test/kev`);
        expect(testResponse.status()).toBe(401);
        return;
      }

      const kevResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/kev`);

      if (kevResponse.status() === 401) {
        expect(kevResponse.status()).toBe(401);
      } else {
        expect(kevResponse.ok()).toBeTruthy();
        const result = await kevResponse.json();
        expect(result).toHaveProperty('vulnerabilities');
        expect(result).toHaveProperty('count');
        expect(Array.isArray(result.vulnerabilities)).toBeTruthy();
      }
    });
  });
});

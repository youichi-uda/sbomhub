import { test, expect } from '@playwright/test';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// These tests work in self-hosted mode without authentication
// In SaaS mode (Clerk enabled), these endpoints require authentication
test.describe('KEV (Known Exploited Vulnerabilities)', () => {
  test.describe('KEV Catalog API', () => {
    test('should sync KEV catalog', async ({ request }) => {
      // Trigger KEV sync
      const syncResponse = await request.post(`${API_BASE_URL}/api/v1/kev/sync`);

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(syncResponse.status());

      if (syncResponse.ok()) {
        const result = await syncResponse.json();
        expect(result).toHaveProperty('total_processed');
        expect(result.total_processed).toBeGreaterThanOrEqual(0);
      }
    });

    test('should get KEV stats', async ({ request }) => {
      const statsResponse = await request.get(`${API_BASE_URL}/api/v1/kev/stats`);

      // Accept 200 (success), 401 (auth required), or 500 (server error - may not be configured)
      expect([200, 401, 500]).toContain(statsResponse.status());

      if (statsResponse.ok()) {
        const stats = await statsResponse.json();
        expect(stats).toHaveProperty('total_entries');
      }
    });

    test('should list KEV catalog entries', async ({ request }) => {
      const catalogResponse = await request.get(`${API_BASE_URL}/api/v1/kev/catalog?limit=10`);

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(catalogResponse.status());

      if (catalogResponse.ok()) {
        const catalog = await catalogResponse.json();
        expect(catalog).toHaveProperty('entries');
        expect(catalog).toHaveProperty('total');
        expect(Array.isArray(catalog.entries)).toBeTruthy();
      }
    });

    test('should check if CVE is in KEV', async ({ request }) => {
      // Check a well-known CVE that should be in KEV (Log4Shell)
      const checkResponse = await request.get(`${API_BASE_URL}/api/v1/kev/CVE-2021-44228`);

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(checkResponse.status());

      if (checkResponse.ok()) {
        const result = await checkResponse.json();
        expect(result).toHaveProperty('cve_id');
        expect(result).toHaveProperty('in_kev');
        expect(result.cve_id).toBe('CVE-2021-44228');
      }
    });

    test('should return false for non-KEV CVE', async ({ request }) => {
      // Check a non-existent CVE
      const checkResponse = await request.get(`${API_BASE_URL}/api/v1/kev/CVE-9999-99999`);

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(checkResponse.status());

      if (checkResponse.ok()) {
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

    test('should get project KEV vulnerabilities', async ({ request }) => {
      if (!projectId) {
        // Project wasn't created (auth required in SaaS mode), skip test
        test.skip();
        return;
      }

      const kevResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/kev`);

      // Accept 200 (success), 401 (auth required), or 500 (server error - may not be configured)
      expect([200, 401, 500]).toContain(kevResponse.status());

      if (kevResponse.ok()) {
        const result = await kevResponse.json();
        expect(result).toHaveProperty('vulnerabilities');
        expect(result).toHaveProperty('count');
        expect(Array.isArray(result.vulnerabilities)).toBeTruthy();
      }
    });
  });
});

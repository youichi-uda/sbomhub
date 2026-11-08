import { test, expect, type APIRequestContext } from '@playwright/test';
import en from '../messages/en.json';
import {
  API_BASE_URL,
  FIXTURE_CVES,
  createVulnerableProject,
  deleteProject,
  type VulnerableProject,
} from './fixtures/vuln-project';

// The CI stack runs in self-hosted anonymous mode (no auth), so every call
// below must answer with its exact success status; there is no 401 branch.

const KEV_CVES = FIXTURE_CVES.filter((c) => c.inKev).map((c) => c.cveId).sort();
const NON_KEV_CVES = FIXTURE_CVES.filter((c) => !c.inKev).map((c) => c.cveId);

/**
 * The catalog endpoints read kev_catalog, which only POST /kev/sync fills
 * (the seed does not). Make sure it is populated so every catalog test is
 * independent of test order; a failing sync FAILS the suite.
 */
async function ensureCatalogSynced(request: APIRequestContext): Promise<void> {
  const statsRes = await request.get(`${API_BASE_URL}/api/v1/kev/stats`);
  expect(statsRes.status()).toBe(200);
  const stats = await statsRes.json();
  if (stats.total_entries === 0) {
    const syncRes = await request.post(`${API_BASE_URL}/api/v1/kev/sync`);
    expect(syncRes.status(), `KEV sync: ${await syncRes.text()}`).toBe(200);
  }
}

test.describe('KEV (Known Exploited Vulnerabilities)', () => {
  test.describe('KEV Catalog API', () => {
    test.beforeAll(async ({ request }) => {
      await ensureCatalogSynced(request);
    });

    test('should sync KEV catalog', async ({ request }) => {
      // NOTE: this fetches the live CISA feed (the CI runner has egress).
      const syncResponse = await request.post(`${API_BASE_URL}/api/v1/kev/sync`);
      expect(syncResponse.status(), await syncResponse.text()).toBe(200);

      const result = await syncResponse.json();
      expect(result.message).toBe('KEV catalog sync completed');
      expect(result.total_processed).toBeGreaterThan(0);
      expect(result.new_entries + result.updated_entries).toBe(result.total_processed);
      expect(typeof result.catalog_version).toBe('string');
      expect(result.catalog_version).not.toBe('');
    });

    test('should get KEV stats consistent with the catalog', async ({ request }) => {
      const statsResponse = await request.get(`${API_BASE_URL}/api/v1/kev/stats`);
      expect(statsResponse.status()).toBe(200);
      const stats = await statsResponse.json();
      expect(stats.total_entries).toBeGreaterThan(0);
      expect(stats.latest_sync_status.status).toBe('success');

      const catalogResponse = await request.get(`${API_BASE_URL}/api/v1/kev/catalog?limit=1`);
      expect(catalogResponse.status()).toBe(200);
      const catalog = await catalogResponse.json();
      expect(catalog.total).toBe(stats.total_entries);
    });

    test('should list KEV catalog entries', async ({ request }) => {
      const catalogResponse = await request.get(`${API_BASE_URL}/api/v1/kev/catalog?limit=10`);
      expect(catalogResponse.status()).toBe(200);

      const catalog = await catalogResponse.json();
      expect(catalog.limit).toBe(10);
      expect(catalog.offset).toBe(0);
      expect(Array.isArray(catalog.entries)).toBe(true);
      expect(catalog.total).toBeGreaterThan(0);
      expect(catalog.entries).toHaveLength(Math.min(10, catalog.total));
      for (const entry of catalog.entries) {
        expect(entry.cve_id).toMatch(/^CVE-\d{4}-\d{4,}$/);
      }
    });

    test('should check if CVE is in KEV', async ({ request }) => {
      // Log4Shell is in the CISA catalog.
      const checkResponse = await request.get(`${API_BASE_URL}/api/v1/kev/CVE-2021-44228`);
      expect(checkResponse.status()).toBe(200);

      const result = await checkResponse.json();
      expect(result.cve_id).toBe('CVE-2021-44228');
      expect(result.in_kev).toBe(true);
      expect(result.entry.cve_id).toBe('CVE-2021-44228');
      expect(result.entry.vendor_project).toBe('Apache');
    });

    test('should return false for non-KEV CVE', async ({ request }) => {
      const checkResponse = await request.get(`${API_BASE_URL}/api/v1/kev/CVE-9999-99999`);
      expect(checkResponse.status()).toBe(200);

      const result = await checkResponse.json();
      expect(result).toEqual({ cve_id: 'CVE-9999-99999', in_kev: false });
    });
  });

  test.describe('KEV in Project Context', () => {
    let project: VulnerableProject;

    test.beforeAll(async ({ request }) => {
      // 4 fixture vulns: 2 CRITICAL in KEV, 2 HIGH not in KEV.
      project = await createVulnerableProject(request, 'KEV Test Project');
    });

    test.afterAll(async ({ request }) => {
      await deleteProject(request, project?.projectId);
    });

    test('should get project KEV vulnerabilities', async ({ request }) => {
      const kevResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${project.projectId}/kev`
      );
      expect(kevResponse.status()).toBe(200);

      const result = await kevResponse.json();
      expect(result.project_id).toBe(project.projectId);
      expect(result.count).toBe(KEV_CVES.length);
      expect(result.vulnerabilities.map((v: { cve_id: string }) => v.cve_id).sort()).toEqual(KEV_CVES);
      for (const v of result.vulnerabilities) {
        expect(v.in_kev).toBe(true);
      }
    });

    test('should mark exactly the KEV vulnerabilities with the KEV badge', async ({ page }) => {
      await page.goto(`/en/projects/${project.projectId}`);
      await page
        .getByRole('button', { name: `${en.Vulnerabilities.title} (${FIXTURE_CVES.length})` })
        .click();

      for (const cveId of KEV_CVES) {
        const entry = page.locator(`[data-vuln-cve-id="${cveId}"]`);
        await expect(entry).toBeVisible({ timeout: 10000 });
        await expect(entry.getByText(en.KEV.badge, { exact: true })).toBeVisible();
      }
      for (const cveId of NON_KEV_CVES) {
        const entry = page.locator(`[data-vuln-cve-id="${cveId}"]`);
        await expect(entry).toBeVisible();
        await expect(entry.getByText(en.KEV.badge, { exact: true })).toHaveCount(0);
      }
    });
  });
});

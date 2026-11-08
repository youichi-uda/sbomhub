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
 * The catalog endpoints read kev_catalog, which docker/seed/web-e2e.sql §9
 * pre-fills with the two KEV-flagged fixture CVEs and one successful sync
 * log, so these tests need no egress and do not depend on test order. A
 * missing seed FAILS here; it is not papered over with a live sync.
 */
async function expectCatalogSeeded(request: APIRequestContext): Promise<void> {
  const statsRes = await request.get(`${API_BASE_URL}/api/v1/kev/stats`);
  expect(statsRes.status()).toBe(200);
  const stats = await statsRes.json();
  expect(stats.total_entries, 'kev_catalog is empty — is docker/seed/web-e2e.sql §9 loaded?').toBeGreaterThanOrEqual(KEV_CVES.length);
}

test.describe('KEV (Known Exploited Vulnerabilities)', () => {
  test.describe('KEV Catalog API', () => {
    test.beforeAll(async ({ request }) => {
      await expectCatalogSeeded(request);
    });

    // There is deliberately no "POST /kev/sync" test here. Sync downloads the
    // live CISA feed, so in this REQUIRED suite it made the gate depend on
    // CISA's availability and let the feed rewrite vulnerabilities.in_kev
    // under the KEV assertions below. Sync is covered hermetically by
    // apps/api/internal/service/kev_test.go::TestKEVService_SyncCatalog_InjectedURL
    // (canned catalogue over httptest). These tests hold for the §9 seed alone
    // (no egress) and for a catalogue the api's start-up sync filled from
    // CISA (egress): they assert only what is true of both.

    test('should get KEV stats consistent with the catalog', async ({ request }) => {
      const statsResponse = await request.get(`${API_BASE_URL}/api/v1/kev/stats`);
      expect(statsResponse.status()).toBe(200);
      const stats = await statsResponse.json();
      expect(stats.total_entries).toBeGreaterThan(0);
      // `success` either way: the seed's sync log, or — on a runner with
      // egress — the api's own start-up sync (scheduler/kev_sync.go runs one
      // immediately), whichever is later.
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

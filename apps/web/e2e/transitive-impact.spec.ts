import { test, expect, type Page } from '@playwright/test';

// M30 F403 (#139) — cross-project transitive blast-radius deep-dive web view.
//
// Fully mock-intercepted (page.route) so the render contract for the new
// TransitiveImpact component is exercised deterministically with no backend
// seed. The web-e2e seed never provisions cross-project transitive data; the
// real tenant-scoped aggregation, per-SBOM parse and M29 traversal reuse are
// covered by the Wave A / F402 real-PG integration tests (issue #138). This
// pins only the web layer's rendering of the pinned /paths contract:
//   - the deep-dive is lazy: nothing fetched until the toggle is clicked
//   - multi-project transitive chains render (root → … → component) reusing
//     the M29 PathChain
//   - is_direct → "upgrade directly" vs transitive → "bump the parent"
//   - project `degraded` (SPDX) → edges-unavailable banner (once), no chains
//   - component `in_graph=false` → "not in latest SBOM"
//   - `truncated` with paths → "showing N"; with none → "too complex"
//   - affected-0 → honest "no projects affected"
//   - the F400 contradictory-state banners never co-occur

// Helper to check if the page was redirected to sign-in (SaaS/auth mode).
async function isRedirectedToSignIn(page: Page): Promise<boolean> {
  const url = page.url();
  return url.includes('/sign-in') || url.includes('/login');
}

const CVE = 'CVE-2021-44228';

const APP_A = { id: 'pkg:npm/app-a', name: 'app-a', version: '1.0.0', type: 'application' };
const EXPRESS = { id: 'pkg:npm/express', name: 'express', version: '4.18.0', type: 'library' };
const QS = { id: 'pkg:npm/qs', name: 'qs', version: '6.2.0', type: 'library' };
const APP_B = { id: 'pkg:npm/app-b', name: 'app-b', version: '2.0.0', type: 'application' };
const LOG4J = {
  id: 'pkg:maven/org.apache.logging.log4j/log4j-core',
  name: 'log4j-core',
  version: '2.14.0',
  type: 'library',
};

// A present impact result so the search page renders the TransitiveImpact
// card (it is gated on impactResult being present). The blast-radius summary
// itself is covered by search.spec.ts; here it is just scaffolding.
const IMPACT = {
  cve_id: CVE,
  severity: 'critical',
  cvss_score: 10.0,
  epss_score: 0,
  in_kev: true,
  affected_project_count: 2,
  total_project_count: 5,
  affected_projects: [
    {
      project_id: '11111111-1111-4111-8111-111111111111',
      project_name: 'iot-gateway',
      affected_components: [{ name: 'qs', version: '6.2.0', purl: 'pkg:npm/qs@6.2.0' }],
      component_count: 1,
    },
  ],
};

const CVE_RESULT = {
  cve_id: CVE,
  description: 'Log4Shell',
  cvss_score: 10.0,
  epss_score: 0,
  severity: 'CRITICAL',
  affected_projects: [],
  unaffected_projects: [],
};

// Intercept the CVE search + impact (so the card renders) and the paths
// endpoint with the supplied deep-dive body.
async function mockSearch(page: Page, paths: unknown, impact: unknown = IMPACT) {
  await page.route('**/api/v1/search/cve*', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(CVE_RESULT),
    }),
  );
  await page.route('**/api/v1/vulnerabilities/*/impact', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(impact),
    }),
  );
  await page.route('**/api/v1/vulnerabilities/*/paths', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(paths),
    }),
  );
}

async function runSearch(page: Page): Promise<boolean> {
  await page.goto('/en/search');
  await page.waitForLoadState('networkidle');
  if (await isRedirectedToSignIn(page)) return false;
  await page.getByPlaceholder(CVE).fill(CVE);
  await page.getByRole('button', { name: 'Search' }).first().click();
  await expect(page.getByTestId('transitive-impact')).toBeVisible({ timeout: 10000 });
  return true;
}

test.describe('Cross-project transitive blast-radius (M30 F403)', () => {
  test('lazily loads and renders multi-project transitive chains', async ({ page }) => {
    const paths = {
      cve_id: CVE,
      severity: 'HIGH',
      cvss_score: 7.5,
      epss_score: 0,
      in_kev: false,
      affected_project_count: 2,
      total_project_count: 12,
      affected_projects: [
        {
          project_id: '11111111-1111-4111-8111-111111111111',
          project_name: 'iot-gateway',
          sbom_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          format: 'cyclonedx',
          degraded: false,
          component_count: 1,
          affected_components: [
            {
              name: 'qs',
              version: '6.2.0',
              purl: 'pkg:npm/qs@6.2.0',
              in_graph: true,
              is_direct: false,
              truncated: false,
              path_count: 1,
              paths: [[APP_A, EXPRESS, QS]],
            },
          ],
        },
        {
          project_id: '22222222-2222-4222-8222-222222222222',
          project_name: 'edge-controller',
          sbom_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
          format: 'cyclonedx',
          degraded: false,
          component_count: 1,
          affected_components: [
            {
              name: 'log4j-core',
              version: '2.14.0',
              purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0',
              in_graph: true,
              is_direct: true,
              truncated: false,
              path_count: 1,
              paths: [[APP_B, LOG4J]],
            },
          ],
        },
      ],
    };
    await mockSearch(page, paths);

    let outstanding = 0;
    await page.route('**/api/v1/vulnerabilities/*/paths', async (route) => {
      outstanding += 1;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(paths),
      });
    });

    if (!(await runSearch(page))) return;

    // Lazy: the paths endpoint is NOT hit until the toggle is clicked.
    expect(outstanding).toBe(0);
    await expect(page.getByTestId('transitive-impact-projects')).toHaveCount(0);

    await page.getByTestId('transitive-impact-toggle').click();

    const projects = page.getByTestId('transitive-impact-project');
    await expect(projects).toHaveCount(2);
    expect(outstanding).toBeGreaterThan(0);

    // Both projects + both chains render, reusing the M29 chain nodes.
    const container = page.getByTestId('transitive-impact-projects');
    await expect(container).toContainText('iot-gateway');
    await expect(container).toContainText('edge-controller');
    await expect(container).toContainText('express');
    await expect(container).toContainText('qs');
    await expect(container).toContainText('log4j-core');

    // qs is transitive; log4j-core is a direct dependency.
    await expect(page.getByTestId('transitive-impact-transitive')).toBeVisible();
    await expect(page.getByTestId('transitive-impact-direct')).toBeVisible();

    // The chain target emphasis is drawn by the reused PathChain renderer.
    await expect(
      container.locator('[data-role="target"]').first(),
    ).toBeVisible();

    // Toggling again hides the deep-dive.
    await page.getByTestId('transitive-impact-toggle').click();
    await expect(page.getByTestId('transitive-impact-projects')).toHaveCount(0);
  });

  test('renders degraded (SPDX) project once, without chains (F400)', async ({ page }) => {
    const paths = {
      cve_id: CVE,
      severity: 'HIGH',
      cvss_score: 7.5,
      epss_score: 0,
      in_kev: false,
      affected_project_count: 1,
      total_project_count: 4,
      affected_projects: [
        {
          project_id: '33333333-3333-4333-8333-333333333333',
          project_name: 'legacy-spdx',
          sbom_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
          format: 'spdx',
          degraded: true,
          component_count: 1,
          affected_components: [
            {
              name: 'qs',
              version: '6.2.0',
              purl: 'pkg:npm/qs@6.2.0',
              in_graph: false,
              is_direct: false,
              truncated: false,
              path_count: 0,
              paths: [],
            },
          ],
        },
      ],
    };
    await mockSearch(page, paths);
    if (!(await runSearch(page))) return;
    await page.getByTestId('transitive-impact-toggle').click();

    const degraded = page.getByTestId('transitive-impact-degraded');
    await expect(degraded).toBeVisible();
    await expect(degraded).toContainText(/SPDX/i);
    // The affected component is still listed (which, not how).
    await expect(
      page.getByTestId('transitive-impact-degraded-components'),
    ).toContainText('qs');
    // F400: the degraded reason is shown ONCE; the per-component in_graph /
    // no-paths banners must NOT also render.
    await expect(page.getByTestId('transitive-impact-not-in-graph')).toHaveCount(0);
    await expect(page.getByTestId('transitive-impact-no-paths')).toHaveCount(0);
    await expect(page.getByTestId('transitive-impact-chain')).toHaveCount(0);
  });

  test('renders in_graph=false component honestly, no contradictory banners (F400)', async ({
    page,
  }) => {
    const paths = {
      cve_id: CVE,
      severity: 'HIGH',
      cvss_score: 7.5,
      epss_score: 0,
      in_kev: false,
      affected_project_count: 1,
      total_project_count: 4,
      affected_projects: [
        {
          project_id: '44444444-4444-4444-8444-444444444444',
          project_name: 'stale-snapshot',
          sbom_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
          format: 'cyclonedx',
          degraded: false,
          component_count: 1,
          affected_components: [
            {
              name: 'qs',
              version: '6.2.0',
              purl: 'pkg:npm/qs@6.2.0',
              in_graph: false,
              is_direct: false,
              truncated: false,
              path_count: 0,
              paths: [],
            },
          ],
        },
      ],
    };
    await mockSearch(page, paths);
    if (!(await runSearch(page))) return;
    await page.getByTestId('transitive-impact-toggle').click();

    const notInGraph = page.getByTestId('transitive-impact-not-in-graph');
    await expect(notInGraph).toBeVisible();
    await expect(notInGraph).toContainText(/latest SBOM/i);
    // Exactly one reason (F400): no chains, no truncated-empty, no direct/
    // transitive badge (is_direct is meaningless for a component not in graph).
    await expect(page.getByTestId('transitive-impact-chain')).toHaveCount(0);
    await expect(page.getByTestId('transitive-impact-truncated-empty')).toHaveCount(0);
    await expect(page.getByTestId('transitive-impact-direct')).toHaveCount(0);
    await expect(page.getByTestId('transitive-impact-transitive')).toHaveCount(0);
  });

  test('reports truncation honestly (with paths and with none)', async ({ page }) => {
    const paths = {
      cve_id: CVE,
      severity: 'HIGH',
      cvss_score: 7.5,
      epss_score: 0,
      in_kev: false,
      affected_project_count: 1,
      total_project_count: 4,
      affected_projects: [
        {
          project_id: '55555555-5555-4555-8555-555555555555',
          project_name: 'busy-graph',
          sbom_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
          format: 'cyclonedx',
          degraded: false,
          component_count: 2,
          affected_components: [
            {
              name: 'qs',
              version: '6.2.0',
              purl: 'pkg:npm/qs@6.2.0',
              in_graph: true,
              is_direct: false,
              truncated: true,
              path_count: 1,
              paths: [[APP_A, EXPRESS, QS]],
            },
            {
              name: 'log4j-core',
              version: '2.14.0',
              purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0',
              in_graph: true,
              is_direct: false,
              truncated: true,
              path_count: 0,
              paths: [],
            },
          ],
        },
      ],
    };
    await mockSearch(page, paths);
    if (!(await runSearch(page))) return;
    await page.getByTestId('transitive-impact-toggle').click();

    // Truncated WITH paths → "showing N", plus the chain still renders.
    await expect(page.getByTestId('transitive-impact-truncated')).toContainText(
      /Showing 1 paths/i,
    );
    await expect(page.getByTestId('transitive-impact-chain')).toHaveCount(1);

    // Truncated WITH zero paths → the distinct "too complex" message, and
    // NOT the "not in latest SBOM" / "no paths" states (F400).
    const te = page.getByTestId('transitive-impact-truncated-empty');
    await expect(te).toBeVisible();
    await expect(te).toContainText(/computation budget/i);
    await expect(page.getByTestId('transitive-impact-not-in-graph')).toHaveCount(0);
    await expect(page.getByTestId('transitive-impact-no-paths')).toHaveCount(0);
  });

  test('affected-0 shows an honest "no projects affected" empty state', async ({ page }) => {
    const paths = {
      cve_id: CVE,
      severity: 'HIGH',
      cvss_score: 7.5,
      epss_score: 0,
      in_kev: false,
      affected_project_count: 0,
      total_project_count: 5,
      affected_projects: [],
    };
    // Impact also reports 0 so the two surfaces agree (not a fabricated state).
    const impactZero = { ...IMPACT, affected_project_count: 0, affected_projects: [] };
    await mockSearch(page, paths, impactZero);
    if (!(await runSearch(page))) return;
    await page.getByTestId('transitive-impact-toggle').click();

    await expect(page.getByTestId('transitive-impact-empty')).toBeVisible();
    await expect(page.getByTestId('transitive-impact-empty')).toContainText(
      /No projects affected/i,
    );
    await expect(page.getByTestId('transitive-impact-project')).toHaveCount(0);
  });
});

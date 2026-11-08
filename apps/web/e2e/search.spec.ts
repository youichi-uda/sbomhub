import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import {
    FIXTURE_CVES,
    createVulnerableProject,
    deleteProject,
    type VulnerableProject,
} from './fixtures/vuln-project';

// Cross-project search over data this spec creates itself: a project with
// the four FIXTURE_CVES (components vuln-fixture-critical / -high) plus one
// component whose name is unique to this run. Other specs create fixture
// projects concurrently, so CVE / fixture-component searches assert "my
// project is in the results", never exact global counts; only the unique
// component gives an exact match count.

const tSearch = en.Search;

function searchResultsText(name: string, count: number, constraint = ''): string {
    return tSearch.searchResults
        .replace('{name}', name)
        .replace('{constraint}', constraint)
        .replace('{count}', String(count));
}

async function searchCve(page: Page, query: string, expectedStatus: number) {
    await page.goto('/en/search');
    await page.getByPlaceholder(tSearch.cvePlaceholder).fill(query);
    const response = page.waitForResponse(
        (resp) => resp.url().includes('/api/v1/search/cve') && resp.request().method() === 'GET',
    );
    await page.getByRole('button', { name: tSearch.searchButton, exact: true }).click();
    expect((await response).status()).toBe(expectedStatus);
}

async function searchComponent(page: Page, name: string, version?: string) {
    await page.goto('/en/search');
    await page.getByRole('tab', { name: tSearch.componentSearch }).click();
    await page.getByPlaceholder(tSearch.componentNamePlaceholder).fill(name);
    if (version) {
        await page.getByPlaceholder(tSearch.versionPlaceholder).fill(version);
    }
    const response = page.waitForResponse(
        (resp) => resp.url().includes('/api/v1/search/component') && resp.request().method() === 'GET',
    );
    await page.getByRole('button', { name: tSearch.searchButton, exact: true }).click();
    expect((await response).status()).toBe(200);
}

test.describe('Search Functionality', () => {
    let fixture: VulnerableProject;
    const uniqueComponent = `search-e2e-widget-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    test.beforeAll(async ({ request }) => {
        fixture = await createVulnerableProject(request, 'Search Test Project', [
            {
                type: 'library',
                name: uniqueComponent,
                version: '2.3.4',
                licenses: [{ license: { id: 'BSD-3-Clause' } }],
            },
        ]);
    });

    test.afterAll(async ({ request }) => {
        await deleteProject(request, fixture?.projectId);
    });

    test('should display search page with input fields', async ({ page }) => {
        await page.goto('/en/search');

        await expect(page.getByRole('heading', { name: tSearch.title, level: 1 })).toBeVisible();
        await expect(page.getByRole('tab', { name: tSearch.cveSearch })).toHaveAttribute('aria-selected', 'true');
        await expect(page.getByRole('tab', { name: tSearch.componentSearch })).toBeVisible();
        await expect(page.getByPlaceholder(tSearch.cvePlaceholder)).toBeVisible();
        await expect(page.getByRole('button', { name: tSearch.searchButton, exact: true })).toBeVisible();

        await page.getByRole('tab', { name: tSearch.componentSearch }).click();
        await expect(page.getByPlaceholder(tSearch.componentNamePlaceholder)).toBeVisible();
        await expect(page.getByPlaceholder(tSearch.versionPlaceholder)).toBeVisible();
    });

    test('should search for component by name', async ({ page }) => {
        await searchComponent(page, uniqueComponent);

        const results = page.getByTestId('search-results');
        await expect(results).toContainText(searchResultsText(uniqueComponent, 1));
        const rows = results.getByRole('row').filter({ hasText: uniqueComponent });
        await expect(rows).toHaveCount(1);
        const cells = rows.getByRole('cell');
        await expect(cells.nth(0)).toHaveText(fixture.projectName);
        await expect(cells.nth(1)).toHaveText(uniqueComponent);
        await expect(cells.nth(2)).toHaveText('2.3.4');
        await expect(cells.nth(3)).toHaveText('BSD-3-Clause');
        await expect(cells.nth(4)).toHaveText(tSearch.none);
    });

    test('should search for CVE and display results', async ({ page }) => {
        const cve = FIXTURE_CVES[0]; // CVE-2021-44228, CRITICAL, vuln-fixture-critical
        await searchCve(page, cve.cveId, 200);

        const results = page.getByTestId('search-results');
        await expect(results).toBeVisible();
        await expect(results.locator('span.font-mono', { hasText: cve.cveId }).first()).toBeVisible();
        await expect(results.getByText(cve.severity, { exact: true }).first()).toBeVisible();

        // My project is listed among the affected ones, with its component.
        await expect(results.getByText(new RegExp(`^${tSearch.affectedProjects} \\(\\d+\\)$`))).toBeVisible();
        const myLink = results.getByRole('link', { name: fixture.projectName, exact: true });
        await expect(myLink).toHaveAttribute('href', `/en/projects/${fixture.projectId}`);
        const myBlock = results
            .locator('div.border.rounded-lg:not(.bg-card)')
            .filter({ has: page.getByRole('link', { name: fixture.projectName, exact: true }) });
        await expect(myBlock).toContainText(`${cve.component}@1.0.0`);
        await expect(page.getByTestId('empty-state')).toHaveCount(0);
    });

    test('should display CVE details with severity and description', async ({ page }) => {
        const cve = FIXTURE_CVES[2]; // CVE-2021-23337, HIGH
        const v = fixture.vuln(cve.cveId);
        await searchCve(page, cve.cveId, 200);

        const results = page.getByTestId('search-results');
        await expect(results.locator('span.font-mono', { hasText: cve.cveId }).first()).toBeVisible();
        await expect(results.getByText(`CVSS: ${Number(v.cvss_score).toFixed(1)} | EPSS: —`)).toBeVisible();
        await expect(results.getByText(String(v.description), { exact: true })).toBeVisible();
        await expect(results.getByText('HIGH', { exact: true }).first()).toBeVisible();
    });

    test('should handle non-existent CVE search gracefully', async ({ page }) => {
        await searchCve(page, 'CVE-9999-99999', 404);

        const errorCard = page.getByTestId('empty-state');
        await expect(errorCard).toBeVisible();
        await expect(errorCard).toHaveText(tSearch.cveNotFound);
        await expect(page.getByTestId('search-results')).toHaveCount(0);
    });

    test('should validate CVE format', async ({ page }) => {
        // The server rejects a non-CVE string with 400; the page maps every
        // byCVE failure to the same "CVE not found" error card.
        await searchCve(page, 'invalid-cve-format', 400);

        const errorCard = page.getByTestId('empty-state');
        await expect(errorCard).toBeVisible();
        await expect(errorCard).toHaveText(tSearch.cveNotFound);
        await expect(page.getByTestId('search-results')).toHaveCount(0);
    });

    test('should navigate to project from search results', async ({ page }) => {
        await searchComponent(page, uniqueComponent);

        const link = page.getByTestId('search-results').getByRole('link', { name: fixture.projectName, exact: true });
        await link.click();

        await expect(page).toHaveURL(new RegExp(`/en/projects/${fixture.projectId}$`));
        await expect(page.getByRole('heading', { name: fixture.projectName, level: 1 })).toBeVisible();
        await expect(page.getByText(en.ProjectDetail.backToProjects)).toBeVisible();
    });

    test('should display component search results with project context', async ({ page }) => {
        // vuln-fixture-high exists in every fixture project (other specs
        // create them too): assert the row for MY project, not the total.
        const cves = FIXTURE_CVES.filter((c) => c.component === 'vuln-fixture-high');
        await searchComponent(page, 'vuln-fixture-high');

        const results = page.getByTestId('search-results');
        await expect(results).toContainText(new RegExp(`Search results for "vuln-fixture-high": \\d+ matches`));
        const myRow = results.getByRole('row').filter({
            has: page.getByRole('link', { name: fixture.projectName, exact: true }),
        });
        await expect(myRow).toHaveCount(1);
        await expect(myRow.getByRole('link')).toHaveAttribute('href', `/en/projects/${fixture.projectId}`);
        const cells = myRow.getByRole('cell');
        await expect(cells.nth(1)).toHaveText('vuln-fixture-high');
        await expect(cells.nth(2)).toHaveText('1.0.0');
        await expect(cells.nth(3)).toHaveText('MIT');
        // One severity badge per linked CVE (both HIGH).
        await expect(cells.nth(4).getByText('HIGH', { exact: true })).toHaveCount(cves.length);
    });

    // M28 F389 (#135): cross-project vulnerability impact (blast radius).
    // The web-e2e seed never provisions cross-project data, so intercept
    // both the CVE search and the new /vulnerabilities/:cve/impact endpoint
    // with a fixed multi-project blast radius. The real tenant-scoped
    // aggregation + tenant isolation are covered by the Wave A real-PG
    // integration tests (issue #134); this pins only the web rendering of
    // the N-of-M summary + severity/KEV/EPSS rollup + per-project
    // component_count.
    test('should render blast-radius summary from impact endpoint (M28 F389)', async ({ page }) => {
        const impact = {
            cve_id: 'CVE-2021-44228',
            severity: 'critical',
            cvss_score: 10.0,
            // M47 W4 retires F391 (#135): the backend now OMITS epss_score
            // when FIRST.org has no score for the CVE, and emits a real 0
            // only as a genuine "~0%" prediction. This mock takes the
            // un-scored shape (field absent); the web renders the dedicated
            // unscored badge — asserted below.
            in_kev: true,
            affected_project_count: 2,
            total_project_count: 5,
            affected_projects: [
                {
                    project_id: '11111111-1111-4111-8111-111111111111',
                    project_name: 'Mock App A',
                    affected_components: [
                        { name: 'log4j-core', version: '2.14.0', purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0' },
                    ],
                    component_count: 1,
                },
                {
                    project_id: '22222222-2222-4222-8222-222222222222',
                    project_name: 'Mock App B',
                    affected_components: [
                        { name: 'log4j-core', version: '2.13.0', purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0' },
                    ],
                    component_count: 3,
                },
            ],
        };
        const cveResult = {
            cve_id: 'CVE-2021-44228',
            description: 'Log4Shell',
            cvss_score: 10.0,
            epss_score: 0,
            severity: 'CRITICAL',
            affected_projects: [],
            unaffected_projects: [],
        };

        // Host-agnostic globs so the intercepts hold regardless of the API
        // base URL NEXT_PUBLIC_API_URL points at.
        await page.route('**/api/v1/vulnerabilities/*/impact', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(impact) }),
        );
        await page.route('**/api/v1/search/cve*', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(cveResult) }),
        );

        await page.goto('/en/search');

        await page.getByPlaceholder('CVE-2021-44228').fill('CVE-2021-44228');
        await page.getByRole('button', { name: 'Search' }).first().click();

        const summary = page.getByTestId('blast-radius-summary');
        await expect(summary).toBeVisible({ timeout: 10000 });
        // One-glance blast radius: N of M.
        await expect(summary).toHaveAttribute('data-affected-count', '2');
        await expect(summary).toHaveAttribute('data-total-count', '5');
        await expect(summary).toContainText('2 of 5 projects affected');
        // Rollup badges. CVSS is always present; an omitted epss_score means
        // FIRST.org has no score, which renders as the dedicated unscored
        // badge — never a misleading "EPSS 0.0%" (M47 W4, retiring F391's
        // suppress-on-0 rule).
        await expect(summary.getByTestId('blast-radius-cvss')).toContainText('CVSS 10.0');
        await expect(summary.getByTestId('blast-radius-epss')).toContainText('EPSS unscored');
        // Per-project rollup (name + component_count).
        const projects = summary.getByTestId('blast-radius-project');
        await expect(projects).toHaveCount(2);
        await expect(summary).toContainText('Mock App A');
        await expect(summary).toContainText('Mock App B');
        await expect(summary).toContainText('3 components');
    });

    // M28 F389 (#135): blast radius of 0 is a valid answer (no local
    // project is exposed to this CVE) and must read as reassurance, not an
    // error. Intercept impact with affected_project_count=0.
    test('should render blast-radius empty state when no projects affected (M28 F389)', async ({ page }) => {
        const impact = {
            cve_id: 'CVE-2021-44228',
            severity: 'high',
            cvss_score: 7.5,
            // M47 W4: un-scored CVEs arrive with epss_score omitted.
            in_kev: false,
            affected_project_count: 0,
            total_project_count: 5,
            affected_projects: [],
        };
        const cveResult = {
            cve_id: 'CVE-2021-44228',
            description: 'no local exposure',
            cvss_score: 7.5,
            epss_score: 0,
            severity: 'HIGH',
            affected_projects: [],
            unaffected_projects: [],
        };

        await page.route('**/api/v1/vulnerabilities/*/impact', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(impact) }),
        );
        await page.route('**/api/v1/search/cve*', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(cveResult) }),
        );

        await page.goto('/en/search');

        await page.getByPlaceholder('CVE-2021-44228').fill('CVE-2021-44228');
        await page.getByRole('button', { name: 'Search' }).first().click();

        const summary = page.getByTestId('blast-radius-summary');
        await expect(summary).toBeVisible({ timeout: 10000 });
        await expect(summary).toHaveAttribute('data-affected-count', '0');
        await expect(summary.getByTestId('blast-radius-empty')).toBeVisible();
        await expect(summary).toContainText('No projects affected');
        // No per-project rows when clean.
        await expect(summary.getByTestId('blast-radius-project')).toHaveCount(0);
    });

    // M28 F395 (#134/#135): a 204 / empty impact response must NOT be rendered
    // as a fabricated "0 projects affected". "No projects affected" is an
    // affirmative security claim; showing it when the endpoint returned nothing
    // (broken / 204) is false reassurance. getImpact throws on an empty
    // envelope, the search page's best-effort catch hides the summary, and the
    // byCVE listing still renders. This pins the distinction from the genuine
    // 200 + affected:[] empty-state test above.
    test('should NOT render blast-radius summary when impact endpoint returns no body (M28 F395)', async ({ page }) => {
        const cveResult = {
            cve_id: 'CVE-2021-44228',
            description: 'Log4Shell',
            cvss_score: 10.0,
            epss_score: 0,
            severity: 'CRITICAL',
            affected_projects: [],
            unaffected_projects: [],
        };

        // Impact endpoint returns 204 No Content (broken / empty); byCVE 200.
        await page.route('**/api/v1/vulnerabilities/*/impact', (route) =>
            route.fulfill({ status: 204 }),
        );
        await page.route('**/api/v1/search/cve*', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(cveResult) }),
        );

        await page.goto('/en/search');

        await page.getByPlaceholder('CVE-2021-44228').fill('CVE-2021-44228');
        await page.getByRole('button', { name: 'Search' }).first().click();

        // The byCVE search resolved and rendered its results container...
        await expect(page.getByTestId('search-results')).toBeVisible({ timeout: 10000 });
        // ...but the blast-radius summary must be absent — never a fabricated
        // "No projects affected" from an empty/204 impact response.
        await expect(page.getByTestId('blast-radius-summary')).toHaveCount(0);
        await expect(page.getByTestId('blast-radius-empty')).toHaveCount(0);
    });

    test('should show result count for component search', async ({ page }) => {
        // Version constraint that the unique component satisfies: 1 match.
        await searchComponent(page, uniqueComponent, '<3.0.0');
        const results = page.getByTestId('search-results');
        await expect(results).toContainText(searchResultsText(uniqueComponent, 1, ' (<3.0.0)'));
        await expect(results.getByRole('row').filter({ hasText: uniqueComponent })).toHaveCount(1);

        // ...and one it does not: 0 matches + the empty state.
        await searchComponent(page, uniqueComponent, '>=3.0.0');
        await expect(results).toContainText(searchResultsText(uniqueComponent, 0, ' (>=3.0.0)'));
        await expect(results.getByText(tSearch.noComponentsFound)).toBeVisible();
        await expect(results.getByRole('table')).toHaveCount(0);
    });
});

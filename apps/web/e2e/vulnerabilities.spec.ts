import { test, expect, type Page, type APIRequestContext } from '@playwright/test';
import en from '../messages/en.json';
import {
  API_BASE_URL,
  FIXTURE_CVES,
  createVulnerableProject,
  deleteProject,
  type VulnerableProject,
} from './fixtures/vuln-project';

// Every test here runs against a fresh project that carries exactly the
// four FIXTURE_CVES (2 CRITICAL in KEV, 2 HIGH not in KEV). There is no
// "fresh project has no vulns, so skip" branch: if the fixture is missing
// createVulnerableProject fails the setup.

const vulnTabName = new RegExp(`^${en.Vulnerabilities.title} \\((\\d+)\\)$`);

async function openVulnerabilitiesTab(page: Page, projectId: string): Promise<void> {
  await page.goto(`/en/projects/${projectId}`);
  await page.getByRole('button', { name: vulnTabName }).click();
  // The list is fetched asynchronously; wait until every fixture entry is in.
  await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length, { timeout: 15000 });
}

async function apiOrder(request: APIRequestContext, projectId: string, sort: 'cvss' | 'epss') {
  const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities?sort=${sort}`);
  expect(res.status()).toBe(200);
  return (await res.json()) as Array<{ cve_id: string; cvss_score: number | null }>;
}

test.describe('Vulnerabilities', () => {
  let fixture: VulnerableProject;

  test.beforeAll(async ({ request }) => {
    fixture = await createVulnerableProject(request, 'Vuln Test Project');
  });

  test.afterAll(async ({ request }) => {
    await deleteProject(request, fixture?.projectId);
  });

  test('should trigger vulnerability scan', async ({ page, request }) => {
    // The scan mutates link state in the background, so it gets its own
    // project rather than racing the read-only tests on the shared one.
    const own = await createVulnerableProject(request, 'Vuln Scan Project');
    const statusUrl = `${API_BASE_URL}/api/v1/projects/${own.projectId}/sboms/${own.sbomId}/scan-status`;
    type ScanStatus = { status?: string; error?: string; reasons?: string[]; vulnerabilities?: { total?: number } };
    const pollTerminal = async (): Promise<ScanStatus> => {
      let last: ScanStatus = {};
      await expect
        .poll(
          async () => {
            const res = await request.get(statusUrl);
            expect(res.status()).toBe(200);
            last = await res.json();
            return last.status;
          },
          { timeout: 45000, intervals: [1000] },
        )
        .toMatch(/^(completed|failed)$/);
      return last;
    };
    // A terminal state must explain itself: "failed" carries an error and
    // reasons (the hermetic stack has no NVD/JVN egress, so it ends there
    // with fetch_failed), "completed" carries neither (an online runner).
    // A scanner that marked every run failed without saying why fails here.
    const expectExplained = (s: ScanStatus): void => {
      if (s.status === 'failed') {
        expect(s.error, 'a failed scan must say why').toBeTruthy();
        expect(s.reasons?.length, 'a failed scan must list reasons').toBeGreaterThan(0);
      } else {
        expect(s.error ?? '', 'a completed scan carries no error').toBe('');
      }
    };
    try {
      // The upload already started a scan; let it finish so the rescan below
      // does not overlap it.
      expectExplained(await pollTerminal());

      const scanResponse = await request.post(
        `${API_BASE_URL}/api/v1/projects/${own.projectId}/scan?sbom_id=${own.sbomId}`
      );
      expect(scanResponse.status()).toBe(202);
      const started = await scanResponse.json();
      expect(started.sbom_id).toBe(own.sbomId);
      expect(started.status_url).toBe(`/api/v1/projects/${own.projectId}/sboms/${own.sbomId}/scan-status`);

      const last = await pollTerminal();
      expectExplained(last);
      // The already-linked vulnerabilities survive a (failed) rescan.
      expect(last.vulnerabilities?.total).toBe(FIXTURE_CVES.length);

      await openVulnerabilitiesTab(page, own.projectId);
      await expect(page.getByRole('heading', { name: en.Vulnerabilities.title })).toBeVisible();
      await expect(page.getByRole('button', { name: vulnTabName })).toHaveText(
        new RegExp(`\\(${FIXTURE_CVES.length}\\)$`),
      );
    } finally {
      await deleteProject(request, own.projectId);
    }
  });

  test('should display vulnerability details', async ({ page }) => {
    await openVulnerabilitiesTab(page, fixture.projectId);

    for (const c of FIXTURE_CVES) {
      const v = fixture.vuln(c.cveId);
      // M13-3 F175 #89: the CVE id also appears in the RemediationPanel
      // trigger, so scope through the canonical header span.
      const cveLocator = page.getByTestId('vuln-cve-id').filter({ hasText: c.cveId });
      await expect(cveLocator).toHaveCount(1);
      await expect(cveLocator).toBeVisible();

      // M13-3 F181 #89: exact attribute match on the entry wrapper.
      const entry = page.locator(`[data-vuln-cve-id="${c.cveId}"]`);
      await expect(entry).toHaveCount(1);
      await expect(entry.getByTestId('vuln-cve-id').locator('xpath=following-sibling::*[1]')).toHaveText(c.severity);
      await expect(entry.getByText(`CVSS: ${v.cvss_score}`)).toBeVisible();
      expect(typeof v.description).toBe('string');
      await expect(entry.getByText(v.description as string)).toBeVisible();
    }
  });

  test('should display vulnerability severity badges correctly', async ({ page }) => {
    await openVulnerabilitiesTab(page, fixture.projectId);

    for (const c of FIXTURE_CVES) {
      const entry = page.locator(`[data-vuln-cve-id="${c.cveId}"]`);
      // The severity badge is the element right after the header CVE id
      // (the RemediationPanel repeats the severity further down, so a
      // plain getByText would be satisfied by that copy alone).
      const headerBadge = entry.getByTestId('vuln-cve-id').locator('xpath=following-sibling::*[1]');
      await expect(headerBadge).toHaveText(c.severity);
      // KEV badge only on the KEV-listed CVEs.
      const kev = entry.getByText(en.KEV.badge, { exact: true });
      if (c.inKev) {
        await expect(kev).toBeVisible();
      } else {
        await expect(kev).toHaveCount(0);
      }
    }

    // Tab counter shows the server total.
    await expect(page.getByRole('button', { name: vulnTabName })).toHaveText(
      `${en.Vulnerabilities.title} (${FIXTURE_CVES.length})`,
    );
  });

  // The old "filter vulnerabilities by severity" test looked for a
  // severity combobox / filter buttons that this tab has never rendered
  // and asserted nothing; it was removed. The tab's real list control is
  // the CVSS ⇄ EPSS sort toggle, tested below.

  test('should sort vulnerabilities by CVSS score and toggle to EPSS', async ({ page, request }) => {
    const byCvss = await apiOrder(request, fixture.projectId, 'cvss');
    const byEpss = await apiOrder(request, fixture.projectId, 'epss');
    // Precondition for a discriminating test: CVSS order is descending
    // and the two orders differ (the fixture CVEs have no EPSS score, so
    // EPSS sort falls back to the id tie-break).
    const scores = byCvss.map((v) => v.cvss_score ?? -1);
    expect(scores).toEqual([...scores].sort((a, b) => b - a));
    expect(byEpss.map((v) => v.cve_id)).not.toEqual(byCvss.map((v) => v.cve_id));

    await openVulnerabilitiesTab(page, fixture.projectId);
    const sortGroup = page.getByRole('group', { name: en.Vulnerabilities.sortLabel });
    const cvssButton = sortGroup.getByRole('button', { name: en.Vulnerabilities.sortByCvss, exact: true });
    const epssButton = sortGroup.getByRole('button', { name: en.Vulnerabilities.sortByEpss, exact: true });
    const entries = page.getByTestId('vuln-entry');
    const renderedOrder = () =>
      entries.evaluateAll((els) => els.map((e) => e.getAttribute('data-vuln-cve-id')));

    // Default: CVSS, highest first.
    await expect(cvssButton).toHaveAttribute('aria-pressed', 'true');
    await expect(epssButton).toHaveAttribute('aria-pressed', 'false');
    await expect.poll(renderedOrder).toEqual(byCvss.map((v) => v.cve_id));

    await epssButton.click();
    await expect(epssButton).toHaveAttribute('aria-pressed', 'true');
    await expect(cvssButton).toHaveAttribute('aria-pressed', 'false');
    await expect.poll(renderedOrder).toEqual(byEpss.map((v) => v.cve_id));

    await cvssButton.click();
    await expect.poll(renderedOrder).toEqual(byCvss.map((v) => v.cve_id));
  });

  // M65 bug 3: RemediationPanel fetched the RELATIVE /api/v1/remediation/:cve
  // on the web origin (a Next.js 404) and never rendered the NVD/OSV links.
  // It now calls the API (NEXT_PUBLIC_API_URL) through the API client.
  const remediationUrl = (cveId: string) =>
    (r: { url(): string }) => new URL(r.url()).pathname === `/api/v1/remediation/${cveId}`;

  test('should display CVE link that opens in new tab', async ({ page }) => {
    await openVulnerabilitiesTab(page, fixture.projectId);

    const cveId = FIXTURE_CVES[0].cveId;
    const entry = page.locator(`[data-vuln-cve-id="${cveId}"]`);
    // The real request goes to the API origin, not the web origin, and gets
    // a JSON answer from the API. The hermetic stack is SBOMHUB_OFFLINE, where
    // the API skips OSV and answers 200 with type "manual" guidance.
    const asked = page.waitForRequest(remediationUrl(cveId));
    const answered = page.waitForResponse(remediationUrl(cveId));
    // The RemediationPanel trigger is the button labelled with the CVE id.
    await entry.getByRole('button', { name: new RegExp(cveId) }).click();
    expect(new URL((await asked).url()).origin).toBe(new URL(API_BASE_URL).origin);
    const res = await answered;
    expect(res.headers()['content-type']).toContain('application/json');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.cve_id).toBe(cveId);
    expect(body.remediation.type).toBe('manual');

    const nvdLink = entry.getByRole('link', { name: 'NVD' });
    await expect(nvdLink).toBeVisible({ timeout: 10000 });
    await expect(entry.getByText(en.RemediationPanel.fetchFailed)).toHaveCount(0);
    await expect(entry.getByText(en.RemediationPanel.notAvailable)).toHaveCount(0);
    await expect(nvdLink).toHaveAttribute('href', `https://nvd.nist.gov/vuln/detail/${cveId}`);
    await expect(nvdLink).toHaveAttribute('target', '_blank');
    await expect(nvdLink).toHaveAttribute('rel', /noopener/);
    await expect(entry.getByRole('link', { name: 'OSV' })).toHaveAttribute('href', `https://osv.dev/vulnerability/${cveId}`);
  });

  test('should render remediation guidance returned by the API', async ({ page }) => {
    const cveId = FIXTURE_CVES[0].cveId;
    // Stubbed: the hermetic stack cannot reach OSV. Only the rendering of a
    // successful answer is checked here; the real round trip is above.
    await page.route(`${API_BASE_URL}/api/v1/remediation/${cveId}**`, (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: cveId,
          summary: 'stub',
          severity: 'CRITICAL',
          affected_component: { name: 'log4j-core', ecosystem: 'Maven', current_version: '2.14.1' },
          remediation: { type: 'upgrade', target_version: '2.17.1', commands: { maven: 'mvn versions:use-dep-version -Dincludes=org.apache.logging.log4j:log4j-core -DdepVersion=2.17.1' } },
          workarounds: null,
        }),
      }),
    );
    await openVulnerabilitiesTab(page, fixture.projectId);
    const entry = page.locator(`[data-vuln-cve-id="${cveId}"]`);
    await entry.getByRole('button', { name: new RegExp(cveId) }).click();

    await expect(entry.getByText(en.RemediationPanel.recommendedUpdate.replace('{version}', '2.17.1'), { exact: false })).toBeVisible({ timeout: 10000 });
    await expect(entry.getByText(/mvn versions:use-dep-version/)).toBeVisible();
    await expect(entry.getByRole('link', { name: 'NVD' })).toBeVisible();
    await expect(entry.getByText(en.RemediationPanel.notAvailable)).toHaveCount(0);
    await expect(entry.getByText(en.RemediationPanel.fetchFailed)).toHaveCount(0);
  });

  test('should say remediation is not available when the API answers 404, and still link NVD / OSV', async ({ page }) => {
    const cveId = FIXTURE_CVES[0].cveId;
    // Stubbed: the online "OSV has no entry" answer cannot happen offline.
    await page.route(`${API_BASE_URL}/api/v1/remediation/${cveId}**`, (route) =>
      route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: 'remediation not available' }) }),
    );
    await openVulnerabilitiesTab(page, fixture.projectId);
    const entry = page.locator(`[data-vuln-cve-id="${cveId}"]`);
    await entry.getByRole('button', { name: new RegExp(cveId) }).click();
    await expect(entry.getByText(en.RemediationPanel.notAvailable)).toBeVisible({ timeout: 10000 });
    await expect(entry.getByText(en.RemediationPanel.fetchFailed)).toHaveCount(0);
    await expect(entry.getByRole('link', { name: 'NVD' })).toHaveAttribute('href', `https://nvd.nist.gov/vuln/detail/${cveId}`);
    await expect(entry.getByRole('link', { name: 'OSV' })).toHaveAttribute('href', `https://osv.dev/vulnerability/${cveId}`);
  });

  test('should report a failed remediation request as a failure, and retry on the next open', async ({ page }) => {
    const cveId = FIXTURE_CVES[0].cveId;
    let calls = 0;
    await page.route(`${API_BASE_URL}/api/v1/remediation/${cveId}**`, (route) => {
      calls += 1;
      return route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'boom' }) });
    });
    await openVulnerabilitiesTab(page, fixture.projectId);
    const entry = page.locator(`[data-vuln-cve-id="${cveId}"]`);
    const trigger = entry.getByRole('button', { name: new RegExp(cveId) });
    await trigger.click();
    await expect(entry.getByText(en.RemediationPanel.fetchFailed)).toBeVisible({ timeout: 10000 });
    await expect(entry.getByText(en.RemediationPanel.notAvailable)).toHaveCount(0);
    await trigger.click(); // collapse
    await expect(entry.getByText(en.RemediationPanel.fetchFailed)).toHaveCount(0);
    await trigger.click(); // re-open retries
    await expect(entry.getByText(en.RemediationPanel.fetchFailed)).toBeVisible();
    expect(calls).toBe(2);
  });
});

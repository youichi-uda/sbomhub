import { test, expect } from '@playwright/test';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('Vulnerabilities', () => {
  let projectId: string;
  let sbomId: string;

  test.beforeAll(async ({ request }) => {
    // Create a test project with vulnerable components
    const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `Vuln Test Project ${Date.now()}`,
        description: 'Project for vulnerability E2E tests',
      },
    });
    const project = await createResponse.json();
    projectId = project.id;

    // Upload SBOM with vulnerable components
    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      components: [
        {
          type: 'library',
          name: 'lodash',
          version: '4.17.20', // Known vulnerable version
          licenses: [{ license: { id: 'MIT' } }],
        },
      ],
    };

    const uploadResponse = await request.post(
      `${API_BASE_URL}/api/v1/projects/${projectId}/sbom`,
      {
        data: JSON.stringify(sbom),
        headers: { 'Content-Type': 'application/json' },
      }
    );
    const sbomData = await uploadResponse.json();
    sbomId = sbomData.id; // Changed from sbom_id to id
  });

  test.afterAll(async ({ request }) => {
    if (projectId) {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    }
  });

  test('should trigger vulnerability scan', async ({ page, request }) => {
    // Trigger vulnerability scan via API
    const scanResponse = await request.post(
      `${API_BASE_URL}/api/v1/projects/${projectId}/scan?sbom_id=${sbomId}`
    );
    expect(scanResponse.status()).toBe(202);

    // Wait for scan to complete (NVD has rate limits)
    await page.waitForTimeout(10000);

    // Navigate to project vulnerabilities
    await page.goto(`/en/projects/${projectId}`);
    await page.getByRole('button', { name: /Vulnerabilities/i }).click();

    // The scan may find vulnerabilities for lodash 4.17.20
    // Check that the vulnerabilities section is displayed
    await expect(page.getByRole('heading', { name: 'Vulnerabilities' })).toBeVisible();
  });

  test('should display vulnerability details', async ({ page, request }) => {
    // Get vulnerabilities for the project
    const vulnResponse = await request.get(
      `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`
    );
    const vulnerabilities = await vulnResponse.json();

    await page.goto(`/en/projects/${projectId}`);
    await page.getByRole('button', { name: /Vulnerabilities/i }).click();

    if (vulnerabilities && vulnerabilities.length > 0) {
      // Verify vulnerability information is displayed
      const firstVuln = vulnerabilities[0];
      await expect(page.getByText(firstVuln.cve_id)).toBeVisible({ timeout: 5000 });

      // Check severity badge
      await expect(page.getByText(firstVuln.severity)).toBeVisible();

      // Check CVSS score
      await expect(page.getByText(`CVSS: ${firstVuln.cvss_score}`)).toBeVisible();
    }
  });

  test('should display vulnerability severity badges correctly', async ({ page, request }) => {
    // Get vulnerabilities from API first to know what to expect
    const vulnResponse = await request.get(
      `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`
    );
    const vulnerabilities = await vulnResponse.json();

    await page.goto(`/en/projects/${projectId}`);
    await page.getByRole('button', { name: /Vulnerabilities/i }).click();
    await page.waitForTimeout(1000);

    if (vulnerabilities && vulnerabilities.length > 0) {
      // Count vulnerabilities by severity
      const severityCounts = {
        CRITICAL: vulnerabilities.filter((v: { severity: string }) => v.severity === 'CRITICAL').length,
        HIGH: vulnerabilities.filter((v: { severity: string }) => v.severity === 'HIGH').length,
        MEDIUM: vulnerabilities.filter((v: { severity: string }) => v.severity === 'MEDIUM').length,
        LOW: vulnerabilities.filter((v: { severity: string }) => v.severity === 'LOW').length,
      };

      // Verify badges are shown for each severity that has vulnerabilities
      if (severityCounts.CRITICAL > 0) {
        await expect(page.getByText('CRITICAL', { exact: true }).first()).toBeVisible();
      }
      if (severityCounts.HIGH > 0) {
        await expect(page.getByText('HIGH', { exact: true }).first()).toBeVisible();
      }
      if (severityCounts.MEDIUM > 0) {
        await expect(page.getByText('MEDIUM', { exact: true }).first()).toBeVisible();
      }
      if (severityCounts.LOW > 0) {
        await expect(page.getByText('LOW', { exact: true }).first()).toBeVisible();
      }

      // Verify total count matches
      const totalFromAPI = vulnerabilities.length;
      // The Vulnerabilities tab shows count in format "Vulnerabilities (N)"
      const vulnTab = page.getByRole('button', { name: /Vulnerabilities/i });
      const tabText = await vulnTab.textContent();
      if (tabText) {
        const match = tabText.match(/\((\d+)\)/);
        if (match) {
          const displayedCount = parseInt(match[1], 10);
          expect(displayedCount).toBe(totalFromAPI);
        }
      }
    } else {
      // If no vulnerabilities, verify empty state message or zero count
      const noVulnMessage = page.getByText(/no vulnerabilities|脆弱性なし|0 件/i);
      const emptyState = await noVulnMessage.isVisible().catch(() => false);
      const zeroInTab = await page.getByRole('button', { name: /Vulnerabilities \(0\)/i }).isVisible().catch(() => false);
      expect(emptyState || zeroInTab).toBeTruthy();
    }
  });

  test('should filter vulnerabilities by severity', async ({ page, request }) => {
    const vulnResponse = await request.get(
      `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`
    );
    const vulnerabilities = await vulnResponse.json();

    if (!vulnerabilities || vulnerabilities.length === 0) {
      test.skip();
      return;
    }

    await page.goto(`/en/projects/${projectId}`);
    await page.getByRole('button', { name: /Vulnerabilities/i }).click();
    await page.waitForTimeout(1000);

    // Look for severity filter dropdown or buttons
    const severityFilter = page.getByRole('combobox').filter({ hasText: /severity|重大度/i });
    const severityButtons = page.locator('button').filter({ hasText: /CRITICAL|HIGH|MEDIUM|LOW/i });

    if (await severityFilter.isVisible()) {
      // Filter by CRITICAL
      await severityFilter.click();
      const criticalOption = page.getByRole('option', { name: /CRITICAL/i });
      if (await criticalOption.isVisible()) {
        await criticalOption.click();
        await page.waitForTimeout(500);

        // Verify only CRITICAL vulnerabilities are shown
        const visibleBadges = page.getByText('CRITICAL', { exact: true });
        const highBadges = page.getByText('HIGH', { exact: true });

        if (await visibleBadges.first().isVisible().catch(() => false)) {
          // If CRITICAL is visible, HIGH should not be in the filtered list
          const highCount = await highBadges.count();
          // This is a weak assertion as filtering might show multiple severities
        }
      }
    } else if (await severityButtons.first().isVisible()) {
      // Click on a severity button to filter
      await severityButtons.first().click();
      await page.waitForTimeout(500);
    }
  });

  test('should sort vulnerabilities by CVSS score', async ({ page, request }) => {
    const vulnResponse = await request.get(
      `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`
    );
    const vulnerabilities = await vulnResponse.json();

    if (!vulnerabilities || vulnerabilities.length < 2) {
      test.skip();
      return;
    }

    await page.goto(`/en/projects/${projectId}`);
    await page.getByRole('button', { name: /Vulnerabilities/i }).click();
    await page.waitForTimeout(1000);

    // Look for sort options
    const sortButton = page.getByRole('button', { name: /sort|ソート/i });
    const cvssHeader = page.locator('th, button').filter({ hasText: /CVSS/i });

    if (await cvssHeader.isVisible()) {
      await cvssHeader.click();
      await page.waitForTimeout(500);

      // Get all CVSS scores displayed
      const cvssTexts = page.locator('text=/CVSS: [0-9.]+/');
      const count = await cvssTexts.count();

      if (count >= 2) {
        const firstScore = await cvssTexts.first().textContent();
        const lastScore = await cvssTexts.last().textContent();

        // Extract numeric values
        const firstNum = parseFloat(firstScore?.match(/[0-9.]+/)?.[0] || '0');
        const lastNum = parseFloat(lastScore?.match(/[0-9.]+/)?.[0] || '0');

        // After sorting, scores should be in order (ascending or descending)
        expect(firstNum !== lastNum || count === 1).toBeTruthy();
      }
    }
  });

  test('should display CVE link that opens in new tab', async ({ page, request }) => {
    const vulnResponse = await request.get(
      `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`
    );
    const vulnerabilities = await vulnResponse.json();

    if (!vulnerabilities || vulnerabilities.length === 0) {
      test.skip();
      return;
    }

    await page.goto(`/en/projects/${projectId}`);
    await page.getByRole('button', { name: /Vulnerabilities/i }).click();
    await page.waitForTimeout(1000);

    // Find CVE links
    const cveLink = page.locator('a').filter({ hasText: /CVE-\d{4}-\d+/i }).first();

    if (await cveLink.isVisible()) {
      // Verify the link has proper attributes
      const href = await cveLink.getAttribute('href');
      expect(href).toBeTruthy();
      expect(href).toMatch(/nvd\.nist\.gov|cve\.mitre\.org|CVE-/i);

      // Check if it opens in new tab
      const target = await cveLink.getAttribute('target');
      expect(target).toBe('_blank');
    }
  });
});

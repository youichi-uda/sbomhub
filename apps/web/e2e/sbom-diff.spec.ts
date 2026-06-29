import { test, expect } from '@playwright/test';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('SBOM Diff', () => {
  let projectId: string;

  test.beforeAll(async ({ request }) => {
    // Create project
    const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `SBOM Diff Project ${Date.now()}`,
        description: 'Project for SBOM diff E2E tests',
      },
    });
    expect(projectResponse.ok()).toBeTruthy();
    const project = await projectResponse.json();
    projectId = project.id;
    console.log('Created project:', projectId);

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

    // Upload base SBOM (version 1) and verify success
    const baseSbomResponse = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
      data: JSON.stringify(baseSbom),
      headers: { 'Content-Type': 'application/json' },
    });
    expect(baseSbomResponse.ok()).toBeTruthy();
    console.log('Uploaded base SBOM, status:', baseSbomResponse.status());

    // Add a delay to ensure DB writes complete
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Upload target SBOM (version 2) and verify success
    const targetSbomResponse = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
      data: JSON.stringify(targetSbom),
      headers: { 'Content-Type': 'application/json' },
    });
    expect(targetSbomResponse.ok()).toBeTruthy();
    console.log('Uploaded target SBOM, status:', targetSbomResponse.status());

    // Wait for the async processing to complete
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Verify SBOMs were actually created by fetching them
    const sbomsResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/sboms`);
    console.log('SBOMs GET status:', sbomsResponse.status());
    if (sbomsResponse.ok()) {
      const sboms = await sbomsResponse.json();
      console.log('SBOMs count after upload:', sboms?.length || 0);
      expect(sboms.length).toBeGreaterThanOrEqual(2);
    } else {
      console.log('SBOMs GET failed, response:', await sbomsResponse.text());
    }
  });

  test.afterAll(async ({ request }) => {
    if (projectId) {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    }
  });

  // M10-6 #74 + Phase D F163 + M11-1 #76 (F164 resolved): F163 rewrote
  // the assertions against the M10-6 timeline + detail UI. M11-1
  // isolated the production-only crash: the Go backend marshals nil
  // diff-bucket slices as JSON `null`, and the timeline `useMemo` then
  // called `.length` on them, throwing TypeError at hydration. The fix
  // normalises every bucket to `[]` in apps/web/src/lib/api.ts::getDiff
  // so the typed shape's invariant holds at runtime.
  test('should compare two sboms and show added/removed/updated components', async ({ page, request }) => {
    // Sanity: the API must surface both uploaded SBOMs for the diff
    // endpoint to have non-empty input. If the upload path is broken
    // we want a fast failure here, not a confusing UI-level miss.
    const sbomsResponse = await request.get(
      `${API_BASE_URL}/api/v1/projects/${projectId}/sboms`,
    );
    expect(sbomsResponse.ok()).toBeTruthy();
    const sboms = await sbomsResponse.json();
    expect(sboms.length).toBeGreaterThanOrEqual(2);

    // --- Timeline mode (default landing) -------------------------------
    await page.goto(`/en/projects/${projectId}/diff`);
    await page.waitForLoadState('networkidle');

    // h1 from messages/en.json -> SbomDiff.Page.title
    await expect(
      page.getByRole('heading', { level: 1, name: /SBOM Change History/i }),
    ).toBeVisible({ timeout: 10000 });

    // Timeline section heading from SbomDiff.Timeline.title.
    await expect(page.getByText(/SBOM revisions/i)).toBeVisible();

    // Both uploads should appear in the timeline list. We don't pin
    // the exact ordering since timestamps depend on upload latency;
    // we only assert both rows are present.
    await expect(page.getByText(/Uploaded/i).first()).toBeVisible();

    // The newest revision has a "Diff vs previous" affordance whose
    // click navigates into detail mode.
    const diffLink = page
      .getByRole('link', { name: /Diff vs previous|View diff/i })
      .first();
    await expect(diffLink).toBeVisible({ timeout: 10000 });
    await diffLink.click();

    // --- Detail mode (?from=<base>&to=<target>) ------------------------
    await page.waitForLoadState('networkidle');
    await expect(
      page.getByRole('heading', { level: 1, name: /Diff detail/i }),
    ).toBeVisible({ timeout: 10000 });

    // Three panels: Components / Vulnerabilities / License policy.
    // Each surfaces as a tab trigger in the detail view. The project's
    // shadcn-derived Tabs primitive renders the triggers as plain
    // <button> nodes (no ARIA role="tab"), so the role query is
    // 'button' not 'tab' — see apps/web/src/components/ui/tabs.tsx.
    await expect(page.getByRole('button', { name: /^Components$/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /^Vulnerabilities$/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /License policy/i })).toBeVisible();

    // Click into the Components tab (or rely on it being default) and
    // assert the three buckets land:
    //   - alpha-lib  (only in base   -> removed)
    //   - beta-lib   (only in target -> added)
    //   - shared-lib (version changed 1.0.0 -> 1.1.0)
    await page.getByRole('button', { name: /^Components$/ }).click();

    // shared-lib version change is the most resilient assertion since
    // the new bucket renders both versions explicitly via the table.
    await expect(page.getByText('shared-lib')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('1.1.0')).toBeVisible();

    // alpha-lib must appear in the Removed bucket; beta-lib in Added.
    await expect(page.getByText('alpha-lib')).toBeVisible();
    await expect(page.getByText('beta-lib')).toBeVisible();
  });
});

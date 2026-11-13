import { test, expect, type Page, type Route } from '@playwright/test';
import en from '../messages/en.json';
import ja from '../messages/ja.json';
import {
    createProject,
    createVulnerableProject,
    deleteProject,
    FIXTURE_CVES,
    uniqueName,
    uploadSbom,
    vulnerableSbom,
    type VulnerableProject,
} from './fixtures/vuln-project';

// Integration Codex review 2026-11-13 (High): the project page said
// "No vulnerabilities found." whenever the list was empty. Scans run in the
// background after an upload, so an empty list can also mean the scan is
// still running, failed (MyJVN suspended: fetch_failed + source_unavailable),
// completed without a source the operator switched off (skipped_sources), or
// that its status is unknown. The page now reads
// GET /api/v1/projects/:id/sboms/:sbom_id/scan-status for the latest SBOM.
//
// The hermetic stack runs SBOMHUB_OFFLINE=true, where a real scan completes
// at once, so the other states are produced by rewriting the real
// scan-status answer (route.fetch keeps the API's own CORS headers).

type ScanBody = {
    status: string;
    error?: string;
    reasons?: string[];
    skipped_sources?: string[];
};

/** Answers every scan-status poll of the project with `body()` (read per request). */
async function mockScanStatus(page: Page, projectId: string, body: () => ScanBody) {
    const polls: string[] = [];
    await page.route(
        (url) => url.pathname.startsWith(`/api/v1/projects/${projectId}/sboms/`) && url.pathname.endsWith('/scan-status'),
        async (route: Route) => {
            const res = await route.fetch();
            const real = await res.json();
            const b = body();
            polls.push(b.status);
            await route.fulfill({ response: res, json: { ...real, ...b } });
        },
    );
    return polls;
}

const cleanSbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    version: 1,
    // Synthetic name / purl: nothing to match, on- or offline.
    components: [{ type: 'library', name: 'scan-status-clean-fixture', version: '1.0.0', purl: 'pkg:generic/sbomhub-e2e/scan-status-clean@1.0.0' }],
};

/** "Vulnerabilities (0 · incomplete)" etc. */
const tabText = (count: number | null, qualifier: string | null) =>
    `${en.Vulnerabilities.title} (${qualifier === null ? count : qualifier.replace('{count}', String(count))})`;
const vulnTab = (page: Page) => page.getByRole('button', { name: new RegExp(`^${en.Vulnerabilities.title} \\(`) });
const notice = (page: Page) => page.getByTestId('scan-status-notice');
const empty = (page: Page) => page.getByTestId('vulnerabilities-empty');

test.describe('project page: scan status of the latest SBOM', () => {
    let clean: { id: string } | undefined;
    let noSbom: { id: string } | undefined;
    let vulnerable: VulnerableProject | undefined;

    test.beforeAll(async ({ request }) => {
        clean = await createProject(request, uniqueName('Scan Status Clean'));
        await uploadSbom(request, clean.id, cleanSbom);
        noSbom = await createProject(request, uniqueName('Scan Status No SBOM'));
        vulnerable = await createVulnerableProject(request, 'Scan Status Vulnerable');
    });
    test.afterAll(async ({ request }) => {
        await deleteProject(request, clean?.id);
        await deleteProject(request, noSbom?.id);
        await deleteProject(request, vulnerable?.projectId);
    });
    // A poll may still be in flight in a route handler when a test ends.
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });

    test('running: provisional, never "no vulnerabilities"; on completion the list and count are refetched', async ({ page }) => {
        const projectId = vulnerable!.projectId;
        let phase: 'running' | 'completed' = 'running';
        const polls = await mockScanStatus(page, projectId, () => ({ status: phase }));
        // While running, the list has not been committed yet (each scanner
        // commits at the end of its sweep): the API answers no rows.
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${projectId}/vulnerabilities`,
            async (route) => {
                if (phase !== 'running') return route.fallback();
                const res = await route.fetch();
                await route.fulfill({ response: res, json: [], headers: { ...res.headers(), 'x-total-count': '0' } });
            },
        );

        await page.goto(`/en/projects/${projectId}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await expect(notice(page)).toHaveAttribute('role', 'status');
        await expect(notice(page)).toContainText(en.ScanStatus.runningTitle);
        await expect(vulnTab(page)).toHaveText(tabText(0, en.ScanStatus.tabCountRunning));
        await expect(page.getByTestId('scan-finished-announcer')).toHaveText('');
        await vulnTab(page).click();
        await expect(empty(page)).toHaveAttribute('data-empty-state', 'emptyRunning');
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyRunning);
        await expect(page.getByText(en.ProjectDetail.noVulnerabilities, { exact: true })).toHaveCount(0);
        // It keeps polling while running.
        await expect.poll(() => polls.length, { timeout: 15_000 }).toBeGreaterThanOrEqual(2);

        // The scan finishes: no reload, no tab switch.
        phase = 'completed';
        await expect(notice(page)).toHaveCount(0, { timeout: 15_000 });
        await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length);
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
        await expect(empty(page)).toHaveCount(0);
        // Announced to assistive technology (a stable polite live region).
        await expect(page.getByTestId('scan-finished-announcer')).toHaveText(en.ScanStatus.scanFinishedAnnouncement);
        await expect(page.getByTestId('scan-finished-announcer')).toHaveAttribute('role', 'status');

        // And stops polling once settled.
        const settled = polls.length;
        await page.waitForTimeout(4_000);
        expect(polls.length).toBe(settled);
    });

    test('failed with source_unavailable: an alert with the reasons in words, list may be incomplete', async ({ page }) => {
        const polls = await mockScanStatus(page, clean!.id, () => ({
            status: 'failed',
            error: 'jvn: scan failed (fetch_failed, source_unavailable)',
            reasons: ['fetch_failed', 'source_unavailable'],
        }));
        await page.goto(`/en/projects/${clean!.id}`);
        const alert = page.getByRole('alert').filter({ has: page.getByText(en.ScanStatus.failedTitle) });
        await expect(alert).toBeVisible();
        await expect(alert).toHaveAttribute('data-scan-state', 'failed');
        await expect(alert.locator('[data-reason="source_unavailable"]')).toHaveText(en.ScanStatus.reasonSourceUnavailable);
        await expect(alert.locator('[data-reason="fetch_failed"]')).toHaveText(en.ScanStatus.reasonFetchFailed);
        await expect(alert).toContainText('MyJVN');
        await expect(alert).toContainText('jvn: scan failed (fetch_failed, source_unavailable)');

        await expect(vulnTab(page)).toHaveText(tabText(0, en.ScanStatus.tabCountIncomplete));
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyFailed);
        await expect(page.getByText(en.ProjectDetail.noVulnerabilities, { exact: true })).toHaveCount(0);
        // A failed scan is settled: no polling.
        await page.waitForTimeout(4_000);
        expect(polls.length).toBeLessThanOrEqual(2);
    });

    test('failed, in Japanese', async ({ page }) => {
        await mockScanStatus(page, clean!.id, () => ({
            status: 'failed',
            reasons: ['fetch_failed', 'source_unavailable', 'some_future_reason'],
        }));
        await page.goto(`/ja/projects/${clean!.id}`);
        await expect(notice(page)).toContainText(ja.ScanStatus.failedTitle);
        await expect(notice(page).locator('[data-reason="source_unavailable"]')).toHaveText(ja.ScanStatus.reasonSourceUnavailable);
        // An unrecognised reason is shown, not dropped.
        await expect(notice(page).locator('[data-reason="some_future_reason"]')).toHaveText(
            ja.ScanStatus.reasonOther.replace('{code}', 'some_future_reason'),
        );
    });

    test('unknown: says the status is unknown, not clean', async ({ page }) => {
        await mockScanStatus(page, clean!.id, () => ({ status: 'unknown' }));
        await page.goto(`/en/projects/${clean!.id}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'unknown');
        await expect(notice(page)).toContainText(en.ScanStatus.unknownTitle);
        await expect(vulnTab(page)).toHaveText(tabText(0, en.ScanStatus.tabCountUnconfirmed));
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyUnknown);
        await expect(page.getByText(en.ProjectDetail.noVulnerabilities, { exact: true })).toHaveCount(0);
    });

    test('unknown can be transient: Retry asks again and shows the recovered state (Codex R1)', async ({ page }) => {
        let state = 'unknown';
        await mockScanStatus(page, clean!.id, () => ({ status: state }));
        await page.goto(`/en/projects/${clean!.id}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'unknown');
        state = 'completed';
        await notice(page).getByRole('button', { name: en.Common.retry }).click();
        await expect(notice(page)).toHaveCount(0);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
    });

    test('an unrecognised status string reads as unknown', async ({ page }) => {
        await mockScanStatus(page, clean!.id, () => ({ status: 'finished' }));
        await page.goto(`/en/projects/${clean!.id}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'unknown');
    });

    test('completed with skipped_sources: a persistent coverage notice, also at the empty state', async ({ page }) => {
        await mockScanStatus(page, clean!.id, () => ({ status: 'completed', skipped_sources: ['jvn'] }));
        await page.goto(`/en/projects/${clean!.id}`);
        const coverage = page.getByTestId('scan-coverage-notice');
        await expect(coverage).toHaveAttribute('role', 'status');
        await expect(coverage).toContainText(en.ScanStatus.skippedBody.replace('{sources}', 'JVN'));
        await expect(vulnTab(page)).toHaveText(tabText(0, en.ScanStatus.tabCountPartial));
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyPartial.replace('{sources}', 'JVN'));
        await expect(page.getByText(en.ProjectDetail.noVulnerabilities, { exact: true })).toHaveCount(0);
        // Persistent: still there on another tab.
        await page.getByRole('button', { name: new RegExp(`^${en.Components.title} \\(`) }).click();
        await expect(coverage).toBeVisible();
    });

    // Codex R1 Critical: "completed" does not prove every source / component
    // was looked up (this very stack is SBOMHUB_OFFLINE=true and completes
    // with nothing queried), so even then the page does not say a bare
    // "No vulnerabilities found.".
    test('completed (the real API, nothing mocked): a message scoped to what the scan could look up', async ({ page }) => {
        await page.goto(`/en/projects/${clean!.id}`);
        await expect(vulnTab(page)).toHaveText(tabText(0, null));
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
        await expect(page.getByText(en.ProjectDetail.noVulnerabilities, { exact: true })).toHaveCount(0);
        await expect(notice(page)).toHaveCount(0);
        await expect(page.getByTestId('scan-coverage-notice')).toHaveCount(0);
    });

    test('scan-status cannot be loaded: an alert with Retry, not clean; Retry recovers', async ({ page }) => {
        const path = (url: URL) =>
            url.pathname.startsWith(`/api/v1/projects/${clean!.id}/sboms/`) && url.pathname.endsWith('/scan-status');
        let failedPolls = 0;
        await page.route(path, (route) => {
            failedPolls++;
            return route.fulfill({ status: 500, json: { error: 'failed to get scan status' } });
        });
        await page.goto(`/en/projects/${clean!.id}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'unavailable');
        await expect(notice(page)).toHaveAttribute('role', 'alert');
        await expect(vulnTab(page)).toHaveText(tabText(0, en.ScanStatus.tabCountUnconfirmed));
        const beforeTab = failedPolls;
        await vulnTab(page).click();
        // Opening the tab re-reads the scan state; let that fail too before
        // the outage ends, so the Retry below is what recovers it.
        await expect.poll(() => failedPolls).toBeGreaterThan(beforeTab);
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyUnavailable);
        await expect(page.getByText(en.ProjectDetail.noVulnerabilities, { exact: true })).toHaveCount(0);

        await page.unroute(path);
        await notice(page).getByRole('button', { name: en.Common.retry }).click();
        await expect(notice(page)).toHaveCount(0);
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
    });

    test('no SBOM yet: says nothing was scanned, not "no vulnerabilities"', async ({ page }) => {
        await page.goto(`/en/projects/${noSbom!.id}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyNoSbom);
        await expect(notice(page)).toHaveCount(0);
    });

    test('the vulnerability list cannot be loaded: an error, not "no vulnerabilities"', async ({ page }) => {
        const path = (url: URL) => url.pathname === `/api/v1/projects/${clean!.id}/vulnerabilities`;
        let failedLoads = 0;
        await page.route(path, (route) => {
            failedLoads++;
            return route.fulfill({ status: 500, json: { error: 'internal' } });
        });
        await page.goto(`/en/projects/${clean!.id}`);
        // Visible on the default tab already, not only inside the list (Codex R1).
        await expect(vulnTab(page)).toHaveText(tabText(null, en.ScanStatus.tabCountLoadFailed));
        const beforeTab = failedLoads;
        await vulnTab(page).click();
        // Opening the tab refreshes the list; let that refresh fail too
        // before the outage ends, so the Retry below is what recovers it.
        await expect.poll(() => failedLoads).toBeGreaterThan(beforeTab);
        const err = page.getByTestId('vulnerabilities-load-error');
        await expect(err).toBeVisible();
        await expect(err).toContainText(en.ScanStatus.listLoadFailed);
        await expect(empty(page)).toHaveCount(0);
        await expect(page.getByText(en.ProjectDetail.noVulnerabilities, { exact: true })).toHaveCount(0);
        await page.unroute(path);
        await err.getByRole('button', { name: en.Common.retry }).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
    });

    // Codex R1 High: client request-start order is not server order. A list
    // request issued while a status poll is in flight can be served before
    // the scan commits, and the status can then answer completed. The list
    // must be fetched again after the settled answer arrived.
    test('a list served before the scan committed is not paired with the completed state', async ({ page }) => {
        const projectId = vulnerable!.projectId;
        let phase: 'running' | 'held' | 'completed' = 'running';
        let committed = false;
        let releaseStatus: () => void = () => {};
        const statusHeld = new Promise<void>((r) => (releaseStatus = r));
        let heldSeen = false;
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${projectId}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                if (phase === 'held') {
                    // The server read the state after the commit…
                    heldSeen = true;
                    await statusHeld;
                    committed = true;
                    phase = 'completed';
                    return route.fulfill({ response: res, json: { ...real, status: 'completed' } });
                }
                await route.fulfill({ response: res, json: { ...real, status: phase } });
            },
        );
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${projectId}/vulnerabilities`,
            async (route) => {
                if (committed) return route.fallback();
                const res = await route.fetch();
                await route.fulfill({ response: res, json: [], headers: { ...res.headers(), 'x-total-count': '0' } });
            },
        );
        await page.goto(`/en/projects/${projectId}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await vulnTab(page).click();
        await expect(empty(page)).toHaveAttribute('data-empty-state', 'emptyRunning');

        phase = 'held';
        await expect.poll(() => heldSeen, { timeout: 15_000 }).toBe(true);
        // …while a list request that started LATER was served before it.
        await page.getByRole('button', { name: en.Vulnerabilities.sortByEpss }).click();
        await expect(page.getByRole('button', { name: en.Vulnerabilities.sortByEpss })).toHaveAttribute('aria-pressed', 'true');
        await page.waitForTimeout(500);
        releaseStatus();

        await expect(notice(page)).toHaveCount(0, { timeout: 15_000 });
        await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length);
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
        await expect(empty(page)).toHaveCount(0);
    });
});

// Codex R1 High: an upload must move the page to the NEW SBOM's scan, even
// when the latest-SBOM request from page load is still in flight (react-query
// would otherwise reuse it and answer the old SBOM).
test.describe('project page: uploading an SBOM follows its scan', () => {
    let project: { id: string } | undefined;

    test.beforeAll(async ({ request }) => {
        project = await createProject(request, uniqueName('Scan Status Upload'));
        await uploadSbom(request, project.id, cleanSbom);
    });
    test.afterAll(async ({ request }) => {
        await deleteProject(request, project?.id);
    });
    // A poll may still be in flight in a route handler when a test ends.
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });

    test('upload while the first latest-SBOM request is still pending', async ({ page }) => {
        const projectId = project!.id;
        page.on('dialog', (d) => void d.accept());
        // The first latest-SBOM answer is slow (it answers the OLD SBOM).
        let first = true;
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${projectId}/sbom`,
            async (route) => {
                if (route.request().method() !== 'GET' || !first) return route.fallback();
                first = false;
                const res = await route.fetch();
                await new Promise((r) => setTimeout(r, 4_000));
                await route.fulfill({ response: res });
            },
        );
        let phase: 'running' | 'completed' = 'running';
        const polled = new Set<string>();
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${projectId}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                polled.add(real.sbom_id);
                await route.fulfill({ response: res, json: { ...real, status: phase } });
            },
        );
        let uploadedId = '';
        page.on('response', async (r) => {
            if (r.request().method() === 'POST' && new URL(r.url()).pathname === `/api/v1/projects/${projectId}/sbom`) {
                uploadedId = (await r.json()).id;
            }
        });

        await page.goto(`/en/projects/${projectId}`);
        await page.locator('input[type="file"]').setInputFiles({
            name: 'vulnerable.json',
            mimeType: 'application/json',
            buffer: Buffer.from(JSON.stringify(vulnerableSbom())),
        });
        await expect.poll(() => uploadedId).not.toBe('');
        // The page polls the NEW SBOM's scan and shows it running.
        await expect.poll(() => polled.has(uploadedId), { timeout: 15_000 }).toBe(true);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        // Still the new SBOM after the slow pre-upload answer arrived.
        await page.waitForTimeout(4_500);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');

        phase = 'completed';
        await expect(notice(page)).toHaveCount(0, { timeout: 15_000 });
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
    });
});

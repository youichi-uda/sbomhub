import { test, expect, type Page, type Route } from '@playwright/test';
import en from '../messages/en.json';
import ja from '../messages/ja.json';
import {
    createProject,
    createVulnerableProject,
    deleteProject,
    API_BASE_URL,
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
    vulnerabilities?: { total: number };
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
        // A failed scan is settled: no fast polling (re-read once a minute).
        await page.waitForTimeout(1_000);
        const settled = polls.length;
        await page.waitForTimeout(4_000);
        expect(polls.length).toBe(settled);
    });

    test('failed, in Japanese', async ({ page }) => {
        await mockScanStatus(page, clean!.id, () => ({
            status: 'failed',
            reasons: ['fetch_failed', 'source_unavailable', 'some_future_reason'],
        }));
        await page.goto(`/ja/projects/${clean!.id}`);
        // A settled answer is shown once its list re-read is in (several
        // requests): allow for a busy dev server.
        await expect(notice(page)).toContainText(ja.ScanStatus.failedTitle, { timeout: 15_000 });
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
        // unknown may mean another replica is still scanning (Codex R2 Low).
        await expect(page.getByTestId('scan-finished-announcer')).toHaveText('');
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

        await page.waitForLoadState('networkidle');
        await page.unroute(path);
        await notice(page).getByRole('button', { name: en.Common.retry }).click();
        await expect(notice(page)).toHaveCount(0);
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
    });

    test('no SBOM yet: says nothing was scanned, not "no vulnerabilities"', async ({ page }) => {
        await page.goto(`/en/projects/${noSbom!.id}`);
        // The always-visible counter does not say a bare 0 either (Codex R6).
        await expect(vulnTab(page)).toHaveText(tabText(null, en.ScanStatus.tabCountNotScanned));
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
        // Nothing still in flight may end the outage's effect by itself.
        await page.waitForLoadState('networkidle');
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

// Codex R2: pairing the scan state with a list that belongs to it.
test.describe('project page: the scan state and the list stay paired (Codex R2)', () => {
    const projects: string[] = [];
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        for (const id of projects) await deleteProject(request, id);
    });

    test('CI uploads another SBOM while this one settles: the page moves to the new SBOM', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status External Upload'));
        projects.push(p.id);
        const first = await uploadSbom(request, p.id, cleanSbom);
        let phase: 'running' | 'held' = 'running';
        let release: () => void = () => {};
        const held = new Promise<void>((r) => (release = r));
        let heldSeen = false;
        const polled = new Set<string>();
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${p.id}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                polled.add(real.sbom_id);
                if (real.sbom_id !== first) {
                    // the new SBOM: its scan is running
                    return route.fulfill({ response: res, json: { ...real, status: 'running' } });
                }
                if (phase === 'held') {
                    heldSeen = true;
                    await held;
                    return route.fulfill({ response: res, json: { ...real, status: 'completed' } });
                }
                await route.fulfill({ response: res, json: { ...real, status: 'running' } });
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        phase = 'held';
        await expect.poll(() => heldSeen, { timeout: 15_000 }).toBe(true);
        // While the first SBOM's settled answer is on its way, CI uploads another.
        const second = await uploadSbom(request, p.id, vulnerableSbom());
        release();
        await expect.poll(() => polled.has(second), { timeout: 15_000 }).toBe(true);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await expect(vulnTab(page)).toHaveText(/·/);
        await expect(page.getByTestId('scan-finished-announcer')).toHaveText('');
    });

    test('a later scan of the same SBOM is noticed (settled states are re-read)', async ({ page, request }) => {
        const vp = await createVulnerableProject(request, 'Scan Status Rescan');
        projects.push(vp.projectId);
        await page.clock.install();
        // First the SBOM's scan settled with nothing committed yet…
        let total = 0;
        await mockScanStatus(page, vp.projectId, () => ({ status: 'completed', vulnerabilities: { total } }) as ScanBody);
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${vp.projectId}/vulnerabilities`,
            async (route) => {
                if (total > 0) return route.fallback();
                const res = await route.fetch();
                await route.fulfill({ response: res, json: [], headers: { ...res.headers(), 'x-total-count': '0' } });
            },
        );
        await page.goto(`/en/projects/${vp.projectId}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
        // Let the tab's own refresh (latest SBOM → state → list) finish first,
        // so only the re-read below can bring the new findings in.
        await page.waitForTimeout(2_000);
        // …then a manual rescan of the same SBOM committed findings.
        total = FIXTURE_CVES.length;
        await page.clock.fastForward('01:05');
        await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length, { timeout: 15_000 });
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
    });

    test('a sort switched while the settled list is refetched is "checking", not the final result', async ({ page }) => {
        // Uses its own project so the counts are its own.
        test.slow();
        const request = page.request;
        const vp = await createVulnerableProject(request, 'Scan Status Sort Race');
        projects.push(vp.projectId);
        let phase: 'running' | 'completed' = 'running';
        const statusPolls = await mockScanStatus(page, vp.projectId, () => ({ status: phase }));
        let releaseEpss: () => void = () => {};
        const epssHeld = new Promise<void>((r) => (releaseEpss = r));
        let cvssSettleSeen = false;
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${vp.projectId}/vulnerabilities`,
            async (route) => {
                const sort = new URL(route.request().url()).searchParams.get('sort');
                if (phase === 'running') {
                    const res = await route.fetch();
                    return route.fulfill({ response: res, json: [], headers: { ...res.headers(), 'x-total-count': '0' } });
                }
                if (sort === 'epss') await epssHeld;
                else {
                    // the list refetch of the settled answer (a completed
                    // answer has been served), not some earlier refresh
                    if (statusPolls.includes('completed')) cvssSettleSeen = true;
                    await new Promise((r) => setTimeout(r, 1_500));
                }
                return route.fallback();
            },
        );
        await page.goto(`/en/projects/${vp.projectId}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveAttribute('data-empty-state', 'emptyRunning');
        phase = 'completed';
        // The settled answer's list refetch (CVSS) is slow; switch to EPSS meanwhile.
        await expect.poll(() => cvssSettleSeen, { timeout: 15_000 }).toBe(true);
        await page.getByRole('button', { name: en.Vulnerabilities.sortByEpss }).click();
        await page.waitForTimeout(2_000);
        // The scan has completed, but the EPSS list is still loading: the
        // rows on screen (the CVSS list, or none) are not the final result.
        await expect(vulnTab(page)).toHaveText(new RegExp(`^${en.Vulnerabilities.title} \\(\\d+ · (checking|scanning)\\)$`));
        await expect(page.locator('[data-empty-state="emptyCompleted"]')).toHaveCount(0);
        releaseEpss();
        await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length);
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
    });

    test('a failed refresh that keeps the earlier rows does not show their count as final', async ({ page, request }) => {
        const vp = await createVulnerableProject(request, 'Scan Status Stale Rows');
        projects.push(vp.projectId);
        await page.goto(`/en/projects/${vp.projectId}`);
        await vulnTab(page).click();
        await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length);
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${vp.projectId}/vulnerabilities`,
            (route) => route.fulfill({ status: 500, json: { error: 'internal' } }),
        );
        // Leave and re-open the tab: the refresh fails, the rows stay.
        await page.getByRole('button', { name: new RegExp(`^${en.Components.title} \\(`) }).click();
        await vulnTab(page).click();
        await expect(page.getByTestId('vulnerabilities-load-error')).toBeVisible();
        await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length);
        await expect(vulnTab(page)).toHaveText(tabText(null, en.ScanStatus.tabCountLoadFailed));
    });

    test('one Retry recovers when the latest-SBOM and scan-status reads both failed', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status Chain Retry'));
        projects.push(p.id);
        await uploadSbom(request, p.id, cleanSbom);
        await page.goto(`/en/projects/${p.id}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
        // Nothing from page load may still be in flight when the outage starts
        // (a late successful read would end the outage's effect by itself).
        await page.waitForLoadState('networkidle');
        let outage = true;
        let failures = 0;
        await page.route(
            (url) =>
                url.pathname === `/api/v1/projects/${p.id}/sbom` ||
                (url.pathname.startsWith(`/api/v1/projects/${p.id}/sboms/`) && url.pathname.endsWith('/scan-status')),
            (route) => {
                if (!outage || route.request().method() !== 'GET') return route.fallback();
                failures++;
                return route.fulfill({ status: 500, json: { error: 'internal' } });
            },
        );
        // Re-open the tab during the outage: both reads fail.
        await page.getByRole('button', { name: new RegExp(`^${en.Components.title} \\(`) }).click();
        await vulnTab(page).click();
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'unavailable');
        // The tab's refresh has run its course under the outage, Retry idle.
        await expect.poll(() => failures).toBeGreaterThanOrEqual(1);
        await expect(notice(page).getByRole('button', { name: en.Common.retry })).toBeEnabled();
        await page.waitForLoadState('networkidle');
        outage = false;
        await notice(page).getByRole('button', { name: en.Common.retry }).click();
        await expect(notice(page)).toHaveCount(0);
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
    });
});

// Codex R3.
test.describe('project page: settled answers that move, uploads during a scan, the truncation banner (Codex R3)', () => {
    const projects: string[] = [];
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        for (const id of projects) await deleteProject(request, id);
    });

    test('a second settled read that differs from the first gets its own fresh list', async ({ page, request }) => {
        const vp = await createVulnerableProject(request, 'Scan Status Moving Settle');
        projects.push(vp.projectId);
        // running → (settle) completed/0, list read before the commit → completed/4
        let phase: 'running' | 'settling' = 'running';
        let committed = false;
        let settleReads = 0;
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${vp.projectId}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                if (phase === 'running') return route.fulfill({ response: res, json: { ...real, status: 'running' } });
                settleReads++;
                const total = committed ? FIXTURE_CVES.length : 0;
                await route.fulfill({ response: res, json: { ...real, status: 'completed', vulnerabilities: { ...real.vulnerabilities, total } } });
            },
        );
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${vp.projectId}/vulnerabilities`,
            async (route) => {
                if (committed) return route.fallback();
                const res = await route.fetch();
                await route.fulfill({ response: res, json: [], headers: { ...res.headers(), 'x-total-count': '0' } });
                // The list was served before another scan's findings landed;
                // the next state read sees them.
                if (phase === 'settling' && settleReads > 0) committed = true;
            },
        );
        await page.goto(`/en/projects/${vp.projectId}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveAttribute('data-empty-state', 'emptyRunning');
        // The tab's own refresh must be over: only the settle may fetch the list.
        await page.waitForLoadState('networkidle');
        phase = 'settling';
        await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length, { timeout: 15_000 });
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
    });

    test('CI uploads another SBOM while this one is still running: the page moves to it', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status Upload While Running'));
        projects.push(p.id);
        const first = await uploadSbom(request, p.id, cleanSbom);
        await page.clock.install();
        const polled = new Set<string>();
        await mockScanStatus(page, p.id, () => ({ status: 'running' }));
        page.on('request', (r) => {
            const m = new URL(r.url()).pathname.match(/\/sboms\/([^/]+)\/scan-status$/);
            if (m) polled.add(m[1]);
        });
        await page.goto(`/en/projects/${p.id}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await expect.poll(() => polled.has(first)).toBe(true);
        const second = await uploadSbom(request, p.id, cleanSbom);
        await page.clock.fastForward('01:05');
        await expect.poll(() => polled.has(second), { timeout: 15_000 }).toBe(true);
    });

    test('the truncation banner is translated, and hidden while its numbers are not current', async ({ page, request }) => {
        const vp = await createVulnerableProject(request, 'Scan Status Truncated');
        projects.push(vp.projectId);
        let fail = false;
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${vp.projectId}/vulnerabilities`,
            async (route) => {
                if (fail) return route.fulfill({ status: 500, json: { error: 'internal' } });
                const res = await route.fetch();
                // The server reports more matches than one page holds.
                await route.fulfill({ response: res, headers: { ...res.headers(), 'x-total-count': '150' } });
            },
        );
        await page.goto(`/en/projects/${vp.projectId}`);
        await vulnTab(page).click();
        const banner = page.getByTestId('vulnerabilities-truncated');
        await expect(banner).toContainText(
            en.ScanStatus.truncatedTitle.replace('{shown}', String(FIXTURE_CVES.length)).replace('{total}', '150'),
        );
        await expect(page.getByText('脆弱性が表示件数を超えています')).toHaveCount(0);
        // A failed refresh keeps the rows, but the banner's numbers are not current.
        fail = true;
        await page.getByRole('button', { name: new RegExp(`^${en.Components.title} \\(`) }).click();
        await vulnTab(page).click();
        await expect(page.getByTestId('vulnerabilities-load-error')).toBeVisible();
        await expect(banner).toHaveCount(0);
    });
});

// Codex R4.
test.describe('project page: list bound to its SBOM, coverage changes between reads (Codex R4)', () => {
    const projects: string[] = [];
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        for (const id of projects) await deleteProject(request, id);
    });

    test("a newer SBOM found while scanning shows its own list, not the previous SBOM's rows", async ({ page, request }) => {
        const vp = await createVulnerableProject(request, 'Scan Status List Bound');
        projects.push(vp.projectId);
        await page.clock.install();
        const polled = new Set<string>();
        await mockScanStatus(page, vp.projectId, () => ({ status: 'running' }));
        page.on('request', (r) => {
            const m = new URL(r.url()).pathname.match(/\/sboms\/([^/]+)\/scan-status$/);
            if (m) polled.add(m[1]);
        });
        await page.goto(`/en/projects/${vp.projectId}`);
        await vulnTab(page).click();
        await expect(page.getByTestId('vuln-entry')).toHaveCount(FIXTURE_CVES.length);
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, en.ScanStatus.tabCountRunning));
        // CI uploads a clean SBOM; the page finds it on its next latest-SBOM read.
        const second = await uploadSbom(request, vp.projectId, cleanSbom);
        await page.clock.fastForward('01:05');
        await expect.poll(() => polled.has(second), { timeout: 15_000 }).toBe(true);
        await expect(page.getByTestId('vuln-entry')).toHaveCount(0);
        await expect(vulnTab(page)).toHaveText(tabText(0, en.ScanStatus.tabCountRunning));
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyRunning);
    });

    test('skipped sources that appear between two settled reads are shown, not the first read', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status Coverage Moves'));
        projects.push(p.id);
        await uploadSbom(request, p.id, cleanSbom);
        let phase: 'running' | 'settling' = 'running';
        let listServedWhileSettling = false;
        await mockScanStatus(page, p.id, () =>
            phase === 'running'
                ? { status: 'running' }
                : { status: 'completed', skipped_sources: listServedWhileSettling ? ['jvn'] : [] },
        );
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${p.id}/vulnerabilities`,
            async (route) => {
                const res = await route.fetch();
                await route.fulfill({ response: res });
                if (phase === 'settling') listServedWhileSettling = true;
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveAttribute('data-empty-state', 'emptyRunning');
        await page.waitForLoadState('networkidle');
        phase = 'settling';
        await expect(page.getByTestId('scan-coverage-notice')).toBeVisible({ timeout: 15_000 });
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyPartial.replace('{sources}', 'JVN'));
        await expect(vulnTab(page)).toHaveText(tabText(0, en.ScanStatus.tabCountPartial));
    });
});

// Codex R5: the list endpoint answers for whichever SBOM is latest; a list
// fetched for SBOM A after CI uploaded B must not be shown as A's.
test.describe('project page: a list read after another upload (Codex R5)', () => {
    let projectId: string | undefined;
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        await deleteProject(request, projectId);
    });

    test('a sort switch after CI uploaded another SBOM moves the page to that SBOM', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status Sort After Upload'));
        projectId = p.id;
        const first = await uploadSbom(request, p.id, cleanSbom);
        const polled = new Set<string>();
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${p.id}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                polled.add(real.sbom_id);
                // the first SBOM's scan is done; any later one is still running
                await route.fulfill({ response: res, json: { ...real, status: real.sbom_id === first ? 'completed' : 'running' } });
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
        await page.waitForLoadState('networkidle');
        // CI uploads another SBOM (with findings); before the page's next
        // latest-SBOM read, the user switches the sort.
        const second = await uploadSbom(request, p.id, vulnerableSbom());
        await page.getByRole('button', { name: en.Vulnerabilities.sortByEpss }).click();
        await expect.poll(() => polled.has(second), { timeout: 15_000 }).toBe(true);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await expect(vulnTab(page)).toHaveText(new RegExp(`· scanning\\)$`));
    });
});

// Codex R6.
test.describe('project page: malformed settled answers, leaving mid-check (Codex R6)', () => {
    let projectId: string | undefined;
    test.beforeAll(async ({ request }) => {
        projectId = (await createProject(request, uniqueName('Scan Status R6'))).id;
        await uploadSbom(request, projectId, cleanSbom);
    });
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        await deleteProject(request, projectId);
    });

    test('a completed answer without a finding total reads as unknown and stops fast polling', async ({ page }) => {
        const polls = await mockScanStatus(page, projectId!, () => ({ status: 'completed', vulnerabilities: {} }) as unknown as ScanBody);
        await page.goto(`/en/projects/${projectId}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'unknown');
        await page.waitForLoadState('networkidle');
        const settled = polls.length;
        await page.waitForTimeout(7_000);
        expect(polls.length).toBe(settled);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'unknown');
    });

    test('leaving the page while a settled answer is being checked starts no further requests', async ({ page }) => {
        let release: () => void = () => {};
        const held = new Promise<void>((r) => (release = r));
        let heldSeen = false;
        let phase: 'running' | 'held' = 'running';
        let afterRelease = 0;
        let released = false;
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${projectId}`),
            async (route) => {
                if (released) afterRelease++;
                const path = new URL(route.request().url()).pathname;
                if (!path.endsWith('/scan-status')) return route.fallback();
                const res = await route.fetch();
                const real = await res.json();
                if (phase === 'held') {
                    heldSeen = true;
                    await held;
                    return route.fulfill({ response: res, json: { ...real, status: 'completed' } });
                }
                return route.fulfill({ response: res, json: { ...real, status: 'running' } });
            },
        );
        await page.goto(`/en/projects/${projectId}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        phase = 'held';
        await expect.poll(() => heldSeen, { timeout: 15_000 }).toBe(true);
        // Client-side navigation away from the project page.
        await page.getByRole('link', { name: en.ProjectDetail.backToProjects }).click();
        await expect(page).toHaveURL(/\/en\/projects\/?$/);
        released = true;
        release();
        await page.waitForTimeout(2_000);
        expect(afterRelease).toBe(0);
    });
});

// Codex R8: every list read is checked against the scan state, not only
// the ones the scan-status query starts.
test.describe('project page: a list read while a new scan of the same SBOM runs (Codex R8)', () => {
    let projectId: string | undefined;
    test.beforeAll(async ({ request }) => {
        projectId = (await createVulnerableProject(request, 'Scan Status R8')).projectId;
    });
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        await deleteProject(request, projectId);
    });

    test('a sort switch during a rescan shows the scan as running, not the completed state', async ({ page }) => {
        let state = 'completed';
        await mockScanStatus(page, projectId!, () => ({ status: state }));
        await page.goto(`/en/projects/${projectId}`);
        await vulnTab(page).click();
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
        await page.waitForLoadState('networkidle');
        // A manual rescan of the same SBOM starts; the user switches the sort.
        state = 'running';
        await page.getByRole('button', { name: en.Vulnerabilities.sortByEpss }).click();
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, en.ScanStatus.tabCountRunning));
    });

    test('a list Retry during a rescan shows the scan as running', async ({ page }) => {
        let state = 'completed';
        let failList = false;
        await mockScanStatus(page, projectId!, () => ({ status: state }));
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${projectId}/vulnerabilities`,
            (route) => (failList ? route.fulfill({ status: 500, json: { error: 'internal' } }) : route.fallback()),
        );
        await page.goto(`/en/projects/${projectId}`);
        await vulnTab(page).click();
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
        await page.waitForLoadState('networkidle');
        // The EPSS list fails to load…
        failList = true;
        await page.getByRole('button', { name: en.Vulnerabilities.sortByEpss }).click();
        const err = page.getByTestId('vulnerabilities-load-error');
        await expect(err).toBeVisible();
        await page.waitForLoadState('networkidle');
        // …a rescan of the same SBOM starts, the outage ends, the user retries.
        failList = false;
        state = 'running';
        await err.getByRole('button', { name: en.Common.retry }).click();
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await expect(vulnTab(page)).toHaveText(new RegExp(`· scanning\\)$`));
    });
});

// Codex R9: reads that overlap. A settled-state poll still in flight when a
// rescan starts and the user switches the sort; an old latest-SBOM answer
// arriving after a newer SBOM was seen.
test.describe('project page: overlapping reads (Codex R9)', () => {
    const projects: string[] = [];
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        for (const id of projects) await deleteProject(request, id);
    });

    test('a stale settled poll answering after a rescan began does not restore the settled state', async ({ page, request }) => {
        const vp = await createVulnerableProject(request, 'Scan Status R9 Stale Poll');
        projects.push(vp.projectId);
        await page.clock.install();
        let state = 'completed';
        let holdNext = false;
        let heldSeen = false;
        let release: () => void = () => {};
        const held = new Promise<void>((r) => (release = r));
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${vp.projectId}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                if (holdNext) {
                    holdNext = false;
                    heldSeen = true;
                    const answer = state; // read before the rescan began
                    await held;
                    return route.fulfill({ response: res, json: { ...real, status: answer } });
                }
                await route.fulfill({ response: res, json: { ...real, status: state } });
            },
        );
        await page.goto(`/en/projects/${vp.projectId}`);
        await vulnTab(page).click();
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null));
        await page.waitForLoadState('networkidle');
        holdNext = true;
        await page.clock.fastForward('01:05'); // the once-a-minute re-read starts…
        await expect.poll(() => heldSeen, { timeout: 15_000 }).toBe(true);
        state = 'running'; // …a rescan begins…
        await page.getByRole('button', { name: en.Vulnerabilities.sortByEpss }).click(); // …the user re-sorts
        await page.waitForTimeout(1_000);
        release(); // the stale "completed" arrives last
        await page.waitForTimeout(2_000);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await expect(vulnTab(page)).toHaveText(new RegExp(`· scanning\\)$`));
    });

    test('an old latest-SBOM answer arriving after a newer SBOM was seen does not move the page back', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status R9 Old Latest'));
        projects.push(p.id);
        const first = await uploadSbom(request, p.id, cleanSbom);
        await page.clock.install();
        let holdNextLatest = false;
        let heldSeen = false;
        let release: () => void = () => {};
        const held = new Promise<void>((r) => (release = r));
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${p.id}/sbom`,
            async (route) => {
                if (route.request().method() !== 'GET' || !holdNextLatest) return route.fallback();
                holdNextLatest = false;
                const res = await route.fetch(); // answered now: the OLD latest SBOM
                heldSeen = true;
                await held;
                return route.fulfill({ response: res });
            },
        );
        const polled = new Set<string>();
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${p.id}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                polled.add(real.sbom_id);
                await route.fulfill({ response: res, json: { ...real, status: real.sbom_id === first ? 'completed' : 'running' } });
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
        await page.waitForLoadState('networkidle');
        holdNextLatest = true;
        await page.clock.fastForward('01:05'); // a once-a-minute latest-SBOM read starts and is slow
        await expect.poll(() => heldSeen, { timeout: 15_000 }).toBe(true);
        const second = await uploadSbom(request, p.id, cleanSbom); // CI uploads
        await page.getByRole('button', { name: en.Vulnerabilities.sortByEpss }).click(); // a read that sees it
        await expect.poll(() => polled.has(second), { timeout: 15_000 }).toBe(true);
        release(); // the old answer (the first SBOM) arrives last
        await page.waitForTimeout(2_000);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await expect(vulnTab(page)).toHaveText(new RegExp(`· scanning\\)$`));
    });
});

// Codex R10: a refresh of the same sort, and a refresh that fails on a new SBOM.
test.describe('project page: refreshes of the snapshot (Codex R10)', () => {
    const projects: string[] = [];
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        for (const id of projects) await deleteProject(request, id);
    });

    test('after an upload, the previous SBOM\'s final count is not shown while the new one is read', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status R10 Upload'));
        projects.push(p.id);
        await uploadSbom(request, p.id, cleanSbom);
        page.on('dialog', (d) => void d.accept());
        let holdLatest = false;
        let release: () => void = () => {};
        const held = new Promise<void>((r) => (release = r));
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${p.id}/sbom`,
            async (route) => {
                if (route.request().method() !== 'GET' || !holdLatest) return route.fallback();
                await held;
                return route.fallback();
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
        await expect(vulnTab(page)).toHaveText(tabText(0, null));
        await page.waitForLoadState('networkidle');
        // Upload from the page; the re-read of the latest SBOM is slow.
        holdLatest = true;
        await page.getByRole('button', { name: new RegExp(`^${en.Projects.upload}`) }).click();
        await page.locator('input[type="file"]').setInputFiles({
            name: 'next.json',
            mimeType: 'application/json',
            buffer: Buffer.from(JSON.stringify(vulnerableSbom())),
        });
        await vulnTab(page).click();
        // The old SBOM's completed state is not presented as final meanwhile.
        await expect(vulnTab(page)).not.toHaveText(tabText(0, null));
        await expect(page.locator('[data-empty-state="emptyCompleted"]')).toHaveCount(0);
        holdLatest = false;
        release();
    });

    test('a refresh that fails after a new SBOM was found does not keep the old SBOM\'s notice', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status R10 Failed Refresh'));
        projects.push(p.id);
        const first = await uploadSbom(request, p.id, cleanSbom);
        let failList = false;
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${p.id}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                const json = real.sbom_id === first
                    ? { ...real, status: 'failed', reasons: ['source_unavailable'] }
                    : { ...real, status: 'completed' };
                await route.fulfill({ response: res, json });
            },
        );
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${p.id}/vulnerabilities`,
            (route) => (failList ? route.fulfill({ status: 500, json: { error: 'internal' } }) : route.fallback()),
        );
        await page.goto(`/en/projects/${p.id}`);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'failed');
        await page.waitForLoadState('networkidle');
        await uploadSbom(request, p.id, cleanSbom); // CI: a new SBOM…
        failList = true; // …whose list cannot be read
        await vulnTab(page).click();
        await expect(page.getByTestId('vulnerabilities-load-error')).toBeVisible();
        // The first SBOM's "failed" notice no longer stands for the latest SBOM.
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'unavailable');
    });
});

// Codex R11: refreshes that overlap other refreshes, and the project-wide Retry.
test.describe('project page: overlapping foreground refreshes (Codex R11)', () => {
    const projects: string[] = [];
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        for (const id of projects) await deleteProject(request, id);
    });

    test('project Retry does not show the snapshot cached behind the error screen as current', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status R11 Project Retry'));
        projects.push(p.id);
        const projectName = (await (await request.get(`${API_BASE_URL}/api/v1/projects/${p.id}`)).json()).name as string;
        await uploadSbom(request, p.id, cleanSbom);
        let projectFails = true;
        let holdLatest = false;
        let release: () => void = () => {};
        const held = new Promise<void>((r) => (release = r));
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${p.id}`,
            (route) =>
                route.request().method() === 'GET' && projectFails
                    ? route.fulfill({ status: 500, json: { error: 'failed to get project' } })
                    : route.fallback(),
        );
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${p.id}/sbom`,
            async (route) => {
                if (route.request().method() !== 'GET' || !holdLatest) return route.fallback();
                await held;
                return route.fallback();
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        const alert = page.getByTestId('project-load-error');
        await expect(alert).toBeVisible();
        await page.waitForLoadState('networkidle'); // the snapshot (completed, 0) is cached
        await uploadSbom(request, p.id, vulnerableSbom()); // CI uploads meanwhile
        projectFails = false;
        holdLatest = true; // the snapshot re-read is slow
        await alert.getByRole('button', { name: en.Common.retry }).click();
        await expect(page.getByRole('heading', { level: 1, name: projectName })).toBeVisible();
        await expect(vulnTab(page)).not.toHaveText(tabText(0, null));
        await expect(page.getByTestId('scan-finished-announcer')).toHaveText('');
        holdLatest = false;
        release();
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null), { timeout: 15_000 });
    });

    test('upload, then open the tab at once: the previous state stays hidden until the new snapshot', async ({ page, request }) => {
        const p = await createProject(request, uniqueName('Scan Status R11 Upload Tab'));
        projects.push(p.id);
        await uploadSbom(request, p.id, cleanSbom);
        page.on('dialog', (d) => void d.accept());
        let holdLatest = false;
        let release: () => void = () => {};
        const held = new Promise<void>((r) => (release = r));
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${p.id}/sbom`,
            async (route) => {
                if (route.request().method() !== 'GET' || !holdLatest) return route.fallback();
                await held;
                return route.fallback();
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        await expect(page.getByTestId('scan-finished-announcer')).toHaveText(en.ScanStatus.scanFinishedAnnouncement);
        await page.waitForLoadState('networkidle');
        holdLatest = true;
        await page.locator('input[type="file"]').setInputFiles({
            name: 'next.json',
            mimeType: 'application/json',
            buffer: Buffer.from(JSON.stringify(vulnerableSbom())),
        });
        // Upload done (its refresh is held); the tab refresh replaces it.
        await page.waitForTimeout(1_000);
        await vulnTab(page).click();
        await page.waitForTimeout(1_000);
        await expect(page.getByTestId('scan-finished-announcer')).toHaveText('');
        await expect(page.locator('[data-empty-state="emptyCompleted"]')).toHaveCount(0);
        holdLatest = false;
        release();
        await expect(vulnTab(page)).toHaveText(tabText(FIXTURE_CVES.length, null), { timeout: 15_000 });
    });
});

// Codex R12 Low: leaving the page aborts the latest-SBOM and list requests
// themselves (not only the requests after them).
test.describe('project page: leaving aborts the snapshot requests in flight (Codex R12)', () => {
    let projectId: string | undefined;
    test.beforeAll(async ({ request }) => {
        projectId = (await createProject(request, uniqueName('Scan Status R12 Abort'))).id;
        await uploadSbom(request, projectId, cleanSbom);
    });
    test.afterEach(async ({ page }) => {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
    });
    test.afterAll(async ({ request }) => {
        await deleteProject(request, projectId);
    });

    for (const [name, matches] of [
        ['latest SBOM', (path: string) => path === `/api/v1/projects/${projectId}/sbom`],
        ['vulnerability list', (path: string) => path === `/api/v1/projects/${projectId}/vulnerabilities`],
    ] as const) {
        test(`the ${name} request is aborted on leaving`, async ({ page }) => {
            let release: () => void = () => {};
            const held = new Promise<void>((r) => (release = r));
            let heldSeen = false;
            const aborted: string[] = [];
            page.on('requestfailed', (r) => aborted.push(new URL(r.url()).pathname));
            await page.route(
                (url) => matches(url.pathname),
                async (route) => {
                    if (route.request().method() !== 'GET') return route.fallback();
                    heldSeen = true;
                    await held;
                    return route.fallback().catch(() => {});
                },
            );
            await page.goto(`/en/projects/${projectId}`);
            await expect.poll(() => heldSeen, { timeout: 15_000 }).toBe(true);
            await page.getByRole('link', { name: en.ProjectDetail.backToProjects }).click();
            await expect(page).toHaveURL(/\/en\/projects\/?$/);
            await expect.poll(() => aborted.some((p) => matches(p)), { timeout: 10_000 }).toBe(true);
            release();
        });
    }
});

// Codex R12 Low: no snapshot polling behind "Project not found".
test('project page: no scan polling behind "Project not found" (Codex R12)', async ({ page }) => {
    const missing = '00000000-0000-0000-0000-00000000beef';
    await page.clock.install();
    let reads = 0;
    page.on('request', (r) => {
        const path = new URL(r.url()).pathname;
        if (path.startsWith(`/api/v1/projects/${missing}/`)) reads++;
    });
    await page.goto(`/en/projects/${missing}`);
    await expect(page.getByText(en.Common.projectNotFound, { exact: true })).toBeVisible();
    await page.waitForLoadState('networkidle');
    const before = reads;
    await page.clock.fastForward('03:05');
    await page.waitForTimeout(1_500);
    expect(reads).toBe(before);
});

// Codex R13 Low: re-sorting a completed result must not re-announce the
// scan as finished (the live region must not clear and refill).
test('project page: re-sorting a completed result does not re-announce it (Codex R13)', async ({ page, request }) => {
    const p = await createProject(request, uniqueName('Scan Status R13 Announce'));
    try {
        await uploadSbom(request, p.id, cleanSbom);
        await page.goto(`/en/projects/${p.id}`);
        await vulnTab(page).click();
        const announcer = page.getByTestId('scan-finished-announcer');
        await expect(announcer).toHaveText(en.ScanStatus.scanFinishedAnnouncement);
        await page.evaluate(() => {
            const el = document.querySelector('[data-testid="scan-finished-announcer"]')!;
            (window as unknown as { __changes: string[] }).__changes = [];
            new MutationObserver(() =>
                (window as unknown as { __changes: string[] }).__changes.push(el.textContent ?? ''),
            ).observe(el, { childList: true, characterData: true, subtree: true });
        });
        await page.getByRole('button', { name: en.Vulnerabilities.sortByEpss }).click();
        await expect(page.getByRole('button', { name: en.Vulnerabilities.sortByEpss })).toHaveAttribute('aria-pressed', 'true');
        await page.waitForLoadState('networkidle');
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
        const changes = await page.evaluate(() => (window as unknown as { __changes: string[] }).__changes);
        expect(changes).toEqual([]);
    } finally {
        await deleteProject(request, p.id);
    }
});

// Codex R14 Medium: polls skip hidden tabs, so coming back to the tab must
// re-read the snapshot instead of showing the old one for up to a minute.
test('project page: returning to a hidden tab re-reads the scan state (Codex R14)', async ({ page, request }) => {
    const p = await createProject(request, uniqueName('Scan Status R14 Focus'));
    try {
        const first = await uploadSbom(request, p.id, cleanSbom);
        const polled = new Set<string>();
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${p.id}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                polled.add(real.sbom_id);
                await route.fulfill({ response: res, json: { ...real, status: real.sbom_id === first ? 'completed' : 'running' } });
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
        await page.waitForLoadState('networkidle');
        const setVisibility = (state: 'hidden' | 'visible') =>
            page.evaluate((v) => {
                Object.defineProperty(document, 'visibilityState', { value: v, configurable: true });
                Object.defineProperty(document, 'hidden', { value: v === 'hidden', configurable: true });
                document.dispatchEvent(new Event('visibilitychange', { bubbles: true }));
            }, state);
        await setVisibility('hidden');
        const second = await uploadSbom(request, p.id, cleanSbom); // CI, while the tab is hidden
        await setVisibility('visible');
        await expect.poll(() => polled.has(second), { timeout: 10_000 }).toBe(true);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
    } finally {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
        await deleteProject(request, p.id);
    }
});

// Codex R15: returning to the tab must not join a read that started before
// the tab was hidden (react-query's focus refetch does not cancel it).
test('project page: returning to the tab starts a fresh read, not the one from before hiding (Codex R15)', async ({ page, request }) => {
    const p = await createProject(request, uniqueName('Scan Status R15 Focus Join'));
    try {
        const first = await uploadSbom(request, p.id, cleanSbom);
        await page.clock.install();
        const polled = new Set<string>();
        let holdArmed = false;
        let readsSinceArmed = 0;
        let heldSeen = false;
        let release: () => void = () => {};
        const held = new Promise<void>((r) => (release = r));
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${p.id}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                polled.add(real.sbom_id);
                const json = { ...real, status: real.sbom_id === first ? 'completed' : 'running' };
                if (holdArmed && real.sbom_id === first && ++readsSinceArmed === 2) {
                    heldSeen = true; // the poll's final state read, delayed
                    await held;
                    return route.fulfill({ response: res, json }).catch(() => {});
                }
                await route.fulfill({ response: res, json });
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        await vulnTab(page).click();
        await expect(empty(page)).toHaveText(en.ScanStatus.emptyCompleted);
        await page.waitForLoadState('networkidle');
        holdArmed = true;
        await page.clock.fastForward('01:05'); // the minute poll starts and stalls on its last read
        await expect.poll(() => heldSeen, { timeout: 15_000 }).toBe(true);
        const setVisibility = (state: 'hidden' | 'visible') =>
            page.evaluate((v) => {
                Object.defineProperty(document, 'visibilityState', { value: v, configurable: true });
                Object.defineProperty(document, 'hidden', { value: v === 'hidden', configurable: true });
                document.dispatchEvent(new Event('visibilitychange', { bubbles: true }));
            }, state);
        await setVisibility('hidden');
        const second = await uploadSbom(request, p.id, cleanSbom); // CI, while hidden
        await setVisibility('visible');
        await expect.poll(() => polled.has(second), { timeout: 10_000 }).toBe(true);
        release(); // the stale read's answer (the first SBOM, completed) arrives last
        await page.waitForTimeout(1_500);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
        await expect(vulnTab(page)).not.toHaveText(tabText(0, null));
    } finally {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
        await deleteProject(request, p.id);
    }
});

// Codex R16: a tab return while the project itself is still loading is not lost.
test('project page: returning to the tab while the project is still loading still re-reads (Codex R16)', async ({ page, request }) => {
    const p = await createProject(request, uniqueName('Scan Status R16 Focus Pending'));
    try {
        const first = await uploadSbom(request, p.id, cleanSbom);
        const polled = new Set<string>();
        let snapshotDone = false;
        let release: () => void = () => {};
        const held = new Promise<void>((r) => (release = r));
        await page.route(
            (url) => url.pathname === `/api/v1/projects/${p.id}`,
            async (route) => {
                if (route.request().method() !== 'GET') return route.fallback();
                await held; // the project itself is slow
                return route.fallback().catch(() => {});
            },
        );
        await page.route(
            (url) => url.pathname.startsWith(`/api/v1/projects/${p.id}/sboms/`) && url.pathname.endsWith('/scan-status'),
            async (route) => {
                const res = await route.fetch();
                const real = await res.json();
                polled.add(real.sbom_id);
                if (real.sbom_id === first) snapshotDone = true;
                await route.fulfill({ response: res, json: { ...real, status: real.sbom_id === first ? 'completed' : 'running' } });
            },
        );
        await page.goto(`/en/projects/${p.id}`);
        await expect.poll(() => snapshotDone, { timeout: 15_000 }).toBe(true);
        await page.waitForTimeout(1_000);
        const setVisibility = (state: 'hidden' | 'visible') =>
            page.evaluate((v) => {
                Object.defineProperty(document, 'visibilityState', { value: v, configurable: true });
                Object.defineProperty(document, 'hidden', { value: v === 'hidden', configurable: true });
                document.dispatchEvent(new Event('visibilitychange', { bubbles: true }));
            }, state);
        await setVisibility('hidden');
        const second = await uploadSbom(request, p.id, cleanSbom);
        await setVisibility('visible');
        release();
        await expect.poll(() => polled.has(second), { timeout: 10_000 }).toBe(true);
        await expect(notice(page)).toHaveAttribute('data-scan-state', 'running');
    } finally {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
        await deleteProject(request, p.id);
    }
});

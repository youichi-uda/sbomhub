import { test, expect, type Page } from '@playwright/test';

// M29-B (F398 / issue #137) — transitive dependency path-to-root web view.
//
// Fully mock-intercepted (page.route) so the render contract for the new
// DependencyPathPanel is exercised deterministically with no backend seed:
//   - list chain renders root → … → target with the target/direct emphasis
//   - is_direct branch (direct vs transitive guidance line)
//   - degraded (SPDX / no edges) informational empty state
//   - truncated notice (cap reached, reported honestly — never silent)
//   - graph secondary toggle mounts the @xyflow canvas
//
// The real traversal semantics (cycle guard, ownership 404, root
// detection, version granularity) live in the Wave A / F397 backend unit
// tests; this pins only the web layer's rendering of the pinned contract.

const PROJECT_ID = '99999999-9999-4999-8999-999999999999';
const COMPONENT_ID = '88888888-8888-4888-8888-888888888888';

const ROOT = { id: 'pkg:npm/my-app', name: 'my-app', version: '1.0.0', type: 'application' };
const EXPRESS = { id: 'pkg:npm/express', name: 'express', version: '4.18.0', type: 'library' };
const BODY_PARSER = { id: 'pkg:npm/body-parser', name: 'body-parser', version: '1.20.0', type: 'library' };
const KOA = { id: 'pkg:npm/koa', name: 'koa', version: '2.14.0', type: 'library' };
const QS = { id: 'pkg:npm/qs', name: 'qs', version: '6.2.0', type: 'library' };

// Register the minimal project shell the detail page needs to render the
// components tab: the project GET (else the page shows "project not
// found") and a single-component list (so the row + trigger button
// exist). Every other loader on the page hits its own endpoint; those
// are left un-intercepted and fail fast (network refused) — each is
// wrapped in a try/catch on the page and is non-fatal to this flow.
async function mockProjectShell(page: Page) {
  await page.route(`**/api/v1/projects/${PROJECT_ID}`, (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        id: PROJECT_ID,
        name: 'Mock Project',
        description: 'M29-B path view',
        created_at: '2026-07-01T00:00:00Z',
        updated_at: '2026-07-01T00:00:00Z',
      }),
    }),
  );
  await page.route(`**/api/v1/projects/${PROJECT_ID}/components`, (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([
        {
          id: COMPONENT_ID,
          sbom_id: '77777777-7777-4777-8777-777777777777',
          name: 'qs',
          version: '6.2.0',
          type: 'library',
          purl: 'pkg:npm/qs@6.2.0',
          license: 'BSD-3-Clause',
          created_at: '2026-07-01T00:00:00Z',
        },
      ]),
    }),
  );
}

async function openComponentsTabAndTriggerPath(page: Page) {
  await page.goto(`/en/projects/${PROJECT_ID}`);
  await page.waitForLoadState('networkidle');

  // Switch to the Components tab (default landing tab is Upload).
  await page.getByRole('button', { name: /^Components \(/ }).click();

  const trigger = page.getByTestId('dependency-path-trigger');
  await expect(trigger).toBeVisible({ timeout: 10000 });
  await trigger.click();

  await expect(page.getByTestId('dependency-path-panel')).toBeVisible({
    timeout: 10000,
  });
}

test.describe('Dependency path-to-root (M29-B)', () => {
  test('renders transitive path chains + graph toggle', async ({ page }) => {
    await page.route(
      `**/api/v1/projects/${PROJECT_ID}/components/*/paths`,
      (route) =>
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            component_id: COMPONENT_ID,
            component: { name: 'qs', version: '6.2.0', purl: 'pkg:npm/qs' },
            sbom_id: '77777777-7777-4777-8777-777777777777',
            format: 'cyclonedx',
            degraded: false,
            is_direct: false,
            paths: [
              [ROOT, EXPRESS, BODY_PARSER, QS],
              [ROOT, KOA, QS],
            ],
            path_count: 2,
            truncated: false,
          }),
        }),
    );
    await mockProjectShell(page);
    await openComponentsTabAndTriggerPath(page);

    // Transitive branch: the "what do I upgrade" guidance line.
    const guidance = page.getByTestId('dependency-path-guidance');
    await expect(guidance).toBeVisible();
    await expect(guidance).toContainText(/transitive dependency/i);

    // Path count (2 paths) is surfaced honestly.
    await expect(page.getByTestId('dependency-path-count')).toContainText('2');

    // The list chain renders every node across both paths.
    const list = page.getByTestId('dependency-path-list');
    await expect(list).toBeVisible();
    const chains = page.getByTestId('dependency-path-chain');
    await expect(chains).toHaveCount(2);
    await expect(list).toContainText('express');
    await expect(list).toContainText('body-parser');
    await expect(list).toContainText('koa');
    await expect(list).toContainText('qs');
    // The target node carries the target role emphasis.
    await expect(list.locator('[data-role="target"]').first()).toBeVisible();

    // Secondary graph view mounts the @xyflow canvas on toggle.
    await page.getByRole('button', { name: /^Graph$/ }).click();
    await expect(page.getByTestId('dependency-path-graph')).toBeVisible({
      timeout: 10000,
    });
  });

  test('reports direct dependency + truncation honestly', async ({ page }) => {
    await page.route(
      `**/api/v1/projects/${PROJECT_ID}/components/*/paths`,
      (route) =>
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            component_id: COMPONENT_ID,
            component: { name: 'qs', version: '6.2.0', purl: 'pkg:npm/qs' },
            sbom_id: '77777777-7777-4777-8777-777777777777',
            format: 'cyclonedx',
            degraded: false,
            is_direct: true,
            paths: [[ROOT, QS]],
            path_count: 1,
            truncated: true,
          }),
        }),
    );
    await mockProjectShell(page);
    await openComponentsTabAndTriggerPath(page);

    // Direct-dependency branch guidance.
    await expect(page.getByTestId('dependency-path-guidance')).toContainText(
      /direct dependency/i,
    );

    // Truncation is shown, not silently dropped.
    await expect(page.getByTestId('dependency-path-truncated')).toContainText(
      /Showing the first 1 paths/i,
    );
  });

  test('truncated with zero paths shows a distinct message, not "not found" (F400)', async ({
    page,
  }) => {
    // Backend hit its enumeration budget before completing any path. The
    // component IS reachable, so the panel must render the honest
    // "too complex to enumerate" message and NOT the contradictory
    // "not found in graph" empty state nor "showing the first 0 paths".
    await page.route(
      `**/api/v1/projects/${PROJECT_ID}/components/*/paths`,
      (route) =>
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            component_id: COMPONENT_ID,
            component: { name: 'qs', version: '6.2.0', purl: 'pkg:npm/qs' },
            sbom_id: '77777777-7777-4777-8777-777777777777',
            format: 'cyclonedx',
            degraded: false,
            is_direct: false,
            paths: [],
            path_count: 0,
            truncated: true,
          }),
        }),
    );
    await mockProjectShell(page);
    await openComponentsTabAndTriggerPath(page);

    // The distinct honest message renders.
    const distinct = page.getByTestId('dependency-path-truncated-empty');
    await expect(distinct).toBeVisible();
    await expect(distinct).toContainText(/computation budget/i);

    // The contradictory states are NOT rendered.
    await expect(page.getByTestId('dependency-path-empty')).toHaveCount(0);
    await expect(page.getByTestId('dependency-path-truncated')).toHaveCount(0);
  });

  test('shows informational empty state for degraded (SPDX) SBOMs', async ({
    page,
  }) => {
    await page.route(
      `**/api/v1/projects/${PROJECT_ID}/components/*/paths`,
      (route) =>
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            component_id: COMPONENT_ID,
            component: { name: 'qs', version: '6.2.0', purl: 'pkg:npm/qs' },
            sbom_id: '77777777-7777-4777-8777-777777777777',
            format: 'spdx',
            degraded: true,
            is_direct: false,
            paths: [],
            path_count: 0,
            truncated: false,
          }),
        }),
    );
    await mockProjectShell(page);
    await openComponentsTabAndTriggerPath(page);

    // Degraded is informational (not an error) and no chain renders.
    await expect(page.getByTestId('dependency-path-degraded')).toBeVisible();
    await expect(page.getByTestId('dependency-path-degraded')).toContainText(
      /SPDX/i,
    );
    await expect(page.getByTestId('dependency-path-list')).toHaveCount(0);
  });
});

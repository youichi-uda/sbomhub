import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import ja from '../messages/ja.json';
import {
  FIXTURE_PURLS,
  createProject,
  deleteProject,
  listVulns,
  uniqueName,
  uploadSbom,
} from './fixtures/vuln-project';

// M60 NVD / JVN match labels on the vulnerability list (docs/UPGRADE.md
// §13.2): every non-distro finding shows how it was matched and with what
// confidence, and everything but a verified CPE match is marked for review.
//
// docker/seed/web-e2e.sql §8 links the synthetic component
// `vuln-fixture-nvd` to the four seeded CVEs with one label per confidence
// tier — standing in for the scanners' write, which needs NVD / JVN. From
// the API's list projection (bestMatchMethodJoin + model.MatchMethod.
// Confidence) to the rendered badge, everything is the real code. A
// missing seed FAILS the setup; nothing here skips.

const NVD = {
  high: 'CVE-2021-44228', // nvd_cpe
  medium: 'CVE-2021-45046', // nvd_cpe_distro
  low: 'CVE-2021-23337', // jvn_keyword
  unknown: 'CVE-2020-8203', // NULL: a link made before migration 067
} as const;

function sbom(...components: { name: string; purl: string }[]) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    version: 1,
    components: components.map((c) => ({
      type: 'library',
      name: c.name,
      version: '1.0.0',
      purl: c.purl,
      licenses: [{ license: { id: 'MIT' } }],
    })),
  };
}

const nvdComponent = { name: 'vuln-fixture-nvd', purl: FIXTURE_PURLS.nvd };
const keywordComponent = { name: 'vuln-fixture-critical', purl: FIXTURE_PURLS.critical };

let projectId: string | undefined;
let mixedProjectId: string | undefined;

async function openVulnerabilities(page: Page, locale: 'en' | 'ja', id: string, count: number): Promise<void> {
  const msgs = locale === 'en' ? en : ja;
  await page.goto(`/${locale}/projects/${id}`);
  await page
    .getByRole('button', { name: new RegExp(`^${msgs.Vulnerabilities.title} \\(${count}\\)$`) })
    .click();
  await expect(page.getByTestId('vuln-entry')).toHaveCount(count, { timeout: 15000 });
}

function badgeText(m: typeof en.MatchMethod, method: string, confidence: string, review: boolean): string {
  return (review ? m.findingBadgeReview : m.findingBadge)
    .replace('{method}', method)
    .replace('{confidence}', confidence);
}

function withNote(m: typeof en.MatchMethod, hint: string): string {
  return m.findingHintWithNote.replace('{hint}', hint).replace('{note}', m.findingReviewNote);
}

test.describe('M60 NVD / JVN confidence labels', () => {
  test.beforeAll(async ({ request }) => {
    const project = await createProject(request, uniqueName('Finding Match Project'));
    projectId = project.id;
    await uploadSbom(request, project.id, sbom(nvdComponent));
    const mixed = await createProject(request, uniqueName('Finding Match Mixed Project'));
    mixedProjectId = mixed.id;
    await uploadSbom(request, mixed.id, sbom(nvdComponent, keywordComponent));
    await expect
      .poll(
        async () =>
          (await listVulns(request, project.id))
            .map((v) => `${v.cve_id}=${String(v.match_method ?? '')}/${String(v.match_confidence)}`)
            .sort(),
        {
          message: 'NVD fixture links never appeared — is docker/seed/web-e2e.sql §8 (vuln-fixture-nvd) loaded?',
          timeout: 15_000,
        },
      )
      .toEqual(
        [
          `${NVD.high}=nvd_cpe/high`,
          `${NVD.medium}=nvd_cpe_distro/medium`,
          `${NVD.low}=jvn_keyword/low`,
          // pre-M60: no match_method field at all, confidence "unknown"
          `${NVD.unknown}=/unknown`,
        ].sort(),
      );
    await expect
      .poll(async () => (await listVulns(request, mixed.id)).length, { timeout: 15_000 })
      .toBe(4);
  });

  test.afterAll(async ({ request }) => {
    await deleteProject(request, projectId);
    await deleteProject(request, mixedProjectId);
  });

  test('API sends match_method / match_confidence and no distro evidence', async ({ request }) => {
    const vulns = await listVulns(request, projectId!);
    const unknown = vulns.find((v) => v.cve_id === NVD.unknown)!;
    expect(unknown).not.toHaveProperty('match_method');
    for (const v of vulns) expect(v).not.toHaveProperty('match_evidence');
  });

  for (const locale of ['en', 'ja'] as const) {
    const m = (locale === 'en' ? en : ja).MatchMethod;

    test(`every tier is labelled, low / unknown marked for review, nothing hidden (${locale})`, async ({ page }) => {
      await openVulnerabilities(page, locale, projectId!, 4);
      const badge = (cve: string) =>
        page.locator(`[data-vuln-cve-id="${cve}"]`).getByTestId('finding-match-badge');

      await expect(badge(NVD.high)).toHaveText(badgeText(m, m.methodNvdCpe, m.confidenceHigh, false));
      await expect(badge(NVD.high)).toHaveAttribute('data-needs-review', 'false');
      await expect(badge(NVD.high)).toHaveAttribute('data-match-confidence', 'high');

      await expect(badge(NVD.medium)).toHaveText(badgeText(m, m.methodNvdCpeDistro, m.confidenceMedium, true));
      await expect(badge(NVD.medium)).toHaveAttribute('data-needs-review', 'true');

      await expect(badge(NVD.low)).toHaveText(badgeText(m, m.methodJvnKeyword, m.confidenceLow, true));
      await expect(badge(NVD.low)).toHaveAttribute('data-match-method', 'jvn_keyword');
      await expect(badge(NVD.low)).toHaveAttribute('data-needs-review', 'true');

      await expect(badge(NVD.unknown)).toHaveText(badgeText(m, m.methodNotRecorded, m.confidenceUnknown, true));
      await expect(badge(NVD.unknown)).toHaveAttribute('data-match-confidence', 'unknown');

      // No distro badge on NVD / JVN labels, and every finding is listed.
      await expect(page.getByTestId('distro-match-badge')).toHaveCount(0);
      for (const cve of Object.values(NVD)) {
        await expect(page.locator(`[data-vuln-cve-id="${cve}"]`).getByTestId('vuln-cve-id')).toBeVisible();
      }
      await page.screenshot({ path: test.info().outputPath(`finding-badges-${locale}.png`), fullPage: true });
    });

    test(`explanation is reachable by keyboard, touch and screen readers (${locale})`, async ({ browser, baseURL }) => {
      const context = await browser.newContext({ baseURL, hasTouch: true });
      const page = await context.newPage();
      try {
        await openVulnerabilities(page, locale, projectId!, 4);
        const entry = page.locator(`[data-vuln-cve-id="${NVD.low}"]`);
        const badge = entry.getByTestId('finding-match-badge');
        const hint = entry.getByTestId('finding-match-hint');
        const lowHint = withNote(m, m.hintJvnKeyword);

        // The description is there before anything is opened.
        await expect(badge).toHaveAccessibleDescription(lowHint);
        await expect(badge).not.toHaveAttribute('title');
        await expect(hint).toBeHidden();

        // Keyboard: focus shows it, Escape hides it.
        await badge.focus();
        await expect(hint).toBeVisible();
        await expect(hint).toHaveText(lowHint);
        await expect(hint).toHaveAttribute('role', 'tooltip');
        const bg = await hint.locator('span').first().evaluate((el) => getComputedStyle(el).backgroundColor);
        expect(bg, 'the explanation bubble must have an opaque background').not.toBe('rgba(0, 0, 0, 0)');
        await page.keyboard.press('Escape');
        await expect(hint).toBeHidden();

        // Touch: a tap opens it, a tap elsewhere closes it.
        await badge.tap();
        await expect(hint).toBeVisible();
        await page.locator('h1').first().tap();
        await expect(hint).toBeHidden();

        // A verified CPE match explains itself without a review note.
        const high = page.locator(`[data-vuln-cve-id="${NVD.high}"]`).getByTestId('finding-match-badge');
        await expect(high).toHaveAccessibleDescription(m.hintNvdCpe);
        const unknown = page.locator(`[data-vuln-cve-id="${NVD.unknown}"]`).getByTestId('finding-match-badge');
        await expect(unknown).toHaveAccessibleDescription(withNote(m, m.hintNotRecorded));
      } finally {
        await context.close();
      }
    });
  }

  test('the strongest link of the SBOM decides the label, one entry per CVE', async ({ page, request }) => {
    // vuln-fixture-critical links CVE-2021-44228 / -45046 by nvd_keyword;
    // vuln-fixture-nvd links them by nvd_cpe / nvd_cpe_distro. The list
    // shows each CVE once, with the stronger label (bestMatchMethodJoin).
    const vulns = await listVulns(request, mixedProjectId!);
    const byCve = Object.fromEntries(vulns.map((v) => [v.cve_id, v.match_method]));
    expect(byCve[NVD.high]).toBe('nvd_cpe');
    expect(byCve[NVD.medium]).toBe('nvd_cpe_distro');

    await openVulnerabilities(page, 'en', mixedProjectId!, 4);
    const m = en.MatchMethod;
    await expect(
      page.locator(`[data-vuln-cve-id="${NVD.high}"]`).getByTestId('finding-match-badge'),
    ).toHaveText(badgeText(m, m.methodNvdCpe, m.confidenceHigh, false));
    await expect(
      page.locator(`[data-vuln-cve-id="${NVD.medium}"]`).getByTestId('finding-match-badge'),
    ).toHaveText(badgeText(m, m.methodNvdCpeDistro, m.confidenceMedium, true));
  });

  test('the KEV tooltip renders on an opaque popover background', async ({ page }) => {
    // Regression for the undefined bg-popover token (theme-tokens.test.mjs
    // pins the CSS; this pins what the browser actually paints).
    await openVulnerabilities(page, 'en', projectId!, 4);
    const kev = page.locator(`[data-vuln-cve-id="${NVD.high}"] span.bg-red-600[aria-describedby]`);
    await kev.hover();
    const tip = page.locator(`[data-vuln-cve-id="${NVD.high}"]`).getByRole('tooltip');
    await expect(tip).toBeVisible();
    await expect(tip).toContainText(en.KEV.title);
    const bg = await tip.evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(bg).toBe('rgb(255, 255, 255)');
    await tip.screenshot({ path: test.info().outputPath('kev-tooltip.png') });
  });
});

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

// M70 distro labels on the vulnerability list (docs/UPGRADE.md §21).
//
// docker/seed/web-e2e.sql §8 links the synthetic component
// `vuln-fixture-distro` to three seeded CVEs with the three distro labels and
// their evidence — standing in for the scan's distro step, which needs OSV
// and a real deb / rpm package. Everything from the API's list projection to
// the rendered badge and evidence panel is the real code. A missing seed
// FAILS the setup; nothing here skips.

const DISTRO = {
  affected: 'CVE-2021-23337',
  unfixed: 'CVE-2021-45046',
  fixed: 'CVE-2020-8203',
} as const;

const distroSbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.4',
  version: 1,
  components: [
    {
      type: 'library',
      name: 'vuln-fixture-distro',
      version: '1.0.0',
      purl: FIXTURE_PURLS.distro,
      licenses: [{ license: { id: 'MIT' } }],
    },
  ],
};

let projectId: string | undefined;

async function openVulnerabilities(page: Page, locale: 'en' | 'ja'): Promise<void> {
  const msgs = locale === 'en' ? en : ja;
  await page.goto(`/${locale}/projects/${projectId}`);
  await page.getByRole('button', { name: new RegExp(`^${msgs.Vulnerabilities.title} \\(\\d+\\)$`) }).click();
  await expect(page.getByTestId('vuln-entry')).toHaveCount(3, { timeout: 15000 });
}

test.describe('M70 distro labels', () => {
  // Fixed zone so the localized evidence timestamps are exact (M71).
  test.use({ timezoneId: 'Asia/Tokyo' });

  test.beforeAll(async ({ request }) => {
    const project = await createProject(request, uniqueName('Distro Match Project'));
    projectId = project.id;
    await uploadSbom(request, project.id, distroSbom);
    // The API must project the labels and the public evidence.
    await expect
      .poll(
        async () =>
          (await listVulns(request, project.id))
            .map((v) => `${v.cve_id}=${String(v.match_method)}`)
            .sort(),
        {
          message: 'distro fixture links never appeared — is docker/seed/web-e2e.sql §8 (vuln-fixture-distro) loaded?',
          timeout: 15_000,
        },
      )
      .toEqual(
        [
          `${DISTRO.affected}=distro_affected`,
          `${DISTRO.unfixed}=distro_unfixed`,
          `${DISTRO.fixed}=distro_fixed`,
        ].sort(),
      );
  });

  test.afterAll(async ({ request }) => {
    await deleteProject(request, projectId);
  });

  test('API projects evidence without internal fields', async ({ request }) => {
    const vulns = await listVulns(request, projectId!);
    const fixed = vulns.find((v) => v.cve_id === DISTRO.fixed)!;
    expect(fixed.match_confidence).toBe('distro_fixed');
    const ev = fixed.match_evidence as Record<string, unknown>;
    expect(ev.basis).toBe('later_releases');
    expect(ev.records).toEqual(['DEBIAN-CVE-2020-8203', 'DLA-0000-1']);
    expect(ev.source_url).toBe('https://api.osv.dev');
    expect(ev.data_modified).toBe('2026-11-09T00:00:00Z');
    // The seed stores these internal fields with the link; the list must
    // project the public DistroEvidence fields only.
    for (const internal of ['source_id', 'prior_method', 'wm_source', 'wm_rev', 'wm_by_source']) {
      expect(ev).not.toHaveProperty(internal);
    }
    expect(JSON.stringify(vulns)).not.toContain('e2e-internal-source-hash');
  });

  for (const locale of ['en', 'ja'] as const) {
    const m = (locale === 'en' ? en : ja).MatchMethod;

    test(`badges distinguish affected, unfixed and fixed-for-review (${locale})`, async ({ page }) => {
      await openVulnerabilities(page, locale);

      const badge = (cve: string) =>
        page.locator(`[data-vuln-cve-id="${cve}"]`).getByTestId('distro-match-badge');
      await expect(badge(DISTRO.affected)).toHaveText(m.distroAffectedUpgrade.replace('{fixed}', '4.17.21+dfsg-2'));
      await expect(badge(DISTRO.affected)).toHaveAttribute('data-match-method', 'distro_affected');
      await expect(badge(DISTRO.unfixed)).toHaveText(m.distroUnfixed);
      await expect(badge(DISTRO.fixed)).toHaveText(m.distroFixed);
      await expect(badge(DISTRO.fixed)).toHaveAttribute('data-match-method', 'distro_fixed');
      await page.screenshot({ path: test.info().outputPath(`distro-badges-${locale}.png`), fullPage: true });
    });

    // M71: the explanation was only a `title` on a non-focusable span.
    test(`badge explanation is reachable by keyboard, touch and screen readers (${locale})`, async ({ page }) => {
      await openVulnerabilities(page, locale);
      const entry = page.locator(`[data-vuln-cve-id="${DISTRO.fixed}"]`);
      const badge = entry.getByTestId('distro-match-badge');
      const hint = entry.getByTestId('distro-match-hint');

      // The accessible description is there before anything is opened.
      await expect(badge).toHaveAccessibleDescription(m.distroFixedHint);
      await expect(badge).not.toHaveAttribute('title');
      await expect(hint).toBeHidden();

      // Keyboard: focus shows it, Escape hides it.
      await badge.focus();
      await expect(badge).toBeFocused();
      await expect(hint).toBeVisible();
      await expect(hint).toHaveText(m.distroFixedHint);
      await expect(hint).toHaveAttribute('role', 'tooltip');
      await page.keyboard.press('Escape');
      await expect(hint).toBeHidden();
      // Tab moves focus on to the next control.
      await badge.focus();
      await page.keyboard.press('Tab');
      await expect(badge).not.toBeFocused();
      await expect(hint).toBeHidden();

      // A mouse click shows it too (and keeps it while hovered).
      await page.locator('h1').first().click();
      await expect(hint).toBeHidden();
      await badge.click();
      await expect(hint).toBeVisible();

      // The high-confidence badge carries its own explanation.
      const affected = page.locator(`[data-vuln-cve-id="${DISTRO.affected}"]`).getByTestId('distro-match-badge');
      await expect(affected).toHaveAccessibleDescription(m.highConfidenceHint);
    });

    test(`badge explanation opens on tap and closes on a tap elsewhere (${locale})`, async ({ browser, baseURL }) => {
      const context = await browser.newContext({ baseURL, hasTouch: true, timezoneId: 'Asia/Tokyo' });
      const page = await context.newPage();
      try {
        await openVulnerabilities(page, locale);
        const entry = page.locator(`[data-vuln-cve-id="${DISTRO.fixed}"]`);
        const hint = entry.getByTestId('distro-match-hint');
        await expect(hint).toBeHidden();
        await entry.getByTestId('distro-match-badge').tap();
        await expect(hint).toBeVisible();
        await expect(hint).toHaveText(m.distroFixedHint);
        await page.locator('h1').first().tap();
        await expect(hint).toBeHidden();
      } finally {
        await context.close();
      }
    });

    test(`evidence view shows OSV records, release, basis and the end-of-life caveat (${locale})`, async ({ page }) => {
      await openVulnerabilities(page, locale);

      // distro_fixed with basis = later_releases
      const fixedEntry = page.locator(`[data-vuln-cve-id="${DISTRO.fixed}"]`);
      await expect(fixedEntry.getByTestId('distro-evidence-panel')).toHaveCount(0);
      const toggle = fixedEntry.getByRole('button', { name: m.showEvidenceFor.replace('{cve}', DISTRO.fixed) });
      await expect(toggle).toHaveAttribute('aria-expanded', 'false');
      await toggle.click();
      const panel = fixedEntry.getByTestId('distro-evidence-panel');
      await expect(panel).toBeVisible();
      await expect(
        fixedEntry.getByRole('button', { name: m.hideEvidenceFor.replace('{cve}', DISTRO.fixed) }),
      ).toHaveAttribute('aria-expanded', 'true');
      await expect(panel.getByText(m.distroFixedReview)).toBeVisible();
      await expect(panel.getByTestId('distro-evidence-release')).toHaveText('Debian:10');
      await expect(panel.getByTestId('distro-evidence-basis')).toHaveText(m.basisLaterReleases);
      await expect(panel.getByTestId('distro-evidence-source-url')).toHaveText('https://api.osv.dev');
      await expect(panel.getByTestId('distro-evidence-mirror-note')).toHaveCount(0);
      // M71: shown in the viewer's locale and zone, not as the raw ISO string
      // (the browser runs in Asia/Tokyo, see test.use above).
      const modified = panel.getByTestId('distro-evidence-data-modified');
      await expect(modified.locator('time')).toHaveAttribute('datetime', '2026-11-09T00:00:00Z');
      await expect(modified).toHaveText(
        locale === 'en' ? /^Nov 9, 2026, 9:00:00\sAM GMT\+9$/ : /^2026\/11\/09 9:00:00 JST$/,
      );
      const fetched = panel.getByTestId('distro-evidence-fetched-at');
      await expect(fetched.locator('time')).toHaveAttribute('datetime', '2026-11-10T00:00:00Z');
      await expect(fetched).toHaveText(
        locale === 'en' ? /^Nov 10, 2026, 9:00:00\sAM GMT\+9$/ : /^2026\/11\/10 9:00:00 JST$/,
      );
      await expect(panel.getByRole('link', { name: 'DEBIAN-CVE-2020-8203' })).toHaveAttribute(
        'href',
        'https://osv.dev/vulnerability/DEBIAN-CVE-2020-8203',
      );
      await expect(panel.getByRole('link', { name: 'DLA-0000-1' })).toHaveAttribute(
        'href',
        'https://osv.dev/vulnerability/DLA-0000-1',
      );
      await expect(panel.getByTestId('distro-evidence-later-releases')).toHaveText(
        m.laterReleasesCaveat.replace('{release}', 'Debian:10').replace('{releases}', 'Debian:11, Debian:12'),
      );
      await panel.screenshot({ path: test.info().outputPath(`distro-evidence-${locale}.png`) });

      // Hide closes it again (Codex M71 R1 Medium: it used to stay open).
      await fixedEntry.getByRole('button', { name: m.hideEvidenceFor.replace('{cve}', DISTRO.fixed) }).click();
      await expect(panel).toHaveCount(0);
      await expect(toggle).toHaveAttribute('aria-expanded', 'false');
      await toggle.click();
      await expect(panel).toBeVisible();

      // distro_affected with basis = release: no caveat, no review note
      const affectedEntry = page.locator(`[data-vuln-cve-id="${DISTRO.affected}"]`);
      await affectedEntry.getByRole('button', { name: m.showEvidenceFor.replace('{cve}', DISTRO.affected) }).click();
      const affectedPanel = affectedEntry.getByTestId('distro-evidence-panel');
      await expect(affectedPanel.getByTestId('distro-evidence-basis')).toHaveText(m.basisRelease);
      await expect(affectedPanel.getByTestId('distro-evidence-later-releases')).toHaveCount(0);
      await expect(affectedPanel.getByText(m.distroFixedReview)).toHaveCount(0);
      // no source_url in this evidence: the endpoint is unknown, not public
      await expect(affectedPanel.getByTestId('distro-evidence-mirror-note')).toHaveText(
        m.mirrorRecordsNote.replace('{source}', m.sourceUnknown),
      );

      // distro_unfixed from a mirror endpoint: the osv.dev links are flagged
      const unfixedEntry = page.locator(`[data-vuln-cve-id="${DISTRO.unfixed}"]`);
      await unfixedEntry.getByRole('button', { name: m.showEvidenceFor.replace('{cve}', DISTRO.unfixed) }).click();
      await expect(unfixedEntry.getByTestId('distro-evidence-mirror-note')).toHaveText(
        m.mirrorRecordsNote.replace('{source}', 'https://osv.mirror.example'),
      );
    });
  }
});

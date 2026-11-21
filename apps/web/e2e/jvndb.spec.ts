import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import ja from '../messages/ja.json';
import { createVulnerableProject, deleteProject, reportFullScanCoverage } from './fixtures/vuln-project';

// Migration 072: JVN iPedia advisories from the JVNDB RSS feed are shown on
// the vulnerability list as Japanese reference information, attached to a CVE
// NVD already supplied.
//
// The hermetic stack runs SBOMHUB_OFFLINE=true, so the RSS sync makes no
// request and the jvndb tables stay empty. This spec therefore adds a
// `jvndb` entry (taken from the real feed, 2026-11-21) to the API's real list
// answer for one fixture CVE; everything from the list response to the
// rendered link is the real code. The API side (storage, the list
// projection) is covered by the Go integration tests.

const CVE = 'CVE-2021-44228';
const ADVISORY = {
  id: 'JVNDB-2026-044393',
  title: 'OpenJDKにおけるヒープベースのバッファオーバーフローの脆弱性',
  // A hostile url must never become the href: the page rebuilds it from the id.
  url: 'javascript:alert(1)',
  published: '2026-11-19T07:12:00Z',
  modified: '2026-11-19T07:12:00Z',
};
const CANONICAL = 'https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-044393.html';

let projectId: string | undefined;

async function injectAdvisory(page: Page): Promise<void> {
  await page.route(
    (url) => /^\/api\/v1\/projects\/[^/]+\/vulnerabilities$/.test(url.pathname),
    async (route) => {
      let res;
      try {
        res = await route.fetch();
      } catch {
        return route.abort().catch(() => {});
      }
      const body = await res.json().catch(() => null);
      if (Array.isArray(body)) {
        for (const v of body) {
          if (v.cve_id === CVE) v.jvndb = [ADVISORY];
        }
      }
      await route.fulfill({ response: res, json: body }).catch(() => {});
    },
  );
}

test.describe('JVNDB RSS advisories on the vulnerability list', () => {
  test.beforeAll(async ({ request }) => {
    const p = await createVulnerableProject(request, 'JVNDB Advisory Project');
    projectId = p.projectId;
  });
  test.afterAll(async ({ request }) => {
    await deleteProject(request, projectId);
  });

  for (const locale of ['ja', 'en'] as const) {
    test(`${locale}: shows id, Japanese title and the canonical link on the CVE it references only`, async ({ page }) => {
      const msgs = locale === 'en' ? en : ja;
      await reportFullScanCoverage(page);
      await injectAdvisory(page);
      await page.goto(`/${locale}/projects/${projectId}`);
      await page.getByRole('button', { name: new RegExp(`^${msgs.Vulnerabilities.title} \\(4\\)$`) }).click();
      await expect(page.getByTestId('vuln-entry')).toHaveCount(4, { timeout: 15000 });

      const entry = page.locator(`[data-vuln-cve-id="${CVE}"]`);
      const box = entry.getByTestId('jvndb-advisories');
      await expect(box).toBeVisible();
      await expect(box).toContainText(msgs.JVNDB.heading);
      await expect(box).toContainText(msgs.JVNDB.note);

      const link = box.getByRole('link', { name: new RegExp(ADVISORY.id) });
      await expect(link).toHaveAttribute('href', CANONICAL);
      await expect(link).toHaveAttribute('target', '_blank');
      await expect(link).toHaveAttribute('rel', /noopener/);
      const title = box.getByTestId('jvndb-advisory-title');
      await expect(title).toHaveText(ADVISORY.title);
      await expect(title).toHaveAttribute('lang', 'ja');

      // Reference only: no other entry gains it, and the finding count is unchanged.
      await expect(page.getByTestId('jvndb-advisories')).toHaveCount(1);
    });
  }

  test('en heading says it is a Japanese-language advisory', async () => {
    expect(en.JVNDB.heading).toMatch(/Japanese/);
    expect(en.JVNDB.note).toMatch(/does not count as a JVN check/);
  });
});

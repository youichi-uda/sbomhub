import { test, expect, type Locator, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { createVulnerableProject, deleteProject, type VulnerableProject } from './fixtures/vuln-project';

// The shared Tooltip (KEV / EOL / SSVC / ticket badges) wired onFocus on a
// plain <span> badge with no tabIndex: Tab skipped the badge and the KEV
// explanation was hover-only. Every as-child trigger is now a focus stop
// (role="button" for a generic element) whose panel stays mounted, so its
// explanation is the trigger's accessible description before it is shown —
// the pattern of the distro / match HintBadge.

const KEV_CVE = 'CVE-2021-44228'; // in KEV (FIXTURE_CVES)
const NON_KEV_CVE = 'CVE-2021-23337';

/** The panel the trigger's aria-describedby names (the entry also holds the
 *  match-badge hint, another role="tooltip"). */
async function panelOf(page: Page, trigger: Locator): Promise<Locator> {
  const id = await trigger.getAttribute('aria-describedby');
  expect(id, 'the trigger references its tooltip').toBeTruthy();
  return page.locator(`[id="${id}"]`);
}

async function openVulnerabilities(page: Page, projectId: string): Promise<void> {
  await page.goto(`/en/projects/${projectId}`);
  await page.getByRole('button', { name: new RegExp(`^${en.Vulnerabilities.title} \\(4\\)$`) }).click();
  await expect(page.getByTestId('vuln-entry')).toHaveCount(4, { timeout: 15_000 });
}

test.describe('shared Tooltip from the keyboard', () => {
  let project: VulnerableProject | undefined;
  test.beforeAll(async ({ request }) => {
    project = await createVulnerableProject(request, 'Tooltip Keyboard Project');
  });
  test.afterAll(async ({ request }) => {
    await deleteProject(request, project?.projectId);
  });

  test('the KEV badge is a named focus stop described by its tooltip', async ({ page }) => {
    await openVulnerabilities(page, project!.projectId);
    const entry = page.locator(`[data-vuln-cve-id="${KEV_CVE}"]`);
    const kev = entry.getByRole('button', { name: en.KEV.badge, exact: true });
    await expect(kev).toHaveCount(1);
    await expect(kev).toHaveAttribute('tabindex', '0');
    // Described before it is ever shown (the panel is mounted, hidden).
    const tip = await panelOf(page, kev);
    await expect(tip).toHaveAttribute('role', 'tooltip');
    await expect(tip).toBeHidden();
    await expect(kev).toHaveAccessibleDescription(new RegExp(en.KEV.title));
    // The non-KEV entry has no KEV badge (the locator above is not vacuous).
    await expect(
      page.locator(`[data-vuln-cve-id="${NON_KEV_CVE}"]`).getByRole('button', { name: en.KEV.badge, exact: true }),
    ).toHaveCount(0);
  });

  test('Tab reaches the KEV badge and opens it; Escape closes it; Tab away keeps it closed', async ({ page }) => {
    await openVulnerabilities(page, project!.projectId);
    const entry = page.locator(`[data-vuln-cve-id="${KEV_CVE}"]`);
    const kev = entry.getByRole('button', { name: en.KEV.badge, exact: true });
    const tip = await panelOf(page, kev);

    // Real keyboard navigation: focus the element just before the badge in
    // tab order, then press Tab — no programmatic focus on the badge itself.
    const reached = await kev.evaluate((badge) => {
      const all = Array.from(
        document.querySelectorAll<HTMLElement>('a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])'),
      ).filter((el) => !el.hasAttribute('disabled') && el.offsetParent !== null);
      const i = all.indexOf(badge as HTMLElement);
      if (i <= 0) return false;
      all[i - 1].focus();
      return document.activeElement === all[i - 1];
    });
    expect(reached, 'an element precedes the KEV badge in tab order').toBe(true);
    await page.keyboard.press('Tab');
    await expect(kev).toBeFocused();
    await expect(tip).toBeVisible();
    await expect(tip).toContainText(en.KEV.title);

    await page.keyboard.press('Escape');
    await expect(tip).toBeHidden();
    await expect(kev).toBeFocused();

    // Enter / Space toggle it like a button.
    await page.keyboard.press('Enter');
    await expect(tip).toBeVisible();
    await page.keyboard.press(' ');
    await expect(tip).toBeHidden();
    await page.keyboard.press(' ');
    await expect(tip).toBeVisible();

    await page.keyboard.press('Tab');
    await expect(kev).not.toBeFocused();
    await expect(tip).toBeHidden();
  });

  test('hover still opens it, and leaving with the pointer keeps a focus-opened tooltip', async ({ page }) => {
    await openVulnerabilities(page, project!.projectId);
    const entry = page.locator(`[data-vuln-cve-id="${KEV_CVE}"]`);
    const kev = entry.getByRole('button', { name: en.KEV.badge, exact: true });
    const tip = await panelOf(page, kev);
    await kev.hover();
    await expect(tip).toBeVisible();
    await page.mouse.move(0, 0);
    await expect(tip).toBeHidden();

    await kev.focus();
    await expect(tip).toBeVisible();
    await kev.hover();
    await page.mouse.move(0, 0);
    await expect(tip).toBeVisible();
  });

  test('a tap opens it, a second tap closes it, a tap elsewhere closes it', async ({ browser, baseURL }) => {
    const context = await browser.newContext({ baseURL, hasTouch: true, viewport: { width: 390, height: 800 } });
    const page = await context.newPage();
    try {
      await openVulnerabilities(page, project!.projectId);
      const entry = page.locator(`[data-vuln-cve-id="${KEV_CVE}"]`);
      const kev = entry.getByRole('button', { name: en.KEV.badge, exact: true });
      const tip = await panelOf(page, kev);
      await kev.scrollIntoViewIfNeeded();
      // Trusted taps (Codex R2 Low-2): Chromium's real sequence — pointer,
      // touch, focus and the compatibility mouse events and click — not
      // hand-dispatched events.
      await kev.tap();
      await expect(tip).toBeVisible();
      await kev.tap();
      await expect(tip).toBeHidden();
      await kev.tap();
      await expect(tip).toBeVisible();
      // A tap elsewhere closes it.
      await page.getByRole('heading', { level: 1 }).tap();
      await expect(tip).toBeHidden();

      // The touchend + click pair a browser sends for one tap toggles once.
      await kev.dispatchEvent('touchend');
      await kev.dispatchEvent('click');
      await expect(tip).toBeVisible();
    } finally {
      await context.close();
    }
  });
});

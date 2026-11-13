import { test, expect } from '@playwright/test';

// Headless Chromium hides scrollbars (--hide-scrollbars), so a box that
// scrolls sideways never loses height to a scrollbar in the other specs.
// Windows / Firefox / "always show scrollbars" users get a classic scrollbar
// that takes ~15px from the box. TabsList scrolls sideways on a phone-width
// screen (narrow-viewport.spec.ts); with a fixed h-10 the scrollbar ate into
// the 40px and clipped the tabs vertically, adding a second scrollbar
// (Codex web dark/narrow R3 Low). This file runs with classic scrollbars.
test.use({
  launchOptions: { ignoreDefaultArgs: ['--hide-scrollbars'] },
  viewport: { width: 320, height: 800 },
});

const SEED_PROJECT = '00000000-0000-0000-0000-000000000010';

test('a sideways-scrolling tab list keeps its tabs fully visible with a classic scrollbar', async ({ page }) => {
  await page.goto(`/en/projects/${SEED_PROJECT}/compliance`);
  const list = page.getByRole('tablist').first();
  await expect(list).toBeVisible({ timeout: 15_000 });
  const m = await list.evaluate((el: HTMLElement) => ({
    clientWidth: el.clientWidth,
    scrollWidth: el.scrollWidth,
    clientHeight: el.clientHeight,
    scrollHeight: el.scrollHeight,
    scrollbar: el.offsetHeight - el.clientHeight,
  }));
  // The premise: it does scroll sideways, and a real scrollbar is drawn.
  expect(m.scrollWidth, 'the tab list overflows sideways at 320px').toBeGreaterThan(m.clientWidth);
  expect(m.scrollbar, 'a classic (space-taking) scrollbar is drawn').toBeGreaterThan(0);
  // The tabs are not cut off vertically / no vertical scroll inside it.
  expect(m.scrollHeight, 'tabs clipped vertically by the scrollbar').toBeLessThanOrEqual(m.clientHeight);
});

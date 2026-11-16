import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { createVulnerableProject, deleteProject, type VulnerableProject } from './fixtures/vuln-project';

// WCAG 1.4.3 (contrast, AA): text needs 4.5:1 against its background (3:1
// from 24px, or 18.66px bold). Yellow and green text and badges were well
// below it on white: text-yellow-500 #eab308 is 1.9:1, text-green-500
// #22c55e 2.3:1, text-green-600 3.3:1, and the dashboard / search severity
// badges put white text on bg-yellow-500 (1.9:1) and bg-green-500 (2.3:1).
//
// This measures the rendered page: every visible element with text of its
// own whose colour or background comes from a yellow / green / amber / lime
// / emerald class. The background is the first opaque one up the tree, with
// translucent layers (bg-green-500/10) composited over it.

const SEED_PROJECT = '00000000-0000-0000-0000-000000000010';
const HUES = /(?:^|[\s:])(?:text|bg)-(?:yellow|green|amber|lime|emerald)-\d{2,3}(?:\/\d+)?(?=\s|$)/;

interface Failure {
  text: string;
  ratio: number;
  need: number;
  fg: string;
  bg: string;
  cls: string;
}

async function lowContrast(page: Page): Promise<Failure[]> {
  return page.evaluate((huesSource) => {
    const hues = new RegExp(huesSource);
    const parse = (c: string): [number, number, number, number] => {
      const m = c.match(/rgba?\(([^)]+)\)/);
      if (!m) return [0, 0, 0, 0];
      const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
      return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
    };
    const over = (top: number[], bottom: number[]) => {
      const a = top[3];
      return [0, 1, 2].map((i) => top[i] * a + bottom[i] * (1 - a)).concat(1);
    };
    const lum = (c: number[]) => {
      const [r, g, b] = c.slice(0, 3).map((v) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const background = (el: Element): number[] => {
      const layers: number[][] = [];
      for (let a: Element | null = el; a; a = a.parentElement) {
        const c = parse(getComputedStyle(a).backgroundColor);
        if (c[3] > 0) layers.push(c);
        if (c[3] >= 1) break;
      }
      let bg = [255, 255, 255, 1];
      for (const l of layers.reverse()) bg = over(l, bg);
      return bg;
    };
    const huedClass = (el: Element): string | null => {
      for (let a: Element | null = el; a && a !== document.body; a = a.parentElement) {
        const cls = typeof a.className === 'string' ? a.className : '';
        if (hues.test(cls)) return cls;
        // Only the element itself and the ancestors that paint its background.
        if (parse(getComputedStyle(a).backgroundColor)[3] >= 1) break;
      }
      return null;
    };
    const out: Failure[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height || el.closest('[hidden], .sr-only')) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === 'hidden' || Number(cs.opacity) === 0) continue;
      const cls = huedClass(el);
      if (!cls) continue;
      const bg = background(el);
      const fg = over(parse(cs.color), bg);
      const [l1, l2] = [lum(fg), lum(bg)].sort((a, b) => b - a);
      const ratio = (l1 + 0.05) / (l2 + 0.05);
      const size = parseFloat(cs.fontSize);
      const bold = Number(cs.fontWeight) >= 700;
      const need = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
      if (ratio < need) {
        out.push({
          text: own.slice(0, 40),
          ratio: Math.round(ratio * 100) / 100,
          need,
          fg: cs.color,
          bg: `rgb(${bg.slice(0, 3).map(Math.round).join(', ')})`,
          cls: cls.slice(0, 80),
        });
      }
    }
    return out;
  }, HUES.source);
}

async function expectReadable(page: Page, what: string) {
  await page.waitForLoadState('networkidle');
  const failures = await lowContrast(page);
  expect(failures, `${what}: yellow / green text below WCAG AA`).toEqual([]);
}

test.describe('yellow / green text meets WCAG AA contrast', () => {
  let project: VulnerableProject | undefined;
  test.beforeAll(async ({ request }) => {
    project = await createVulnerableProject(request, 'Contrast Project');
  });
  test.afterAll(async ({ request }) => {
    await deleteProject(request, project?.projectId);
  });

  for (const path of ['/en/dashboard', '/en/analytics', `/en/projects/${SEED_PROJECT}/compliance`, '/en/settings/scan']) {
    test(path, async ({ page }) => {
      await page.goto(path);
      await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({ timeout: 15_000 });
      await expectReadable(page, path);
    });
  }

  test('compliance: expanded categories and the checklist', async ({ page }) => {
    await page.goto(`/en/projects/${SEED_PROJECT}/compliance`);
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({ timeout: 15_000 });
    for (const name of Object.values(en.Compliance.category)) {
      const trigger = page.locator('button', { hasText: name });
      if ((await trigger.count()) > 0) await trigger.click();
    }
    await expectReadable(page, 'compliance overview, expanded');
    await page.getByRole('tab', { name: en.Compliance.tabChecklist }).click();
    await expectReadable(page, 'compliance checklist');
  });

  test('project page: components (EOL badges) and vulnerabilities', async ({ page }) => {
    await page.goto(`/en/projects/${project!.projectId}`);
    await expect(page.getByRole('heading', { level: 1, name: project!.projectName })).toBeVisible();
    await page.getByRole('button', { name: new RegExp(`^${en.Components.title} \\(`) }).click();
    await expectReadable(page, 'components tab');
    await page.getByRole('button', { name: new RegExp(`^${en.Vulnerabilities.title} \\(`) }).click();
    await expect(page.getByTestId('vuln-entry')).toHaveCount(4, { timeout: 15_000 });
    await expectReadable(page, 'vulnerabilities tab');
  });

  test('CVE search results (severity badges)', async ({ page }) => {
    await page.goto('/en/search');
    await page.getByPlaceholder(en.Search.cvePlaceholder).fill('CVE-2021-23337');
    await page.getByPlaceholder(en.Search.cvePlaceholder).press('Enter');
    await expect(page.getByText(project!.projectName).first()).toBeVisible({ timeout: 15_000 });
    await expectReadable(page, 'CVE search');
  });
});

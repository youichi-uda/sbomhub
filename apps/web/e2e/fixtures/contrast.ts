import type { Page } from '@playwright/test';

// WCAG 1.4.3 (contrast, AA) measured on the rendered page.
//
// Checked: every visible element with text of its own, plus the value (or,
// when empty, the placeholder) of text inputs and textareas and the shown
// option of a native <select>. Its computed colour is composited over its
// background and compared with that background: 4.5:1, or 3:1 from 24px (or
// 18.66px bold). The background is the first opaque one up the tree, with
// translucent layers (bg-red-500/10) composited over it. Group opacity is
// applied as the browser paints it: an element with opacity < 1 fades its
// own background and everything inside it toward whatever is behind it.
//
// Not checked, as WCAG 1.4.3 exempts them or the number would be a guess:
//   - text of a disabled control (`:disabled`, inside a disabled fieldset,
//     aria-disabled="true") — "part of an inactive user interface component";
//   - text over a background image or gradient anywhere in the walk: no single
//     background colour to measure against.

export interface ContrastFailure {
  text: string;
  ratio: number;
  need: number;
  fg: string;
  bg: string;
  cls: string;
}

export async function lowContrast(page: Page): Promise<ContrastFailure[]> {
  // A colour transition in flight (a tab button turning from filled to
  // outline after the click) would be measured half-way. Wait for every
  // finite animation / transition; spinners (infinite) are left running.
  await page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter((a) => a.effect?.getComputedTiming().iterations !== Infinity)
        .map((a) => a.finished.catch(() => undefined)),
    ),
  );
  return page.evaluate(() => {
    type RGBA = number[];
    // Computed colours are rgb()/rgba() for the hex palette and hsl() tokens,
    // but an opacity modifier on a colour with alpha (bg-slate-900/80) computes
    // to oklab(). Anything that is not rgb() is converted by painting it on a
    // canvas (sRGB), so no format can silently read as transparent.
    const ctx = document.createElement('canvas').getContext('2d', { willReadFrequently: true })!;
    const parse = (c: string): RGBA => {
      const m = c.match(/^rgba?\(([^)]+)\)$/);
      if (m) {
        const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
        return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
      }
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = c;
      if (ctx.fillStyle === '#000000' && !/^(#000|black|rgba?\(0,\s*0,\s*0)/.test(c)) {
        throw new Error(`contrast: unparsed colour ${c}`);
      }
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return [d[0], d[1], d[2], d[3] / 255];
    };
        const lum = (c: RGBA) => {
      const [r, g, b] = c.slice(0, 3).map((v) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    // Paints one pixel of `el`'s box the way the browser composites it:
    // every ancestor's background colour, each element's opacity as an
    // isolated group (it fades its own background and everything inside it
    // toward what is behind it), and optionally the text colour on top.
    // Premultiplied RGBA throughout. `measurable` is false when a background
    // image shows through anywhere (a gradient has no single colour).
    const chainOf = (el: Element) => {
      const chain: Array<{ el: Element; bg: RGBA; opacity: number; image: boolean }> = [];
      for (let a: Element | null = el; a; a = a.parentElement) {
        const cs = getComputedStyle(a);
        chain.push({
          el: a,
          bg: parse(cs.backgroundColor),
          opacity: Number(cs.opacity),
          image: !!cs.backgroundImage && cs.backgroundImage !== 'none',
        });
      }
      return chain;
    };
    const premul = (c: RGBA): RGBA => [c[0] * c[3], c[1] * c[3], c[2] * c[3], c[3]];
    const overP = (top: RGBA, bottom: RGBA): RGBA => top.map((v, i) => v + bottom[i] * (1 - top[3]));
    const paint = (chain: ReturnType<typeof chainOf>, text: RGBA | null): RGBA => {
      let content: RGBA = [0, 0, 0, 0];
      chain.forEach((layer, k) => {
        content = overP(content, premul(layer.bg));
        if (k === 0 && text) content = overP(premul(text), content);
        content = content.map((v) => v * layer.opacity);
      });
      const out = overP(content, [255, 255, 255, 1]);
      return [out[0], out[1], out[2], 1];
    };
    // A background image at `k` is visible unless an opaque background below
    // it covers it with no opacity < 1 in between.
    const imageShows = (chain: ReturnType<typeof chainOf>) =>
      chain.some((layer, k) => {
        if (!layer.image) return false;
        for (let j = k - 1; j >= 0; j--) {
          if (chain[j].opacity < 1) return true;
          if (chain[j].bg[3] >= 1) return false;
        }
        return true;
      });
    // Text colour `color` of `el`, as painted, and the background it is read on.
    const resolve = (el: Element, color: string) => {
      const chain = chainOf(el);
      const painter = chain.find((l) => l.bg[3] >= 1)?.el ?? null;
      return {
        measurable: !imageShows(chain),
        fg: paint(chain, parse(color)),
        bg: paint(chain, null),
        painter,
      };
    };
    const classes = (el: Element, painter: Element | null): string => {
      const out: string[] = [];
      for (let a: Element | null = el; a; a = a.parentElement) {
        const cls = typeof a.className === 'string' ? a.className : '';
        if (/(?:^|\s)(?:text|bg|placeholder|opacity)-/.test(cls)) out.push(cls);
        if (a === painter) break;
      }
      return out.join(' | ');
    };
    const visible = (el: HTMLElement) => {
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height || el.closest('[hidden], .sr-only')) return false;
      if (el.closest(':disabled, [aria-disabled="true"]')) return false;
      const cs = getComputedStyle(el);
      return cs.visibility !== 'hidden' && Number(cs.opacity) !== 0;
    };
    const NOT_TEXT_INPUTS = new Set(['hidden', 'checkbox', 'radio', 'range', 'color', 'file', 'image']);
    // [element, text, colour of that text]
    const samples: Array<[HTMLElement, string, string]> = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>('body *'))) {
      if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'OPTION'].includes(el.tagName)) continue;
      if (!visible(el)) continue;
      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
        if (el instanceof HTMLInputElement && NOT_TEXT_INPUTS.has(el.type)) continue;
        if (el.value) samples.push([el, el.value, getComputedStyle(el).color]);
        else if (el.placeholder) {
          const ph = getComputedStyle(el, '::placeholder');
          const c = parse(ph.color);
          // ::placeholder can carry its own opacity (v4 preflight used to).
          samples.push([el, `placeholder: ${el.placeholder}`, `rgba(${c[0]}, ${c[1]}, ${c[2]}, ${c[3] * Number(ph.opacity || 1)})`]);
        }
        continue;
      }
      if (el instanceof HTMLSelectElement) {
        const shown = el.selectedOptions[0]?.textContent?.trim();
        if (shown) samples.push([el, shown, getComputedStyle(el).color]);
        continue;
      }
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (own) samples.push([el, own, getComputedStyle(el).color]);
    }
    const out: ContrastFailure[] = [];
    for (const [el, text, color] of samples) {
      const { measurable, fg, bg, painter } = resolve(el, color);
      if (!measurable) continue;
      const [l1, l2] = [lum(fg), lum(bg)].sort((a, b) => b - a);
      const ratio = (l1 + 0.05) / (l2 + 0.05);
      const cs = getComputedStyle(el);
      const size = parseFloat(cs.fontSize);
      const bold = Number(cs.fontWeight) >= 700;
      const need = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
      if (ratio < need) {
        out.push({
          text: text.slice(0, 40),
          ratio: Math.round(ratio * 100) / 100,
          need,
          fg: color,
          bg: `rgb(${bg.slice(0, 3).map(Math.round).join(', ')})`,
          cls: classes(el, painter).slice(0, 160),
        });
      }
    }
    return out;
  });
}

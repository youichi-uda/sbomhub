// M14-2 (F209) + keyboard reachability — static regression fixtures for the
// shared Tooltip (KEV / EOL / SSVC / ticket badges, METI titles).
//
// Why .test.mjs (not .test.tsx): the apps/web workspace ships no React
// component test runner (no Vitest / Jest / RTL); the behaviour is driven in
// a real browser by e2e/finding-match.spec.ts ("shared Tooltip from the
// keyboard"). This file pins the structural invariants on the primitive so
// a refactor cannot silently drop them at every callsite at once.
//
// Run: pnpm --filter web test

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const raw = readFileSync(join(__dirname, "..", "tooltip.tsx"), "utf8");
// Comments stripped, so prose cannot satisfy an assertion.
const src = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'])\/\/.*$/gm, "$1");

test("the panel id is minted once with React.useId and shared through context (F209)", () => {
  assert.match(src, /interface TooltipContextValue\s*{[^}]*tooltipId:\s*string/);
  assert.match(src, /const tooltipId\s*=\s*React\.useId\(\)/);
});

test("TooltipContent is role=tooltip with the shared id, and stays mounted while closed", () => {
  assert.match(src, /role="tooltip"/);
  assert.match(src, /id=\{context\.tooltipId\}/);
  // Mounted + hidden, not unmounted: aria-describedby / aria-labelledby
  // must resolve to its text before the first hover or focus.
  assert.match(src, /hidden=\{!open\}/);
  assert.ok(!/if\s*\(!open\)\s*return null/.test(src), "TooltipContent must not unmount while closed");
});

test("the trigger references the panel unconditionally (describedby, or labelledby when icon-only)", () => {
  assert.match(src, /"aria-describedby":\s*hasName \? joinIds\(theirs\["aria-describedby"\], tooltipId\)/);
  assert.match(src, /"aria-labelledby":\s*hasName \? theirs\["aria-labelledby"\] : joinIds\(theirs\["aria-labelledby"\], tooltipId\)/);
  assert.ok(!/aria-(?:describedby|labelledby)[^\n]*context\.open/.test(src), "the reference must not be gated on open");
});

test("a non-focusable as-child trigger becomes a focus stop", () => {
  // The KEV / EOL / SSVC badges are plain <span>s: without this the focus
  // handler can never fire and the explanation is hover-only.
  assert.match(src, /tabIndex:\s*theirs\.tabIndex \?\? \(nativelyFocusable \? undefined : 0\)/);
  assert.match(src, /NATIVELY_FOCUSABLE = new Set\(\[[^\]]*"button"[^\]]*\]\)/);
  // A generic element is announced as a button; a heading keeps its role.
  assert.match(src, /GENERIC_TAGS = new Set\(\[[^\]]*"SPAN"[^\]]*"DIV"[^\]]*\]\)/);
  assert.ok(!/GENERIC_TAGS[^\n]*"H[1-6]"/.test(src), "headings must keep their role");
  assert.match(src, /el\.setAttribute\("role", "button"\)/);
});

test("it opens on hover, focus and tap, and closes on Escape", () => {
  for (const h of ["onMouseEnter", "onMouseLeave", "onFocus", "onBlur", "onTouchEnd", "onClick", "onKeyDown"]) {
    // Merged with the child's own handler, never replacing it.
    assert.match(
      src,
      new RegExp(`${h}: (?:chain\\(theirs\\.${h},|\\(e[^)]*\\) => \\{\\s*theirs\\.${h}\\?\\.\\(e\\);)`),
      `${h} must call the trigger's own handler too`,
    );
  }
  assert.match(src, /e\.key === "Escape"/);
  assert.match(src, /e\.key === "Enter" \|\| e\.key === " "/);
  // A tap elsewhere closes it (mobile browsers that do not focus a tapped span).
  assert.match(src, /addEventListener\("pointerdown", onPointerDown, true\)/);
});

test("the open state is tracked per input, so leaving with the pointer keeps a focus-opened tooltip", () => {
  assert.match(src, /const open = \(hover \|\| focus \|\| tapped\) && !dismissed/);
});

test("the composed ref keeps a React 19 callback ref's cleanup (Codex R1 Low-4)", () => {
  // React calls the composed ref's returned cleanup instead of ref(null), so
  // it must run the trigger's own cleanup, or hand it null when it gave none.
  assert.match(src, /const cleanup = setRef\(theirRef, node\);/);
  assert.match(src, /return \(\) => \{\s*nodeRef\.current = null;\s*if \(cleanup\) cleanup\(\);\s*else setRef\(theirRef, null\);/);
  assert.match(src, /return typeof cleanup === "function" \? cleanup : undefined;/);
});

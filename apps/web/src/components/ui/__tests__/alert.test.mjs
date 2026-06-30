// M14-2 (F210) — regression fixture for AlertDescription type/render alignment.
//
// Why .test.mjs (not .test.tsx): see tooltip.test.mjs header — apps/web
// ships no React component test runner; the in-repo pattern is node:test
// + node:assert with source-level structural assertions (precedent:
// src/proxy.matcher.test.mjs, src/app/.../diff/page.test.mjs).
//
// What this covers: the F210 fix that aligned the forwardRef generics
// of AlertDescription with the actually-rendered DOM element. Before
// F210, the component declared `HTMLParagraphElement` on both ref and
// prop generics while rendering a `<div>` — a silent type-vs-DOM
// mismatch that broke ref narrowing and exposed `<p>`-only attributes
// that would no-op at runtime. The render must stay as `<div>` because
// production callers nest block-level children which would be invalid
// HTML inside a `<p>` (HTML spec disallows `<div>` inside `<p>` and
// React surfaces a hydration warning). Resolution: align both generics
// to `HTMLDivElement`.
//
// Run:
//   node apps/web/src/components/ui/__tests__/alert.test.mjs

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(__dirname, "..", "alert.tsx"), "utf8");

test("AlertDescription forwardRef generics align ref + props to HTMLDivElement (F210)", () => {
  // The pre-F210 signature was:
  //   forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>
  // The render was <div>, breaking the contract on both axes. The F210
  // fix changes BOTH generics to HTMLDivElement so the type surface and
  // the rendered DOM agree. Pinning the exact signature here means a
  // regression that re-introduces HTMLParagraphElement on either generic
  // (or splits the two again — F211 was the symmetric drift on CardTitle)
  // fails fast.
  assert.ok(
    /const AlertDescription = React\.forwardRef<\s*HTMLDivElement\s*,\s*React\.HTMLAttributes<HTMLDivElement>\s*>/.test(
      src,
    ),
    "AlertDescription forwardRef must be `forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>` so the type generics agree with the rendered <div>",
  );
});

test("AlertDescription renders as <div> (production callers nest block children) (F210)", () => {
  // The render must stay <div>. Changing it to <p> would re-introduce
  // the invalid HTML nesting that caused the original asymmetry — e.g.
  // triage/ai-disabled-banner wraps AlertDescription's children in a
  // flex container with multiple block-level items. The
  // `[&_p]:leading-relaxed` Tailwind utility (which styles nested <p>
  // children, not the wrapper itself) is preserved.
  //
  // Extract the AlertDescription factory body and verify the first JSX
  // element produced is <div> with a ref + className passthrough.
  // The factory body shape is `forwardRef<...>(\n  ({...}, ref) => (\n
  //   <div ... />\n));`. We accept whitespace between the forwardRef
  // call paren and the arrow-body paren via [\s\S]*? to be robust to
  // future formatting drift.
  const match = src.match(
    /const AlertDescription = React\.forwardRef<[\s\S]*?>\([\s\S]*?\(\{[\s\S]*?\}, ref\)\s*=>\s*\(([\s\S]*?)\)\s*\);/,
  );
  assert.ok(
    match,
    "Could not locate the AlertDescription forwardRef factory body; refactor of the export shape broke this fixture",
  );
  const body = match[1];
  assert.ok(
    /^\s*<div\b/.test(body),
    `AlertDescription must render <div> as its top-level element (got body: ${body.trim().slice(0, 80)}...)`,
  );
  assert.ok(
    body.includes("ref={ref}"),
    "AlertDescription must forward the ref to the rendered <div>",
  );
  assert.ok(
    body.includes("[&_p]:leading-relaxed"),
    "AlertDescription must preserve the `[&_p]:leading-relaxed` Tailwind utility that styles nested <p> children inside the description",
  );
});

console.log("alert.test.mjs: all F210 type/render invariants pass");

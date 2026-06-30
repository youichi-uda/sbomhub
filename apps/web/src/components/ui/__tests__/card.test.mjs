// M14-2 (F211) — regression fixture for CardTitle ref/props type symmetry.
//
// Why .test.mjs (not .test.tsx): see tooltip.test.mjs header — apps/web
// ships no React component test runner; the in-repo pattern is node:test
// + node:assert with source-level structural assertions (precedent:
// src/proxy.matcher.test.mjs, src/app/.../diff/page.test.mjs).
//
// What this covers: the F211 fix that unified the forwardRef generics
// of CardTitle to HTMLHeadingElement. Before F211, the component
// declared ref as `HTMLParagraphElement` while the prop generic and
// the rendered element (`<h3>`) were both `HTMLHeadingElement` — a
// silent asymmetry that meant a caller's `ref={ref}` was typed
// `RefObject<HTMLParagraphElement>` but actually pointed at an h3,
// defeating ref-narrowing.
//
// Run:
//   node apps/web/src/components/ui/__tests__/card.test.mjs

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(__dirname, "..", "card.tsx"), "utf8");

test("CardTitle forwardRef generics align ref + props to HTMLHeadingElement (F211)", () => {
  // The pre-F211 signature was:
  //   forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLHeadingElement>>
  // i.e. ref pointed at HTMLParagraphElement but the prop generic was
  // HTMLHeadingElement — the two halves disagreed and disagreed with
  // the rendered <h3>. The F211 fix collapses both to
  // HTMLHeadingElement so the type surface and the rendered DOM agree.
  assert.ok(
    /const CardTitle = React\.forwardRef<\s*HTMLHeadingElement\s*,\s*React\.HTMLAttributes<HTMLHeadingElement>\s*>/.test(
      src,
    ),
    "CardTitle forwardRef must be `forwardRef<HTMLHeadingElement, React.HTMLAttributes<HTMLHeadingElement>>` so the type generics agree with the rendered <h3>",
  );
});

test("CardTitle renders as <h3> (h2 belongs to DialogTitle, h5 to AlertTitle) (F211)", () => {
  // Pin the rendered element. CardTitle owns the <h3> heading level in
  // the project's heading hierarchy: <h1> is the page title in
  // dashboard layout, <h2> is reserved for DialogTitle (dialog.tsx
  // F192), <h3> is CardTitle (this file), <h5> is AlertTitle
  // (alert.tsx). Changing CardTitle to anything else would break the
  // semantic outline.
  // The factory body shape is `forwardRef<...>(\n  ({...}, ref) => (\n
  //   <h3 ... />\n  )\n);`. Whitespace between the two open-parens
  // (forwardRef call paren + arrow-body paren) is significant — the
  // CardTitle factory uses a newline + indent, AlertDescription uses
  // no whitespace — so we accept both shapes via [\s\S]*? between the
  // close of the generics and the destructure.
  const match = src.match(
    /const CardTitle = React\.forwardRef<[\s\S]*?>\([\s\S]*?\(\{[\s\S]*?\}, ref\)\s*=>\s*\(([\s\S]*?)\)\s*\);/,
  );
  assert.ok(
    match,
    "Could not locate the CardTitle forwardRef factory body; refactor of the export shape broke this fixture",
  );
  const body = match[1];
  assert.ok(
    /^\s*<h3\b/.test(body),
    `CardTitle must render <h3> as its top-level element (got body: ${body.trim().slice(0, 80)}...)`,
  );
  assert.ok(
    body.includes("ref={ref}"),
    "CardTitle must forward the ref to the rendered <h3>",
  );
});

test("CardDescription generics remain symmetric on HTMLParagraphElement (F211 cross-check)", () => {
  // Cross-check the sibling so a future refactor that touches one and
  // skips the other fails at the audit step (anti-pattern 48: never
  // fix-one-instance-leave-pattern). CardDescription already had
  // symmetric generics pre-F211 and renders <p>; the assertion here
  // pins that invariant for future regressions.
  assert.ok(
    /const CardDescription = React\.forwardRef<\s*HTMLParagraphElement\s*,\s*React\.HTMLAttributes<HTMLParagraphElement>\s*>/.test(
      src,
    ),
    "CardDescription forwardRef must remain `forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>` and continue to render <p>",
  );
});

console.log("card.test.mjs: all F211 type symmetry invariants pass");

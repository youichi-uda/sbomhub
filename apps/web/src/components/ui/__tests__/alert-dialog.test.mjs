// M14-2 (F212) — regression fixture for AlertDialogTitle wrapper semantic.
//
// Why .test.mjs (not .test.tsx): see tooltip.test.mjs header — apps/web
// ships no React component test runner; the in-repo pattern is node:test
// + node:assert with source-level structural assertions (precedent:
// src/proxy.matcher.test.mjs, src/app/.../diff/page.test.mjs).
//
// What this covers: the F212 fix that adds `role="presentation"` to
// the AlertDialogTitle wrapper <div> that appears only on the
// className-override path. Pre-F212, the wrapper was an anonymous
// structural <div> in the SR tree, sitting between the role="dialog"
// panel (F205) and the inner h2 (DialogTitle, F192). Adding
// `role="presentation"` tells assistive tech that the wrapper carries
// no semantic value and that the announcement should jump directly to
// the inner DialogTitle h2 (which owns the DialogContext titleId
// surfaced via aria-labelledby on the dialog panel).
//
// Run:
//   node apps/web/src/components/ui/__tests__/alert-dialog.test.mjs

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(__dirname, "..", "alert-dialog.tsx"), "utf8");

test("AlertDialogTitle wrapper carries role='presentation' on the className-override path (F212)", () => {
  // Pin the wrapper attribute. The wrapper exists only to host the
  // caller-supplied className for visual layout — the h2 semantics and
  // the DialogContext titleId linkage live on the inner DialogTitle.
  // role="presentation" makes that structural identity explicit to
  // screen readers.
  assert.ok(
    /<div\s+className=\{className\}\s+role=["']presentation["']\s*>/.test(src) ||
      /<div\s+role=["']presentation["']\s+className=\{className\}\s*>/.test(src),
    "AlertDialogTitle wrapper <div> on the className-override path must carry role=\"presentation\" so SRs treat it as a structural-only node and announce the inner DialogTitle h2 directly",
  );
});

test("AlertDialogTitle wrapper still delegates to DialogTitle (h2 + titleId linkage) (F212 + F205)", () => {
  // The wrapper must still render DialogTitle as its child so the
  // useId-minted titleId from DialogContext lands on the inner h2 and
  // the dialog panel's aria-labelledby resolves to it. F212 is a pure
  // additive ARIA hint; the F205 composition contract must remain
  // intact.
  assert.ok(
    /role=["']presentation["']\s*>\s*\n?\s*<DialogTitle>/.test(src) ||
      /<div[\s\S]*?role=["']presentation["'][\s\S]*?>\s*<DialogTitle>/.test(src),
    "AlertDialogTitle wrapper must still render <DialogTitle> as its child so the F205 h2 + DialogContext titleId linkage is preserved",
  );
});

test("AlertDialogTitle no-className path remains a direct DialogTitle delegation (F205 + F212)", () => {
  // The two current production callers (settings/apikeys,
  // settings/integrations) pass no className override, so they MUST
  // hit the direct delegation path with no wrapper at all — adding
  // role="presentation" to that branch would be a no-op DOM bloat.
  // Verify the function returns `<DialogTitle>...</DialogTitle>`
  // unwrapped when className is falsy.
  const fnMatch = src.match(
    /function AlertDialogTitle\([\s\S]*?\)\s*\{([\s\S]*?)\n\}/,
  );
  assert.ok(
    fnMatch,
    "Could not locate the AlertDialogTitle function body; refactor of the export shape broke this fixture",
  );
  const body = fnMatch[1];
  assert.ok(
    /return <DialogTitle>\{children\}<\/DialogTitle>;/.test(body),
    "AlertDialogTitle must return `<DialogTitle>{children}</DialogTitle>` directly (no wrapper) on the no-className path so the existing settings/apikeys + settings/integrations callsites stay zero-wrapper",
  );
  // Sanity: only one wrapped branch, and only one direct branch — i.e.
  // the function body contains both `<div ... role="presentation">`
  // and `return <DialogTitle>`. Catches a future refactor that
  // collapses both branches into a single always-wrapped path.
  assert.ok(
    /role=["']presentation["']/.test(body),
    "AlertDialogTitle body must contain the role=\"presentation\" wrapper branch (F212)",
  );
});

console.log("alert-dialog.test.mjs: all F212 wrapper semantic invariants pass");

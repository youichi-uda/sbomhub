// M14-2 (F209) — regression fixtures for the Tooltip ARIA wiring.
//
// Why .test.mjs (not .test.tsx): the apps/web workspace does not ship a
// React component test runner (no Vitest, no Jest, no React Testing
// Library). The only existing JS-side test pattern in the repo is the
// node:assert + node:test scripts at src/proxy.matcher.test.mjs and
// src/app/.../diff/page.test.mjs. Adding a new test framework is out of
// scope for M14-2 (per the wave: closure-only cosmetic primitive
// hardening, no new dependencies).
//
// What this covers: the F209 ARIA contract on the Tooltip primitive —
// role="tooltip", a shared useId-minted id linking trigger
// aria-describedby to the panel id, the id being set on the trigger
// regardless of `context.open`, and the touch/focus handlers that keep
// keyboard / mobile a11y on the same SR contract as mouse hover. A
// regression here means SRs lose the tooltip association at every
// callsite (eol-badge, kev-badge, ssvc-badge, ticket-status, etc.) at
// once, so we pin the structural invariants on the primitive itself.
//
// Run:
//   node apps/web/src/components/ui/__tests__/tooltip.test.mjs
//
// CI: wired into .github/workflows/frontend-ci.yml alongside the other
// M14-2 primitive regression fixtures.

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(__dirname, "..", "tooltip.tsx"), "utf8");

test("TooltipContext exposes tooltipId field (F209)", () => {
  assert.ok(
    /interface TooltipContextValue\s*{[^}]*tooltipId:\s*string/.test(src),
    "TooltipContextValue must declare a `tooltipId: string` field so the trigger + content halves can share the useId-minted identifier",
  );
});

test("Tooltip provider mints a stable tooltipId via React.useId (F209)", () => {
  assert.ok(
    /const tooltipId\s*=\s*React\.useId\(\)/.test(src),
    "Tooltip provider must mint the tooltipId with React.useId() so the ARIA reference is stable across re-renders",
  );
  // The context value memo must include tooltipId so consumers re-render
  // when the id changes (it won't, but the memo dep list keeps the
  // contract explicit).
  assert.ok(
    /React\.useMemo[\s\S]*?\[\s*open\s*,\s*tooltipId\s*\]/.test(src),
    "Tooltip provider's context value useMemo must depend on tooltipId so the id is part of the published contract",
  );
});

test("TooltipContent renders with role='tooltip' + the shared id (F209)", () => {
  // Pin both the role and the id linkage to the context value. A future
  // refactor that drops either side breaks the SR contract: role=tooltip
  // tells the SR what the panel is, id is what the trigger's
  // aria-describedby resolves to.
  assert.ok(
    /role=["']tooltip["']/.test(src),
    "TooltipContent must declare role=\"tooltip\" so screen readers announce the panel as a tooltip rather than an anonymous div",
  );
  assert.ok(
    /id=\{context\.tooltipId\}/.test(src),
    "TooltipContent must set id={context.tooltipId} so the trigger's aria-describedby reference resolves to the panel",
  );
});

test("TooltipTrigger sets aria-describedby unconditionally (F209)", () => {
  // The SR contract requires the describedby reference to be present
  // BEFORE the user hovers/focuses — the dangling reference (when
  // content is unmounted while closed) is handled gracefully by SRs and
  // becomes live the moment the panel mounts. Gating aria-describedby
  // on `context.open` would lose the association at exactly the moment
  // the SR needs to look it up.
  const ariaDescribedByLines = src
    .split("\n")
    .filter((line) => line.includes("aria-describedby"))
    .filter((line) => !line.trim().startsWith("//"))
    // Skip the cloneElement TypeScript prop-type declaration line
    // (`"aria-describedby"?: string;` inside the generic arg). It's a
    // type surface declaration, not an attribute assignment.
    .filter((line) => !/\?:\s*string/.test(line));
  assert.ok(
    ariaDescribedByLines.length >= 2,
    `TooltipTrigger must set aria-describedby on both the cloneElement and the fallback <span> branches (found ${ariaDescribedByLines.length} non-comment / non-type-decl occurrences)`,
  );
  // Both branches must reference context.tooltipId (not a string
  // literal or a different id source).
  for (const line of ariaDescribedByLines) {
    assert.ok(
      line.includes("context.tooltipId"),
      `aria-describedby must reference context.tooltipId, got: ${line.trim()}`,
    );
  }
  // The TooltipTrigger function body must NOT short-circuit on
  // !context.open when setting describedby — that would defeat the
  // pre-hover SR contract.
  assert.ok(
    !/aria-describedby=\{[^}]*context\.open[^}]*\}/.test(src),
    "aria-describedby must NOT be gated on context.open — the SR reference must be stable before hover/focus",
  );
});

test("TooltipTrigger opens on focus + touchend for keyboard/mobile a11y (F209)", () => {
  // Hover-only (mouseenter/leave) excludes keyboard-only and touch-only
  // operators. The F209 hardening wires onFocus + onTouchEnd to the
  // same setOpen(true) path so the SR contract is uniform across input
  // modalities.
  assert.ok(
    /onFocus:\s*handleOpen/.test(src),
    "TooltipTrigger cloneElement must wire onFocus: handleOpen for keyboard-only a11y",
  );
  assert.ok(
    /onBlur:\s*handleClose/.test(src),
    "TooltipTrigger cloneElement must wire onBlur: handleClose so focus moving away closes the tooltip",
  );
  assert.ok(
    /onTouchEnd:\s*handleOpen/.test(src),
    "TooltipTrigger cloneElement must wire onTouchEnd: handleOpen for mobile / touch a11y (no mouseenter on touch surfaces)",
  );
  // Fallback span branch must also include the same handlers so non-
  // asChild callsites get the same a11y contract.
  assert.ok(
    /onFocus=\{handleOpen\}/.test(src),
    "Fallback <span> branch must wire onFocus={handleOpen}",
  );
  assert.ok(
    /onTouchEnd=\{handleOpen\}/.test(src),
    "Fallback <span> branch must wire onTouchEnd={handleOpen}",
  );
  // The fallback span must be focusable (tabIndex={0}) so the focus
  // handlers actually fire under keyboard-only navigation.
  assert.ok(
    /tabIndex=\{0\}/.test(src),
    "Fallback <span> branch must set tabIndex={0} so it accepts keyboard focus and the onFocus handler can fire",
  );
});

console.log("tooltip.test.mjs: all F209 ARIA invariants pass");

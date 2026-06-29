// SBOMHub - apps/web ESLint flat config (M11-5 #80)
//
// Next.js 16 removed `next lint`; the v9.x ESLint binary is now invoked
// directly via the package script. eslint-config-next@16 ships a native
// flat-config (`Linter.Config[]`) so we no longer need FlatCompat.
//
// Layers (order matters — later rules win):
//   1. next/core-web-vitals  → @next/next + react + react-hooks + jsx-a11y + import
//   2. next/typescript        → typescript-eslint recommended
//   3. project-local overrides (this file)
//
// IDE integration (VSCode "ESLint" extension / JetBrains "ESLint" inspector)
// auto-detects eslint.config.mjs at the project root — no extra setting
// required.

import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

const config = [
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    // Global ignores. node_modules / .git are implicit. We exclude
    // build artefacts and the Playwright E2E suite (which lives under
    // apps/web/e2e and is exercised by a different toolchain).
    ignores: [
      ".next/**",
      "out/**",
      "build/**",
      "next-env.d.ts",
      // Playwright specs (M11-2 territory) — kept out of the lint gate
      // to avoid coupling this gate to the e2e migration cadence.
      "e2e/**",
      // Plain Node test fixture (M10-4 proxy matcher invariant) — run
      // directly by `node ...test.mjs` in CI, not via vitest/jest.
      "src/proxy.matcher.test.mjs",
      // Ad-hoc dev utility for capturing landing-page screenshots
      // (used to refresh sbomhub-internal/screenshots/). Hardcoded
      // Windows path, never imported by app code, never executed by CI.
      "screenshot.js",
    ],
  },
  {
    rules: {
      // -- react-hooks plugin v7 new rules (M11-5 #80) --
      // These rules ship with eslint-plugin-react-hooks@7 as errors. The
      // patterns they flag are legitimate concerns, but they fire on
      // pre-existing M0-M9 code that would need behaviour-preserving
      // refactors (state-machine restructuring, useEvent migrations) to
      // satisfy. Downgrading to `warn` keeps them visible in IDE output
      // and CI logs without blocking unrelated PRs on a cross-cutting
      // cleanup wave. Promotion back to `error` is tracked separately.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/immutability": "warn",
    },
  },
];

export default config;

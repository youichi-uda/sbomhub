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
      // -- react-hooks plugin v7 new rules (M11-5 #80 → promoted M12-5 #86) --
      // M11-5 (#80) downgraded these from the plugin default (error) to
      // `warn` because pre-existing M0-M9 code triggered them and a
      // cross-cutting cleanup wave was needed before they could be a
      // hard gate.
      //
      // M12-5 (#86) audited every active site:
      //   - `set-state-in-effect`: 3 hits remaining, each is legitimate
      //     external-state sync (Clerk readiness in api-auth-provider,
      //     pathname-driven exempt branch in subscription-guard,
      //     fetch-lifecycle publication in kev-badge). Each is suppressed
      //     locally with an inline `eslint-disable-next-line` + rationale.
      //   - `immutability`: 0 hits in the codebase as of M12-5 close.
      //
      // With every existing violation either fixed or explicitly disabled
      // with rationale, promoting these to `error` means any NEW violation
      // either earns its own justified inline disable or gets fixed before
      // merge — which is exactly the policy we want.
      "react-hooks/set-state-in-effect": "error",
      "react-hooks/immutability": "error",
      // `react-hooks/incompatible-library` is intentionally left at the
      // plugin default (warn). The only current hit is react-hook-form's
      // `watch()` in criterion-card.tsx, which is structurally
      // unmemoizable; promoting this rule to error would require
      // codebase-wide migration to `useWatch` (tracked for M13). The
      // single existing site is locally suppressed with rationale.
      // -- unused vars: allow `_`-prefixed names (M12-5 #86) --
      // We deliberately keep some props/args around to preserve a public
      // API shape (e.g. shadcn-style component params such as `asChild`,
      // `sideOffset`, `disabled`, or `onClose` callbacks reserved for a
      // future hookup) and some `catch (err)` bindings. Renaming them to
      // `_foo` (via destructure-alias when the public prop name must be
      // kept) flags intent without losing the type-level surface.
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
          destructuredArrayIgnorePattern: "^_",
          ignoreRestSiblings: true,
        },
      ],
    },
  },
];

export default config;

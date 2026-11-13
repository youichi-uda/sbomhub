// Theme-token guard: every Tailwind utility the app uses must generate CSS.
//
// Run: pnpm --filter web test
//
// Why this exists. Tailwind silently emits NOTHING for a utility whose theme
// value is not defined: `bg-popover` with no `--color-popover` is not an
// error, it is a transparent background. The shared Tooltip (KEV / EOL /
// SSVC badges) and the Select dropdown used `bg-popover` /
// `text-popover-foreground`, and Card used `bg-card` /
// `text-card-foreground`, none of which tailwind.config.ts (v3) or
// globals.css (v4, M61) ever defined: the KEV tooltip rendered as
// unreadable text over the page. The tooltip also carried
// `animate-in fade-in-0 zoom-in-95` from the tailwindcss-animate plugin,
// which was never installed.
//
// What is pinned:
//   1. every shadcn/ui colour token the app references through a utility
//      (bg-popover, text-muted-foreground, ring-offset-background, ...)
//      compiles to a rule, and its CSS variable has a light (:root) AND a
//      dark (.dark) value in globals.css;
//   2. every class-like token in a source string literal that also holds
//      ordinary utilities compiles to CSS, so a utility from a plugin that
//      is not installed, or a typo, fails here instead of in a screenshot.
//      Marker classes that are meant to emit nothing are allow-listed.
//
// The CSS is compiled with tailwindcss's own compile() over the real
// src/app/globals.css (the same entry @tailwindcss/postcss builds), one
// fresh compiler per candidate so the output of one cannot mask another.

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { compile } from "tailwindcss";

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(here, "..", "..");
const srcRoot = join(webRoot, "src");
const require = createRequire(import.meta.url);
const globalsPath = join(here, "globals.css");
const globalsCss = readFileSync(globalsPath, "utf8");

function newCompiler() {
  return compile(globalsCss, {
    base: here,
    async loadStylesheet(id, base) {
      const path = id === "tailwindcss" ? require.resolve("tailwindcss/index.css") : resolve(base, id);
      return { path, base: dirname(path), content: readFileSync(path, "utf8") };
    },
  });
}

const baselineLength = (await newCompiler()).build([]).length;

/** The CSS a single candidate adds over an empty build ("" when none). */
async function cssFor(candidate) {
  const out = (await newCompiler()).build([candidate]);
  return out.length === baselineLength ? "" : out;
}

function* sourceFiles(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === "__tests__") continue;
      yield* sourceFiles(p);
    } else if (/\.(tsx?|jsx?)$/.test(name) && !/\.test\./.test(name)) {
      yield p;
    }
  }
}

// A string literal is treated as a class list when it holds at least one
// unmistakable utility; only then are its other tokens checked.
// Variants, including arbitrary ones (`[&_tr]:`, `data-[state=selected]:`).
const VARIANTS = String.raw`(?:(?:[a-z0-9-]*\[[^\]\s]+\]|[a-z0-9-]+):)*`;
const UTILITY_HINT = new RegExp(
  `^${VARIANTS}-?(?:flex|grid|inline-flex|block|hidden|text-|bg-|border|rounded|p[xytrbl]?-|m[xytrbl]?-|w-|h-|gap-|items-|justify-|space-[xy]-|font-|shadow|ring|translate-|-translate-|opacity-|z-|top-|left-|right-|bottom-|inset-|overflow-|cursor-|transition|duration-|scale-|rotate-|min-[wh]-|max-[wh]-|leading-|tracking-|whitespace-|truncate|sr-only|outline|underline|line-clamp-|shrink|grow|self-(?:auto|start|end|center|stretch|baseline)|place-|order-|col-|row-)`,
);
// A utility candidate, optionally behind (arbitrary) variants. The utility
// itself must end in a letter, digit, `]`, `)` or `%`, which keeps prose
// such as "block:" out.
const CLASS_TOKEN = new RegExp(String.raw`^${VARIANTS}!?-?[a-z][a-z0-9\-/[\]().%#_,]*[a-z0-9\])%]$`);
// Classes that intentionally generate no CSS of their own.
const MARKER_CLASSES = new Set(["group", "peer"]);

function isComparedLiteral(before, after) {
  return /[=!]=\s*$/.test(before) || /^\s*[=!]=/.test(after);
}

/** token -> files using it */
function collectClassTokens() {
  const uses = new Map();
  for (const file of sourceFiles(srcRoot)) {
    const text = readFileSync(file, "utf8");
    // Single-line '...' / "..." literals, and `...` template literals that
    // may span lines (a class list broken across lines).
    // A literal right after `className=` is a class list whatever it holds
    // (Codex R2 Low-2: "prose prose-gray max-w-none" has no hint token).
    for (const m of text.matchAll(/(className=\{?\s*)?(?:["']([^"'`\n]{2,600})["']|`([^`]{2,2000})`)/g)) {
      // In a template literal, ${...} is code, not classes: drop it, but keep
      // the string literals inside it (`${x ? ' text-muted-foreground' : ''}`).
      // A literal compared with === / !== is a value, not a class list
      // (`authMode === "clerk" ? "bg-green-100" : ...`).
      const end = m.index + m[0].length;
      if (isComparedLiteral(text.slice(Math.max(0, m.index - 4), m.index), text.slice(end, end + 4))) continue;
      const body =
        m[2] ??
        m[3].replace(/\$\{([^}]*)\}/g, (_, expr) =>
          [...expr.matchAll(/["']([^"'\n]*)["']/g)]
            .filter((q) => !isComparedLiteral(expr.slice(Math.max(0, q.index - 4), q.index), expr.slice(q.index + q[0].length, q.index + q[0].length + 4)))
            .map((q) => ` ${q[1]} `)
            .join(" ") || " ",
        );
      const tokens = body.split(/\s+/).filter(Boolean);
      if (!m[1] && !tokens.some((t) => UTILITY_HINT.test(t))) continue;
      for (const t of tokens) {
        // Only hyphenated / variant tokens: a bare word in a class-ish
        // string ("null", "ticket.id") is not a utility candidate.
        if (!CLASS_TOKEN.test(t) || (!m[1] && !/[-:]/.test(t)) || MARKER_CLASSES.has(t)) continue;
        if (!uses.has(t)) uses.set(t, new Set());
        uses.get(t).add(relative(webRoot, file));
      }
    }
  }
  return uses;
}

const classUses = collectClassTokens();

// shadcn/ui colour tokens (https://ui.shadcn.com/docs/theming).
const TOKEN_NAMES = [
  "background",
  "foreground",
  "card",
  "card-foreground",
  "popover",
  "popover-foreground",
  "primary",
  "primary-foreground",
  "secondary",
  "secondary-foreground",
  "muted",
  "muted-foreground",
  "accent",
  "accent-foreground",
  "destructive",
  "destructive-foreground",
  "border",
  "input",
  "ring",
];
const COLOR_UTILITY = new RegExp(
  `^(?:[a-z0-9-]+:)*(?:bg|text|border(?:-[trblxy])?|ring|ring-offset|outline|fill|stroke|divide|placeholder|from|via|to|shadow|decoration|caret|accent)-(${TOKEN_NAMES.join("|")})(?:/\\d+)?$`,
);

function tokenUses() {
  const out = new Map();
  for (const [t, files] of classUses) {
    const m = COLOR_UTILITY.exec(t);
    if (m) out.set(t, { token: m[1], files });
  }
  return out;
}

/** The custom properties a CSS block defines, by selector. */
function varsDefinedIn(selector) {
  const start = globalsCss.search(new RegExp(`(^|\\n)\\s*${selector.replace(".", "\\.")}\\s*\\{`));
  assert.notEqual(start, -1, `globals.css has no ${selector} block`);
  const body = globalsCss.slice(start, globalsCss.indexOf("}", start));
  return new Set([...body.matchAll(/--([a-z0-9-]+)\s*:/g)].map((m) => m[1]));
}

describe("shadcn/ui theme tokens", () => {
  test("the scan finds the token utilities the components are known to use", () => {
    // Guards the extractor itself: if it stopped finding these, every
    // assertion below would pass vacuously.
    const used = tokenUses();
    for (const t of ["bg-popover", "text-popover-foreground", "bg-card", "text-card-foreground", "text-muted-foreground"]) {
      assert.ok(used.has(t), `${t} not found in src/ — the class scan is broken`);
    }
  });

  test("every token utility used in src/ generates CSS", async () => {
    const dead = [];
    for (const [t, { files }] of tokenUses()) {
      if ((await cssFor(t)) === "") dead.push(`${t}  (${[...files].slice(0, 3).join(", ")})`);
    }
    assert.deepEqual(dead, [], `theme utilities that generate no CSS:\n  ${dead.join("\n  ")}`);
  });

  test("popover and card utilities read their own variables", async () => {
    assert.match(await cssFor("bg-popover"), /background-color:\s*hsl\(var\(--popover\)\)/);
    assert.match(await cssFor("text-popover-foreground"), /color:\s*hsl\(var\(--popover-foreground\)\)/);
    assert.match(await cssFor("bg-card"), /background-color:\s*hsl\(var\(--card\)\)/);
    assert.match(await cssFor("text-card-foreground"), /color:\s*hsl\(var\(--card-foreground\)\)/);
  });

  test("every used token has a light (:root) and a dark (.dark) value", () => {
    const light = varsDefinedIn(":root");
    const dark = varsDefinedIn(".dark");
    const missing = [];
    for (const token of new Set([...tokenUses().values()].map((u) => u.token))) {
      if (!light.has(token)) missing.push(`--${token} in :root`);
      if (!dark.has(token)) missing.push(`--${token} in .dark`);
    }
    assert.deepEqual(missing, []);
  });

  test("every @theme colour reference names a defined variable", () => {
    const light = varsDefinedIn(":root");
    const refs = [...globalsCss.matchAll(/--color-[a-z0-9-]+:\s*hsl\(var\(--([a-z0-9-]+)\)\)/g)].map((m) => m[1]);
    assert.ok(refs.length > 0, "no @theme colour references found");
    assert.deepEqual(refs.filter((r) => !light.has(r)), []);
  });
});

// Dark mode (residual of the popover fix): Tailwind v4's default `dark:`
// variant follows `prefers-color-scheme`, while the token overrides sit on
// `.dark`, which nothing sets — in an OS dark scheme the `dark:` utilities
// turned dark on a light page (grey-400 audit pills on white). Both halves
// must switch on ONE condition, and every light token needs a value under it.
describe("dark mode switches tokens and dark: utilities on one condition", () => {
  const DARK_SELECTOR = ".dark";
  const darkUtilities = [...classUses.keys()].filter((t) => /(^|:)dark:/.test(t));

  /** Body of the first rule in `css` whose selector contains `marker`. */
  function selectorOf(css, marker) {
    const i = css.indexOf(marker);
    assert.notEqual(i, -1, `${marker} not in the compiled CSS`);
    const open = css.indexOf("{", i);
    return css.slice(css.lastIndexOf("\n", i) + 1, open).trim();
  }

  test("the scan finds the dark: utilities in src/", () => {
    assert.ok(darkUtilities.length >= 20, `only ${darkUtilities.length} dark: utilities found — the scan is broken`);
  });

  test("the dark: variant is the token condition (.dark), not the OS media query", async () => {
    const css = await cssFor("dark:bg-red-500");
    const sel = selectorOf(css, ".dark\\:bg-red-500");
    assert.equal(sel, ".dark\\:bg-red-500:where(.dark, .dark *)", "dark: must match an element that is or sits inside the token selector");
    assert.ok(!css.includes("prefers-color-scheme"), "dark: still compiles to a prefers-color-scheme media query");
    // The token overrides live on that same selector.
    assert.ok(varsDefinedIn(DARK_SELECTOR).has("background"));
  });

  test("no dark: utility used in src/, and no token, switches on prefers-color-scheme", async () => {
    const css = (await newCompiler()).build(darkUtilities);
    assert.ok(!/prefers-color-scheme/.test(css), "a dark rule follows the OS scheme while the tokens follow .dark");
    assert.ok(!/prefers-color-scheme/.test(globalsCss.replace(/\/\*[\s\S]*?\*\//g, "")), "globals.css defines a second dark condition");
    for (const t of darkUtilities) {
      const out = await cssFor(t);
      assert.match(out, /:where\(\.dark, \.dark \*\)/, `${t} does not compile under the .dark condition`);
    }
  });

  test("every colour variable defined for light has a dark value, and vice versa", () => {
    const light = new Set([...varsDefinedIn(":root")].filter((v) => v !== "radius"));
    const dark = varsDefinedIn(DARK_SELECTOR);
    assert.ok(light.size >= 19, `only ${light.size} light variables found — the block scan is broken`);
    assert.deepEqual([...light].filter((v) => !dark.has(v)), [], "light variables with no .dark value");
    assert.deepEqual([...dark].filter((v) => !light.has(v)), [], ".dark variables with no light value");
  });

  test("native controls follow the same scheme as the tokens", () => {
    const block = (sel) => {
      const start = globalsCss.search(new RegExp(`(^|\\n)\\s*${sel.replace(".", "\\.")}\\s*\\{`));
      return globalsCss.slice(start, globalsCss.indexOf("}", start));
    };
    assert.match(block(":root"), /color-scheme:\s*light\s*;/);
    assert.match(block(DARK_SELECTOR), /color-scheme:\s*dark\s*;/);
  });
});

describe("every class-like token in src/ generates CSS", () => {
  test("the scan sees the class lists", () => {
    assert.ok(classUses.size > 200, `only ${classUses.size} class tokens found — the class scan is broken`);
    assert.ok(classUses.has("text-muted-foreground"));
    // Codex R1 Low-2: arbitrary variants must be scanned too (table.tsx,
    // alert.tsx), not dropped as non-class tokens.
    for (const t of ["[&_tr]:border-b", "data-[state=selected]:bg-muted", "[&>svg]:text-destructive", "max-w-none", "flex", "translate-x-5", "translate-x-0"]) {
      assert.ok(classUses.has(t), `${t} not collected by the class scan`);
    }
  });

  test("the compile check itself rejects a dead token behind an arbitrary variant", async () => {
    assert.notEqual(await cssFor("[&_tr]:border-b"), "");
    assert.equal(await cssFor("[&_tr]:border-bogus-token"), "");
    assert.equal(await cssFor("data-[state=selected]:bg-popover-bogus"), "");
  });

  test("no utility in src/ compiles to nothing", async () => {
    const dead = [];
    for (const [t, files] of classUses) {
      if ((await cssFor(t)) === "") dead.push(`${t}  (${[...files].slice(0, 3).join(", ")})`);
    }
    assert.deepEqual(dead, [], `classes that generate no CSS (typo, undefined theme token, or a plugin that is not installed):\n  ${dead.join("\n  ")}`);
  });
});

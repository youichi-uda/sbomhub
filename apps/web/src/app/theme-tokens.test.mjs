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
const UTILITY_HINT =
  /^(?:[a-z-]+:)*-?(?:flex|grid|inline-flex|block|hidden|text-|bg-|border|rounded|p[xytrbl]?-|m[xytrbl]?-|w-|h-|gap-|items-|justify-|space-[xy]-|font-|shadow|ring)/;
const CLASS_TOKEN = /^!?-?[a-z][a-z0-9:\-/[\]().%#_,]*[a-z0-9\])%]$/;
// Classes that intentionally generate no CSS of their own.
const MARKER_CLASSES = new Set(["group", "peer"]);

/** token -> files using it */
function collectClassTokens() {
  const uses = new Map();
  for (const file of sourceFiles(srcRoot)) {
    const text = readFileSync(file, "utf8");
    for (const m of text.matchAll(/["'`]([^"'`\n]{2,600})["'`]/g)) {
      const tokens = m[1].split(/\s+/).filter(Boolean);
      if (!tokens.some((t) => UTILITY_HINT.test(t))) continue;
      for (const t of tokens) {
        // Only hyphenated / variant tokens: a bare word in a class-ish
        // string ("null", "ticket.id") is not a utility candidate.
        if (!CLASS_TOKEN.test(t) || !/[-:]/.test(t) || MARKER_CLASSES.has(t)) continue;
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

describe("every class-like token in src/ generates CSS", () => {
  test("the scan sees the class lists", () => {
    assert.ok(classUses.size > 200, `only ${classUses.size} class tokens found — the class scan is broken`);
    assert.ok(classUses.has("text-muted-foreground"));
  });

  test("no utility in src/ compiles to nothing", async () => {
    const dead = [];
    for (const [t, files] of classUses) {
      if ((await cssFor(t)) === "") dead.push(`${t}  (${[...files].slice(0, 3).join(", ")})`);
    }
    assert.deepEqual(dead, [], `classes that generate no CSS (typo, undefined theme token, or a plugin that is not installed):\n  ${dead.join("\n  ")}`);
  });
});

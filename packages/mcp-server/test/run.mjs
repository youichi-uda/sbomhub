#!/usr/bin/env node
// Test entrypoint: finds every *.test.mjs under test/ and hands the exact list
// to `node --test`.
//
// Why not a glob in package.json: `node --test <dir>` was dropped in Node 24,
// and a shell glob does not expand on Windows. Why not the explicit list this
// replaces: that list could disable its own guard — the check that every test
// file is listed lived in one of the listed files, so dropping that file from
// the list silently dropped the check with it (Codex R1, High).
//
// Enumeration is by directory walk, so a new test file is picked up by
// existing, and cannot be omitted by editing a list.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const testDir = fileURLToPath(new URL(".", import.meta.url));

function collect(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...collect(full));
    } else if (entry.name.endsWith(".test.mjs")) {
      found.push(full);
    }
  }
  return found;
}

const files = collect(testDir).sort();
if (files.length === 0) {
  console.error(`no *.test.mjs files under ${testDir}`);
  process.exit(1);
}

const result = spawnSync(
  process.execPath,
  ["--test", "--test-reporter=spec", ...files],
  { stdio: "inherit" }
);
if (result.error) {
  throw result.error;
}
// A signal-killed child reports status null; treat anything but a clean 0 as
// failure so a crash cannot pass for a green run.
process.exit(result.status ?? 1);

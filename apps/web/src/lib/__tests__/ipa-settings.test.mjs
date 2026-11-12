// M71 (Codex R3 Medium): what counts as an IPA settings answer
// (src/lib/ipa-settings.ts). Anything else is a load failure, so the page
// never shows a form of defaults whose Save would send an empty object.
// Run: pnpm --filter web test
import assert from "node:assert/strict";
import { test } from "node:test";

import { parseIPASyncSettings } from "../ipa-settings.ts";

const good = { tenant_id: "t", enabled: false, notify_on_new: true, notify_severity: ["CRITICAL"], last_sync_at: "2026-11-01T00:00:00Z" };

test("a real answer passes through", () => {
  assert.deepEqual(parseIPASyncSettings(good), good);
});

test("a null severity list (Go nil slice) is an empty list", () => {
  assert.deepEqual(parseIPASyncSettings({ ...good, notify_severity: null }).notify_severity, []);
  assert.deepEqual(parseIPASyncSettings({ ...good, notify_severity: undefined }).notify_severity, []);
});

test("empty or malformed answers are rejected", () => {
  for (const v of [
    undefined,
    null,
    "",
    "ok",
    0,
    [],
    [good],
    {},
    { enabled: true },
    { ...good, enabled: "true" },
    { ...good, notify_on_new: undefined },
    { ...good, notify_severity: "CRITICAL" },
    { ...good, notify_severity: [1] },
  ]) {
    assert.equal(parseIPASyncSettings(v), null, JSON.stringify(v));
  }
});

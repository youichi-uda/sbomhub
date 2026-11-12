// M71: timestamp display (src/lib/format-date.ts).
// Run: pnpm --filter web test
import assert from "node:assert/strict";
import { test } from "node:test";

import { formatTimestamp, TIMESTAMP, TIMESTAMP_WITH_ZONE } from "../format-date.ts";

const UTC = { timeZone: "UTC" };

test("formats per locale, not as the raw ISO string", () => {
  const v = "2026-11-09T00:00:00Z";
  const en = formatTimestamp(v, "en", { ...TIMESTAMP_WITH_ZONE, ...UTC });
  const ja = formatTimestamp(v, "ja", { ...TIMESTAMP_WITH_ZONE, ...UTC });
  assert.match(en, /^Nov 9, 2026, 12:00:00\sAM UTC$/);
  assert.match(ja, /^2026\/11\/09 0:00:00 UTC$/);
  assert.notEqual(en, v);
});

test("the zoned form names the zone; the default form is date + minutes", () => {
  const v = "2026-11-09T03:04:05Z";
  assert.match(formatTimestamp(v, "en", { ...TIMESTAMP_WITH_ZONE, timeZone: "Asia/Tokyo" }), /12:04:05\sPM GMT\+9$/);
  assert.match(formatTimestamp(v, "en", { ...TIMESTAMP, ...UTC }), /^Nov 9, 2026, 3:04\sAM$/);
});

test("default options match the CRA components' former local copies", () => {
  const v = "2026-01-02T03:04:05Z";
  assert.equal(formatTimestamp(v, "ja"), new Date(v).toLocaleString("ja", { dateStyle: "medium", timeStyle: "short" }));
});

test("an unparseable value is shown as is", () => {
  for (const v of ["", "not a date", "2026-13-45T99:99:99Z"]) {
    assert.equal(formatTimestamp(v, "en", TIMESTAMP_WITH_ZONE), v);
  }
});

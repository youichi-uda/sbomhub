// Migration 072: JVN iPedia advisories on the vulnerability list
// (src/lib/jvndb.ts). Pinned: the href is rebuilt from the id, never taken
// from the API; malformed entries are dropped; non-arrays yield nothing.
//
// Run: pnpm --filter web test

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { jvndbAdvisoryUrl, parseJvndbAdvisories } from "../jvndb.ts";

describe("jvndbAdvisoryUrl", () => {
  test("builds the year-scoped canonical page", () => {
    assert.equal(
      jvndbAdvisoryUrl("JVNDB-2026-044393"),
      "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-044393.html",
    );
  });
  test("refuses anything that is not a JVNDB id", () => {
    for (const bad of ["", "JVNDB-26-1", "javascript:alert(1)", "JVNDB-2026-044393/../x", null, 7]) {
      assert.equal(jvndbAdvisoryUrl(bad), null);
    }
  });
});

describe("parseJvndbAdvisories", () => {
  test("keeps valid entries and ignores the server url", () => {
    const got = parseJvndbAdvisories([
      {
        id: "JVNDB-2026-044393",
        title: " OpenJDKにおけるヒープベースのバッファオーバーフローの脆弱性 ",
        url: "javascript:alert(1)",
        published: "2026-11-19T07:12:00Z",
      },
    ]);
    assert.deepEqual(got, [
      {
        id: "JVNDB-2026-044393",
        title: "OpenJDKにおけるヒープベースのバッファオーバーフローの脆弱性",
        url: "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-044393.html",
        published: "2026-11-19T07:12:00Z",
      },
    ]);
  });
  test("drops malformed, empty-titled and duplicate entries and bad dates", () => {
    const got = parseJvndbAdvisories([
      { id: "bad", title: "x" },
      { id: "JVNDB-2025-009576", title: "  " },
      { id: "JVNDB-2025-009576", title: "a", published: "not a date" },
      { id: "JVNDB-2025-009576", title: "dup" },
      null,
      "JVNDB-2025-000001",
    ]);
    assert.deepEqual(got, [
      { id: "JVNDB-2025-009576", title: "a", url: "https://jvndb.jvn.jp/ja/contents/2025/JVNDB-2025-009576.html" },
    ]);
  });
  test("caps the title by code point, never inside a surrogate pair", () => {
    const title = "𠀋".repeat(1200); // supplementary-plane kanji, 2 UTF-16 units each
    const [a] = parseJvndbAdvisories([{ id: "JVNDB-2026-000001", title }]);
    assert.equal(Array.from(a.title).length, 1000);
    assert.ok(!a.title.includes("\uFFFD"));
    assert.equal(a.title.length, 2000);
  });
  test("caps the list at five", () => {
    const many = Array.from({ length: 8 }, (_, i) => ({ id: `JVNDB-2026-00000${i}`, title: `t${i}` }));
    assert.equal(parseJvndbAdvisories(many).length, 5);
  });
  test("non-arrays yield nothing", () => {
    for (const v of [undefined, null, {}, "x", 1]) assert.deepEqual(parseJvndbAdvisories(v), []);
  });
});

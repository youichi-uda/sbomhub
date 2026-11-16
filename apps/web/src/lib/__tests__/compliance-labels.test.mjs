// The compliance overview API answers in Japanese only; /en showed it
// verbatim (src/lib/compliance-labels.ts). Run: pnpm --filter web test
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  COMPLIANCE_CATEGORIES,
  COMPLIANCE_CHECKS,
  categoryLabelKey,
  checkLabelKey,
  detailMessage,
  localizedLabel,
} from "../compliance-labels.ts";

const en = JSON.parse(readFileSync(new URL("../../../messages/en.json", import.meta.url), "utf8"));
const ja = JSON.parse(readFileSync(new URL("../../../messages/ja.json", import.meta.url), "utf8"));
const get = (obj, key) => key.split(".").reduce((o, k) => o?.[k], obj);

test("every category and check id has an en and a ja label", () => {
  for (const name of COMPLIANCE_CATEGORIES) {
    const key = categoryLabelKey(name);
    assert.equal(typeof get(en.Compliance, key), "string", `en ${key}`);
    assert.equal(typeof get(ja.Compliance, key), "string", `ja ${key}`);
  }
  for (const id of COMPLIANCE_CHECKS) {
    const key = checkLabelKey(id);
    assert.equal(typeof get(en.Compliance, key), "string", `en ${key}`);
    assert.equal(typeof get(ja.Compliance, key), "string", `ja ${key}`);
  }
  assert.equal(categoryLabelKey("something_new"), null);
  assert.equal(checkLabelKey("something_new"), null);
});

test("the Japanese details sentences of compliance.go are recognised, with their numbers", () => {
  assert.deepEqual(detailMessage("2件のCritical脆弱性が未対応"), { key: "detail.unresolvedCritical", values: { count: "2" } });
  assert.deepEqual(detailMessage("3/4 コンポーネント (75%) にPURLがあります"), {
    key: "detail.withPurl",
    values: { n: "3", total: "4", pct: "75" },
  });
  assert.deepEqual(detailMessage("最終更新: 2026-11-16"), { key: "detail.lastUpdated", values: { date: "2026-11-16" } });
  assert.deepEqual(detailMessage("VEXステートメントが登録されていません"), { key: "detail.noVex", values: {} });
  // Unknown text is shown as the API sent it.
  assert.equal(detailMessage("新しい文言"), null);
});

test("every detail key exists in both languages and the ja text round-trips", () => {
  for (const [key, ja_] of Object.entries(ja.Compliance.detail)) {
    assert.equal(typeof en.Compliance.detail[key], "string", `en detail.${key}`);
    // The ja message, with sample values substituted, is recognised as itself.
    const sample = ja_.replace("{count}", "5").replace("{n}", "1").replace("{total}", "2").replace("{pct}", "50").replace("{date}", "2026-01-02");
    assert.equal(detailMessage(sample)?.key, `detail.${key}`, sample);
  }
});

test("checklist / visualization labels follow the locale", () => {
  const item = { label: "Supplier", label_ja: "サプライヤー" };
  assert.equal(localizedLabel(item, "en"), "Supplier");
  assert.equal(localizedLabel(item, "ja"), "サプライヤー");
});

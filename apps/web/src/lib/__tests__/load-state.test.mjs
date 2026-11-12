// M71: which error UI a react-query screen shows (src/lib/load-state.ts).
// Run: pnpm --filter web test
import assert from "node:assert/strict";
import { test } from "node:test";

import { loadErrorState } from "../load-state.ts";

test("a failed first load replaces the content, never an empty / default form", () => {
  assert.equal(loadErrorState(true, false), "full");
});
test("a failed refetch keeps the last good answer under a banner", () => {
  assert.equal(loadErrorState(true, true), "banner");
});
test("no error, no error UI", () => {
  assert.equal(loadErrorState(false, false), "none");
  assert.equal(loadErrorState(false, true), "none");
});

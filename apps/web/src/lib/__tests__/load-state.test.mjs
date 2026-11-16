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

// Project page tab counters (Components / VEX / License / API keys) read
// "(0)" when their own load failed.
import { tabCountState } from "../load-state.ts";

test("a failed first load is 'failed', never a count of 0", () => {
  assert.equal(tabCountState({ isError: true, isPending: false }, false), "failed");
});
test("a failed refetch keeps the last count, marked stale", () => {
  assert.equal(tabCountState({ isError: true, isPending: false }, true), "stale");
});
test("still loading is not 0", () => {
  assert.equal(tabCountState({ isError: false, isPending: true }, false), "loading");
});
test("a loaded list, even an empty one, is a real count", () => {
  assert.equal(tabCountState({ isError: false, isPending: false }, true), "count");
});

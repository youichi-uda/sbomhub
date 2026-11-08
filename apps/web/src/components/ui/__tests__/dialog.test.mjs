// M65 E2E bug 5 — a closed Dialog must keep its DialogTrigger, and the
// trigger must open the dialog.
//
// Before the fix, Dialog returned null while closed (dropping the "Add
// Integration" / "Create API Key" / "Create ticket" trigger buttons) and
// DialogTrigger was a pass-through with no click wiring. Rendered for real
// through react-dom/server (see load-tsx.mjs), not pattern-matched.
//
// Run: node --test src/components/ui/__tests__/dialog.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";

import { React, cnStub, loadTsx, renderToStaticMarkup } from "./load-tsx.mjs";

const h = React.createElement;
const { Dialog, DialogContent, DialogTitle, DialogTrigger } = loadTsx("components/ui/dialog.tsx", {
  "@/lib/utils": cnStub,
});

function tree(props, triggerChild = h("button", { type: "button" }, "Add Integration")) {
  return h(
    Dialog,
    props,
    h(DialogTrigger, { asChild: true }, triggerChild),
    h(DialogContent, null, h(DialogTitle, null, "New integration")),
  );
}

test("closed controlled dialog renders its trigger and no panel", () => {
  const html = renderToStaticMarkup(tree({ open: false, onOpenChange: () => {} }));
  assert.match(html, /<button[^>]*>Add Integration<\/button>/);
  assert.doesNotMatch(html, /role="dialog"/);
  assert.doesNotMatch(html, /New integration/);
});

test("open dialog renders the trigger and the panel", () => {
  const html = renderToStaticMarkup(tree({ open: true, onOpenChange: () => {} }));
  assert.match(html, /Add Integration/);
  assert.match(html, /role="dialog"/);
  assert.match(html, /aria-modal="true"/);
  assert.match(html, /New integration/);
});

test("asChild trigger merges onto the child (no nested button) with dialog ARIA", () => {
  const html = renderToStaticMarkup(tree({ open: false, onOpenChange: () => {} }));
  assert.equal((html.match(/<button/g) || []).length, 1);
  assert.match(html, /aria-haspopup="dialog"/);
  assert.match(html, /aria-expanded="false"/);
});

test("trigger click opens the dialog (calls onOpenChange(true)) after the child's own onClick", () => {
  const calls = [];
  let fired = false;
  // A probe child that "clicks" itself once during render, via the onClick
  // the trigger injected.
  function Probe({ onClick }) {
    if (!fired) {
      fired = true;
      onClick({ defaultPrevented: false });
    }
    return h("button", { type: "button" }, "Add Integration");
  }
  renderToStaticMarkup(
    tree(
      { open: false, onOpenChange: (o) => calls.push(["open", o]) },
      h(Probe, { onClick: () => calls.push(["child"]) }),
    ),
  );
  assert.deepEqual(calls, [["child"], ["open", true]]);
});

test("child onClick that calls preventDefault keeps the dialog closed", () => {
  const calls = [];
  let fired = false;
  function Probe({ onClick }) {
    if (!fired) {
      fired = true;
      onClick({ defaultPrevented: true });
    }
    return h("button", { type: "button" }, "x");
  }
  renderToStaticMarkup(tree({ open: false, onOpenChange: (o) => calls.push(o) }, h(Probe)));
  assert.deepEqual(calls, []);
});

test("uncontrolled dialog honours defaultOpen", () => {
  assert.match(renderToStaticMarkup(tree({ defaultOpen: true })), /role="dialog"/);
  assert.doesNotMatch(renderToStaticMarkup(tree({})), /role="dialog"/);
});

test("DialogContent / DialogTrigger outside a Dialog fail loudly", () => {
  assert.throws(() => renderToStaticMarkup(h(DialogContent, null, "x")), /within Dialog/);
  assert.throws(() => renderToStaticMarkup(h(DialogTrigger, null, "x")), /within Dialog/);
});

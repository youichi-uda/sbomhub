// pnpm-native-probe.mjs — F161 hardening of the M10-4 #72 pnpm 10 lifecycle
// skip probe. pnpm 10.34.3 auto-skips lifecycle scripts for several native-
// binding packages and only logs an informational warning; M8 F154 verified
// the first-run was OK, but a future bump could land a regression where the
// native binding is missing or silently downgraded to a JS/WASM fallback
// (the original require()-only probe could not see the latter case).
//
// This script exercises the native code path of each package and fails loudly
// if the binding is absent or replaced by a software fallback. Run via
// .github/workflows/frontend-ci.yml after `pnpm install --frozen-lockfile`.
//
// Why each probe is shaped the way it is:
//   * sharp                 — read sharp.versions.vips (only populated when
//                             the native libvips addon is loaded; the wasm
//                             fallback leaves it undefined). Then encode a
//                             tiny 8×8 PNG to ensure the addon actually runs.
//   * @swc/core             — call transformSync on a TypeScript snippet. The
//                             addon is required for transformSync; if the
//                             .node binding is missing, transformSync throws.
//   * @parcel/watcher       — subscribe/unsubscribe against a tempdir; the
//                             N-API .node binding is the only implementation
//                             (no JS fallback).
//   * unrs-resolver         — instantiate ResolverFactory and resolve `fs`
//                             synchronously. The Rust napi-rs binding is the
//                             only implementation.
//
// If a package needs to be removed from this script (e.g. it's no longer a
// transitive dep), update both this file AND the root package.json
// `//pnpm-skip-monitor` note in lockstep.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(import.meta.url);
const require = createRequire(here);

const fail = [];
const log = (m) => console.log("[ok] " + m);
const err = (m) => {
  console.error("[FAIL] " + m);
  fail.push(m);
};

// --- sharp ----------------------------------------------------------------
try {
  const sharp = require("sharp");
  const ver = sharp.versions || {};
  if (!ver.vips) {
    err(
      "sharp: native libvips not loaded (versions=" +
        JSON.stringify(ver) +
        ") — wasm fallback?",
    );
  } else {
    const buf = await sharp({
      create: {
        width: 8,
        height: 8,
        channels: 3,
        background: { r: 1, g: 2, b: 3 },
      },
    })
      .png()
      .toBuffer();
    if (!buf || buf.length < 8) {
      err(
        "sharp: native encode produced " +
          (buf && buf.length) +
          " bytes (expected a valid PNG)",
      );
    } else {
      log("sharp libvips=" + ver.vips + " (encoded " + buf.length + " B PNG)");
    }
  }
} catch (e) {
  err("sharp: " + (e && e.message ? e.message : e));
}

// --- @swc/core ------------------------------------------------------------
try {
  const swc = require("@swc/core");
  const out = swc.transformSync("const x: number = 1;", {
    jsc: { parser: { syntax: "typescript" } },
  });
  if (!out || typeof out.code !== "string" || out.code.length < 1) {
    err("@swc/core: transformSync returned empty code");
  } else {
    log("@swc/core transformSync ok (" + out.code.length + " chars)");
  }
} catch (e) {
  err("@swc/core: " + (e && e.message ? e.message : e));
}

// --- @parcel/watcher ------------------------------------------------------
try {
  const watcher = require("@parcel/watcher");
  const dir = mkdtempSync(join(tmpdir(), "parcel-watcher-probe-"));
  const sub = await watcher.subscribe(dir, () => {});
  await sub.unsubscribe();
  rmSync(dir, { recursive: true, force: true });
  log("@parcel/watcher subscribe/unsubscribe ok");
} catch (e) {
  err("@parcel/watcher: " + (e && e.message ? e.message : e));
}

// --- unrs-resolver --------------------------------------------------------
try {
  const u = require("unrs-resolver");
  const ResolverFactory =
    u.ResolverFactory || (u.default && u.default.ResolverFactory);
  if (!ResolverFactory) {
    err(
      "unrs-resolver: ResolverFactory export missing (binding probably did not load)",
    );
  } else {
    const r = new ResolverFactory({ extensions: [".js", ".json"] });
    // Resolve a Node built-in from this script's directory. unrs-resolver
    // surfaces built-ins via the `path` field; if the binding is dead we'd
    // never get that far.
    const res = r.sync(join(here, ".."), "fs");
    if (!res || (!res.path && !res.error)) {
      err(
        "unrs-resolver: sync({base, request:fs}) returned " +
          JSON.stringify(res),
      );
    } else if (res.error) {
      // Built-ins may surface as an error rather than a path. As long as
      // the call returned a structured result, the binding is alive.
      log("unrs-resolver sync('fs') reached napi (" + res.error + ")");
    } else {
      log("unrs-resolver sync('fs') -> " + basename(res.path));
    }
  }
} catch (e) {
  err("unrs-resolver: " + (e && e.message ? e.message : e));
}

if (fail.length) {
  console.error("---");
  console.error(
    "F161 probe: " + fail.length + " native-binding regression(s).",
  );
  console.error(
    "See package.json `//pnpm-skip-monitor` comment + docs/ci-inventory.md §4.3",
  );
  process.exit(1);
}

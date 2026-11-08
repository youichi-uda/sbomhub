// Loads a .tsx component module under node:test so its React output can be
// rendered (react-dom/server) instead of only pattern-matched as source.
//
// apps/web ships no component test runner and node's type stripping does not
// understand JSX, so the module is transpiled with the workspace TypeScript
// (CommonJS + react-jsx) and evaluated with a `require` that
//   - resolves bare specifiers (react, lucide-react, ...) from apps/web, and
//   - maps the "@/" alias through `aliases` (path under src/ -> module).
//
// Test helper only; not imported by application code.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const webRoot = join(here, "..", "..", "..", "..");
const requireFromWeb = createRequire(join(webRoot, "package.json"));
const ts = requireFromWeb("typescript");

/**
 * @param {string} srcRelative path under apps/web/src, e.g. "components/ui/dialog.tsx"
 * @param {Record<string, unknown>} aliases "@/x" specifier -> module object
 */
export function loadTsx(srcRelative, aliases = {}) {
  const file = join(webRoot, "src", srcRelative);
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      jsx: ts.JsxEmit.ReactJSX,
      esModuleInterop: true,
    },
    fileName: file,
  });
  const mod = { exports: {} };
  const req = (spec) => {
    if (spec in aliases) return aliases[spec];
    if (spec.startsWith("@/")) throw new Error(`load-tsx: no alias given for ${spec}`);
    return requireFromWeb(spec);
  };
  new Function("require", "module", "exports", outputText)(req, mod, mod.exports);
  return mod.exports;
}

export const React = requireFromWeb("react");
export const { renderToStaticMarkup } = requireFromWeb("react-dom/server");
export const cnStub = { cn: (...xs) => xs.filter(Boolean).join(" ") };

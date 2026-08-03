import { test, expect } from '@playwright/test';
import * as ts from 'typescript';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

/**
 * Meta-gate: a conditional skip must never silently disarm a CI gate.
 *
 * THE DEFECT THIS EXISTS FOR
 * --------------------------
 * Playwright evaluates a `test.skip(condition, description)` written at
 * FILE scope or directly inside a `test.describe` callback at COLLECTION
 * time, and skipping the group takes its `beforeAll` with it. So this,
 * which reads like "CI must not skip":
 *
 *     test.describe('gate', () => {
 *         test.beforeAll(() => {
 *             if (!HAS_TOOL && process.env.CI) throw new Error('required in CI');
 *         });
 *         test.skip(!HAS_TOOL, 'tool missing');   // wins, at collection time
 *         test('...', ...);
 *     });
 *
 * is a dead guard: the `throw` is unreachable in exactly the situation it
 * was written for. A CI runner missing the tool reports "N skipped" and a
 * GREEN job — a gate that certifies nothing. That is not hypothetical:
 * `report-unmeasured-pdf.spec.ts` shipped with that shape and was fixed to
 * `!HAS_PDFTOTEXT && !process.env.CI`. Nothing but three source comments
 * stopped the `&& !process.env.CI` from being "simplified" back out.
 * This file is that missing enforcement.
 *
 * THE RULE
 * --------
 * Every GROUP-WIDE conditional skip — a `test.skip` / `test.fixme` call
 * carrying a condition, written at file scope, directly in a
 * `test.describe` body, or inside a `test.beforeAll` — must be provably
 * inert under CI. "Provably" is structural, not semantic: the condition
 * must be a top-level `&&` chain with one conjunct that is literally
 *
 *     !process.env.CI            (or `process.env.CI === undefined`
 *                                 / `process.env.CI == null`)
 *
 * because `A && B && !process.env.CI` cannot be true when CI is set, no
 * matter what A and B are. One hop of file-scope `const` resolution is
 * performed, so `const LOCAL_ONLY = !HAS_TOOL && !process.env.CI;` +
 * `test.skip(LOCAL_ONLY, ...)` also passes — unless the name is declared
 * more than once in the file, in which case shadowing makes the hop
 * unsound and the site is treated as unproven.
 *
 * WHERE THE LINE IS DRAWN — and why
 * ---------------------------------
 * "CI must not skip this"  → conditional skips that take a WHOLE GROUP
 *   with them: file scope, describe scope, `beforeAll`. These are
 *   environment-conditional gates (an external binary, a fixture, a
 *   feature flag). Their whole purpose is to be a gate, and a gate that
 *   evaporates when its precondition is missing is worse than no gate: it
 *   is a green tick that means nothing. Enforced here.
 *
 *   File and describe scope are the sharp case, because they are
 *   evaluated at COLLECTION time and therefore also delete the group's
 *   `beforeAll`. `beforeAll` scope is included because the blast radius
 *   is the same group even though the timing is not — it just cannot
 *   make a preceding `throw` unreachable.
 *
 * "CI may skip this"       → everything else, deliberately NOT gated:
 *   - Per-test runtime skips: inside a test body, a `test.step`, or a
 *     `beforeEach` (`test.skip()`, `test.skip(cond, msg)` after an
 *     `await`). They disable one test, not the gate, and they are the
 *     repo's "soft gate" idiom (48 sites) for seed-dependent assertions.
 *     A soft gate can make a test vacuous, but that is a different bug
 *     class from a group-wide gate switching itself off.
 *   - Declaration-form `test.skip('name', fn)` (2 sites in
 *     error-handling.spec.ts). Statically and unconditionally off, with a
 *     written hand-off. It never pretends to be conditional, so there is
 *     nothing to silently flip.
 *   - `test.describe.skip(...)` / `test.describe.fixme(...)` (0 sites).
 *     Same reasoning: unconditional and self-announcing in the source.
 *
 * ESCAPE HATCH
 * ------------
 * A collection-time conditional skip that genuinely may skip under CI must
 * say so out loud: put `// ci-skip-ok: <reason>` on or above the call. The
 * marker requires a non-empty reason and shows up in review — which is the
 * point. It is an explicit decision, not a default.
 *
 * WHAT THIS DOES NOT CATCH (honest limitations)
 * ---------------------------------------------
 *   - Skips configured outside the spec source: `testIgnore` / `grep` /
 *     project filters in playwright.config.ts, or a `--grep-invert` in a
 *     workflow. A whole spec can be excluded from a run without any
 *     `test.skip` existing.
 *   - Specs outside `apps/web/e2e/**` and non-Playwright gates that
 *     self-disable (Go `t.Skip`, a shell step that `exit 0`s when a tool
 *     is missing, a workflow step with `continue-on-error`).
 *   - A renamed import. The matcher is syntactic on the literal
 *     `test.` prefix, so `import { test as t }` + `t.skip(...)` is
 *     invisible to it. Every spec in this directory imports `test` under
 *     its own name; a file that does not is a visible deviation from the
 *     convention, which is the (weak) thing standing in for a check here.
 *   - A runtime soft gate that makes a test vacuous rather than skipped
 *     (e.g. `if (!found) return;`), and per-test skips of any shape.
 *   - `test.beforeEach(() => test.skip(!HAS_TOOL, ...))`. Formally this
 *     is a per-test decision — it re-runs for every test and may consult
 *     that test's fixtures — which is why it sits on the runtime side of
 *     the line. But when the condition is a module-level constant the
 *     effect is the same group-wide switch-off, and the gate will not say
 *     so. Gating it would instead force `&& !process.env.CI` onto the
 *     legitimate `test.skip(await page.evaluate(...))` idiom, where that
 *     suffix would be actively wrong. Prefer `beforeAll` (which IS gated)
 *     for a group-level precondition; that is the shape this file wants
 *     you to reach for.
 *   - Semantic CI-safety that is not syntactically visible — a condition
 *     computed by a helper function, or through two hops of `const`, is
 *     reported as a violation (fail-closed). Fix by inlining the
 *     `&& !process.env.CI` or by adding the `ci-skip-ok` marker. The same
 *     fail-closed direction applies to a skip written inside a plain
 *     helper closure declared at describe scope: it is attributed to the
 *     describe even though it only runs when the helper is called.
 *
 * NON-VACUITY
 * -----------
 * `analyzer detects the hole it exists for` below runs the analyzer over
 * embedded holed/guarded fixtures on every CI run, so this file cannot
 * degrade into a scan that finds nothing and passes. Measured externally
 * too: a temp spec carrying the holed shape was dropped into `e2e/` and
 * turned this suite red before being removed.
 */

// ---------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------

interface SkipSite {
    file: string;
    line: number;
    callee: string;
    /**
     * `conditional` — `test.skip(cond)` / `test.skip(cond, desc)`.
     * `declaration` — `test.skip('name', fn)`, a statically-off test.
     * `noarg`       — `test.skip()`, only meaningful at runtime.
     */
    form: 'conditional' | 'declaration' | 'noarg';
    /**
     * Where the call sits. `file` / `describe` / `beforeAll` disable a
     * WHOLE GROUP; `test` / `beforeEach` / `step` disable one test.
     */
    scope: 'file' | 'describe' | 'beforeAll' | 'test' | 'eachHook' | 'step';
    condition: string;
    ciNeutral: boolean;
    allowMarker: boolean;
    /** The enclosing describe has a `beforeAll` that can `throw`. */
    guardedByThrowingBeforeAll: boolean;
}

/** Scopes at which one skip call takes an entire group with it. */
const GROUP_SCOPES: ReadonlySet<SkipSite['scope']> = new Set([
    'file',
    'describe',
    'beforeAll',
] as const);

const CALLEE_SKIP = /^test\.(skip|fixme)$/;
const CALLEE_DESCRIBE = /^(test\.describe(\.(only|serial|parallel|skip|fixme))*|describe)$/;
const CALLEE_TEST = /^test(\.(only|skip|fixme|fail|slow))?$/;
const CALLEE_ALL_HOOK = /^test\.(beforeAll|afterAll)$/;
const CALLEE_EACH_HOOK = /^test\.(beforeEach|afterEach)$/;
const ALLOW_MARKER = /ci-skip-ok:\s*\S/;

/** Strip the wrappers that change an expression's text but not its value. */
function unwrap(node: ts.Expression): ts.Expression {
    let cur = node;
    for (;;) {
        if (ts.isParenthesizedExpression(cur)) cur = cur.expression;
        else if (ts.isNonNullExpression(cur)) cur = cur.expression;
        else if (ts.isAsExpression(cur)) cur = cur.expression;
        else if (ts.isSatisfiesExpression(cur)) cur = cur.expression;
        else return cur;
    }
}

/**
 * Dotted name of a call target — `test.skip`, `test.describe.serial` — or
 * null when it is not a plain identifier chain.
 *
 * Built structurally instead of from `getText()`: source text carries the
 * punctuation and whitespace an author happened to write, so `(test.skip)`
 * and `test . skip` both read as "not test.skip" and slipped past the
 * matcher entirely — the site was not even recorded. (Review finding,
 * High; pinned by FIXTURE_PARENTHESISED_CALLEE.)
 */
function calleeName(expr: ts.Expression): string | null {
    const cur = unwrap(expr);
    if (ts.isIdentifier(cur)) return cur.text;
    if (ts.isPropertyAccessExpression(cur)) {
        const left = calleeName(cur.expression);
        return left === null ? null : `${left}.${cur.name.text}`;
    }
    // `test['skip']` is the same call as `test.skip`. (Review finding, High.)
    if (ts.isElementAccessExpression(cur)) {
        const key = unwrap(cur.argumentExpression);
        if (ts.isStringLiteral(key) || ts.isNoSubstitutionTemplateLiteral(key)) {
            const left = calleeName(cur.expression);
            return left === null ? null : `${left}.${key.text}`;
        }
    }
    return null;
}

/** Flatten a top-level `&&` chain into its conjuncts. */
function conjuncts(node: ts.Expression, out: ts.Expression[] = []): ts.Expression[] {
    const cur = unwrap(node);
    if (
        ts.isBinaryExpression(cur) &&
        cur.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
    ) {
        conjuncts(cur.left, out);
        conjuncts(cur.right, out);
    } else {
        out.push(cur);
    }
    return out;
}

function isProcessEnvCI(node: ts.Expression): boolean {
    const cur = unwrap(node);
    return (
        ts.isPropertyAccessExpression(cur) &&
        cur.name.text === 'CI' &&
        ts.isPropertyAccessExpression(cur.expression) &&
        cur.expression.name.text === 'env' &&
        ts.isIdentifier(cur.expression.expression) &&
        cur.expression.expression.text === 'process'
    );
}

/** Globals the CI-neutrality proof reads by name. */
const PROOF_GLOBALS = ['process', 'undefined'] as const;

/**
 * `!process.env.CI`, `process.env.CI === undefined`, `process.env.CI == null`.
 *
 * `globalsIntact` is false when the file binds `process` or `undefined`
 * itself. `const process = { env: { CI: undefined } }` makes
 * `!process.env.CI` say nothing about the environment, and
 * `const undefined = process.env.CI` makes `process.env.CI === undefined`
 * true precisely when CI is set. Either way NOTHING in that file counts
 * as CI-neutral. (Review findings, High.)
 */
function assertsCiIsOff(node: ts.Expression, globalsIntact = true): boolean {
    if (!globalsIntact) return false;
    const cur = unwrap(node);
    if (
        ts.isPrefixUnaryExpression(cur) &&
        cur.operator === ts.SyntaxKind.ExclamationToken &&
        isProcessEnvCI(cur.operand)
    ) {
        return true;
    }
    if (ts.isBinaryExpression(cur) && isProcessEnvCI(cur.left)) {
        const rhs = unwrap(cur.right).getText();
        const op = cur.operatorToken.kind;
        const isEq =
            op === ts.SyntaxKind.EqualsEqualsToken ||
            op === ts.SyntaxKind.EqualsEqualsEqualsToken;
        return isEq && (rhs === 'undefined' || rhs === 'null');
    }
    return false;
}

/** The literal key of a `x['k']` access, or null. */
function literalKey(node: ts.Expression): string | null {
    const k = unwrap(node);
    if (ts.isStringLiteral(k) || ts.isNoSubstitutionTemplateLiteral(k)) return k.text;
    return null;
}

/** True when `node` is `process.env` — dotted or bracketed. */
function isProcessEnv(node: ts.Node): boolean {
    if (!ts.isExpression(node)) return false;
    const cur = unwrap(node);
    const isProcess = (e: ts.Expression): boolean => {
        const c = unwrap(e);
        return ts.isIdentifier(c) && c.text === 'process';
    };
    if (ts.isPropertyAccessExpression(cur)) {
        return cur.name.text === 'env' && isProcess(cur.expression);
    }
    if (ts.isElementAccessExpression(cur)) {
        return literalKey(cur.argumentExpression) === 'env' && isProcess(cur.expression);
    }
    return false;
}

/** Climb out of any parentheses, returning [outermost child, its parent]. */
function skipParens(node: ts.Node): [ts.Node, ts.Node | undefined] {
    let child = node;
    let parent = node.parent as ts.Node | undefined;
    while (parent && ts.isParenthesizedExpression(parent)) {
        child = parent;
        parent = parent.parent;
    }
    return [child, parent];
}

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
    return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

/**
 * True when nothing in the file can have changed `process.env`.
 *
 * Checking only for a rebound `process` identifier was not enough: a bare
 * `delete process.env.CI;` at file scope makes `!process.env.CI` true
 * under CI at collection time while the binding check still says the
 * global is intact. Nor is it enough to look for writes spelled through
 * `process.env` directly — `const env = process.env; env.CI = '';` is the
 * same mutation one alias away. (Review findings, High.)
 *
 * So the rule is inverted and deliberately over-approximating: the ONLY
 * use of `process.env` that leaves it pristine is reading a single member
 * off it (`process.env.CI`, `process.env['CI']`). Every other appearance
 * — aliasing it, spreading it, destructuring it, passing it to a call
 * (`Object.assign(process.env, …)`), assigning to a member, deleting a
 * member — marks the file as one where the CI proof means nothing.
 * Nothing in this suite does any of that, so the over-approximation
 * costs nothing here.
 */
function envIsPristine(sf: ts.SourceFile): boolean {
    let mutated = false;
    const visit = (n: ts.Node): void => {
        if (mutated) return;
        if (isProcessEnv(n)) {
            const [child, parent] = skipParens(n);
            const isMemberRead =
                parent !== undefined &&
                (ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) &&
                parent.expression === child;
            if (!isMemberRead) {
                mutated = true;
                return;
            }
            const [accessChild, grand] = skipParens(parent);
            if (grand !== undefined) {
                if (ts.isDeleteExpression(grand)) {
                    mutated = true;
                    return;
                }
                if (
                    ts.isBinaryExpression(grand) &&
                    isAssignmentOperator(grand.operatorToken.kind) &&
                    grand.left === accessChild
                ) {
                    mutated = true;
                    return;
                }
                if (
                    (ts.isPrefixUnaryExpression(grand) || ts.isPostfixUnaryExpression(grand)) &&
                    (grand.operator === ts.SyntaxKind.PlusPlusToken ||
                        grand.operator === ts.SyntaxKind.MinusMinusToken)
                ) {
                    mutated = true;
                    return;
                }
            }
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    return !mutated;
}

/** Every name the file binds, however it binds it, with a count. */
function boundNames(sf: ts.SourceFile): Map<string, number> {
    const counts = new Map<string, number>();
    const bump = (name: string): void => void counts.set(name, (counts.get(name) ?? 0) + 1);
    const count = (n: ts.Node): void => {
        // Every construct that can introduce a binding. Counting only
        // `const`/`let`/`var` missed a callback PARAMETER, and later a
        // named FUNCTION EXPRESSION, shadowing a file-scope constant.
        // (Review findings, High.)
        if (
            (ts.isVariableDeclaration(n) ||
                ts.isParameter(n) ||
                ts.isBindingElement(n) ||
                ts.isImportSpecifier(n) ||
                ts.isImportClause(n) ||
                ts.isNamespaceImport(n) ||
                ts.isFunctionDeclaration(n) ||
                ts.isFunctionExpression(n) ||
                ts.isClassDeclaration(n) ||
                ts.isClassExpression(n) ||
                ts.isEnumDeclaration(n) ||
                ts.isModuleDeclaration(n)) &&
            n.name &&
            ts.isIdentifier(n.name)
        ) {
            bump(n.name.text);
        }
        ts.forEachChild(n, count);
    };
    count(sf);
    return counts;
}

/**
 * Collect file-scope `const NAME = <expr>;` initialisers for one-hop
 * resolution.
 *
 * Two things disqualify a name:
 *
 *   - It is bound more than ONCE anywhere in the file (any scope, any
 *     construct). An inner `const SKIP = !HAS_TOOL;` inside the describe,
 *     or a callback parameter of the same name, shadows a file-scope
 *     `const SKIP = !HAS_TOOL && !process.env.CI;`, and resolving to the
 *     outer one would clear a skip that is in fact live under CI.
 *   - It is not `const`. `let LOCAL_ONLY = !process.env.CI;` followed by
 *     `LOCAL_ONLY = true;` has a CI-safe INITIALISER and a live VALUE.
 *     (Review finding, High.)
 *
 * Disqualified means the site is judged not-proven, i.e. a violation —
 * fail-closed.
 */
function fileScopeConsts(sf: ts.SourceFile): Map<string, ts.Expression> {
    const declaredAnywhere = boundNames(sf);

    const map = new Map<string, ts.Expression>();
    for (const stmt of sf.statements) {
        if (!ts.isVariableStatement(stmt)) continue;
        // `let` / `var` can be reassigned after the initialiser is read.
        if ((stmt.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
        for (const decl of stmt.declarationList.declarations) {
            if (
                ts.isIdentifier(decl.name) &&
                decl.initializer &&
                declaredAnywhere.get(decl.name.text) === 1
            ) {
                map.set(decl.name.text, decl.initializer);
            }
        }
    }
    return map;
}

function isCiNeutral(
    cond: ts.Expression,
    consts: Map<string, ts.Expression>,
    globalsIntact: boolean,
): boolean {
    const off = (e: ts.Expression): boolean => assertsCiIsOff(e, globalsIntact);
    if (conjuncts(cond).some(off)) return true;
    const cur = unwrap(cond);
    if (ts.isIdentifier(cur)) {
        const init = consts.get(cur.text);
        // One hop only, and never back into an identifier (no cycles).
        if (init && conjuncts(init).some(off)) return true;
    }
    return false;
}

/**
 * True when a `ci-skip-ok:` marker appears in a COMMENT attached to the
 * statement — never merely somewhere in its source text.
 *
 * Scanning the raw statement text instead let the marker be smuggled into
 * the skip's own description string:
 *
 *     test.skip(!HAS_TOOL, 'ci-skip-ok: tool missing');
 *
 * which reads to a human as an ordinary skip message and silently bought
 * the exemption. Found by review; pinned by FIXTURE_MARKER_IN_STRING.
 */
function hasAllowMarker(text: string, stmt: ts.Node): boolean {
    const ranges = [
        ...(ts.getLeadingCommentRanges(text, stmt.getFullStart()) ?? []),
        ...(ts.getTrailingCommentRanges(text, stmt.getEnd()) ?? []),
    ];
    return ranges.some((r) => ALLOW_MARKER.test(text.slice(r.pos, r.end)));
}

function bodyCanThrow(fn: ts.Node): boolean {
    let found = false;
    const visit = (n: ts.Node): void => {
        if (found) return;
        if (ts.isThrowStatement(n)) found = true;
        else ts.forEachChild(n, visit);
    };
    ts.forEachChild(fn, visit);
    return found;
}

export function analyzeSource(fileName: string, text: string): SkipSite[] {
    // Parse with the grammar the extension implies: `<T>` is a type
    // assertion in .ts and a JSX element in .tsx, so the wrong ScriptKind
    // yields an error-recovered AST in which a skip can simply vanish.
    // (Review finding, High.) `foo.spec.js` also has to be JS, not TS.
    const kind = fileName.endsWith('x')
        ? /\.[cm]?jsx$/.test(fileName)
            ? ts.ScriptKind.JSX
            : ts.ScriptKind.TSX
        : /\.[cm]?js$/.test(fileName)
          ? ts.ScriptKind.JS
          : ts.ScriptKind.TS;
    const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, kind);
    const consts = fileScopeConsts(sf);
    // If the file rebinds a global the proof reads by name, the proof is
    // meaningless there and nothing in the file can be judged CI-neutral.
    const bound = boundNames(sf);
    const globalsIntact = !PROOF_GLOBALS.some((g) => bound.has(g)) && envIsPristine(sf);
    const sites: SkipSite[] = [];
    // Enclosing test-construct scopes, innermost last.
    const stack: SkipSite['scope'][] = [];
    // Enclosing `test.describe` callbacks, for the beforeAll-throws diagnosis.
    const describeStack: ts.Node[] = [];

    const describeHasThrowingBeforeAll = (describeBody: ts.Node): boolean => {
        let found = false;
        const visit = (n: ts.Node): void => {
            if (found) return;
            if (
                ts.isCallExpression(n) &&
                calleeName(n.expression) === 'test.beforeAll' &&
                n.arguments.length > 0 &&
                bodyCanThrow(n.arguments[0])
            ) {
                found = true;
                return;
            }
            ts.forEachChild(n, visit);
        };
        ts.forEachChild(describeBody, visit);
        return found;
    };

    const visit = (node: ts.Node): void => {
        let pushed: SkipSite['scope'] | null = null;
        let pushedDescribe = false;

        if (ts.isCallExpression(node)) {
            const callee = calleeName(node.expression) ?? '';
            const args = node.arguments;
            const hasCallback = args.length >= 1 && args.some((a) => ts.isArrowFunction(a) || ts.isFunctionExpression(a));

            if (CALLEE_DESCRIBE.test(callee) && hasCallback) {
                pushed = 'describe';
                pushedDescribe = true;
            } else if (CALLEE_ALL_HOOK.test(callee)) {
                pushed = 'beforeAll';
            } else if (CALLEE_EACH_HOOK.test(callee)) {
                pushed = 'eachHook';
            } else if (callee === 'test.step') {
                pushed = 'step';
            } else if (
                CALLEE_TEST.test(callee) &&
                args.length >= 2 &&
                (ts.isStringLiteral(args[0]) ||
                    ts.isNoSubstitutionTemplateLiteral(args[0]) ||
                    ts.isTemplateExpression(args[0]))
            ) {
                pushed = 'test';
            }

            if (CALLEE_SKIP.test(callee)) {
                const isDeclaration =
                    args.length >= 2 &&
                    (ts.isStringLiteral(args[0]) ||
                        ts.isNoSubstitutionTemplateLiteral(args[0]) ||
                        ts.isTemplateExpression(args[0])) &&
                    (ts.isArrowFunction(args[1]) || ts.isFunctionExpression(args[1]));
                const form: SkipSite['form'] =
                    args.length === 0 ? 'noarg' : isDeclaration ? 'declaration' : 'conditional';
                const scope = stack.length ? stack[stack.length - 1] : 'file';

                let stmt: ts.Node = node;
                while (stmt.parent && !ts.isStatement(stmt)) stmt = stmt.parent;

                sites.push({
                    file: fileName,
                    line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
                    callee,
                    form,
                    scope,
                    condition: form === 'conditional' ? args[0].getText(sf).replace(/\s+/g, ' ') : '',
                    ciNeutral:
                        form === 'conditional'
                            ? isCiNeutral(args[0], consts, globalsIntact)
                            : true,
                    allowMarker: hasAllowMarker(text, stmt),
                    guardedByThrowingBeforeAll:
                        describeStack.length > 0 &&
                        describeHasThrowingBeforeAll(describeStack[describeStack.length - 1]),
                });
            }
        }

        // Only the CALLBACK argument of `test(...)` / `test.describe(...)`
        // / a hook is inside that construct. Its other arguments — the
        // title above all — are evaluated eagerly, at collection time, in
        // the ENCLOSING scope. Pushing the scope over the whole call let a
        // skip hidden in a test's title expression be filed as a per-test
        // runtime skip and pass. (Review finding, High.)
        if (pushed && ts.isCallExpression(node)) {
            if (pushedDescribe) describeStack.push(node);
            visit(node.expression);
            for (const arg of node.arguments) {
                const isCallback = ts.isArrowFunction(arg) || ts.isFunctionExpression(arg);
                if (isCallback) {
                    stack.push(pushed);
                    visit(arg);
                    stack.pop();
                } else {
                    visit(arg);
                }
            }
            if (pushedDescribe) describeStack.pop();
            return;
        }

        ts.forEachChild(node, visit);
    };

    visit(sf);
    return sites;
}

/** Group-wide conditional skips that are not provably inert under CI. */
export function violations(sites: SkipSite[]): SkipSite[] {
    return sites.filter(
        (s) =>
            s.form === 'conditional' &&
            GROUP_SCOPES.has(s.scope) &&
            !s.ciNeutral &&
            !s.allowMarker,
    );
}

function describeViolation(v: SkipSite): string {
    const collection = v.scope === 'file' || v.scope === 'describe';
    const when = collection ? 'evaluated at COLLECTION time' : 'runs before every test in the group';
    const why =
        collection && v.guardedByThrowingBeforeAll
            ? 'the enclosing describe has a `beforeAll` that throws — a collection-time ' +
              'skip takes that beforeAll with it, so the guard is DEAD CODE'
            : 'this disables the WHOLE GROUP under CI with no loud failure, which turns ' +
              'the gate into a green tick that certifies nothing';
    return (
        `${v.file}:${v.line}  ${v.callee}(${v.condition})\n` +
        `    scope=${v.scope} (${when})\n` +
        `    ${why}.\n` +
        '    Fix: append `&& !process.env.CI` to the condition, or, if skipping under\n' +
        '    CI really is intended, add a `// ci-skip-ok: <reason>` comment.'
    );
}

// ---------------------------------------------------------------------
// Fixtures — these keep the gate honest (see NON-VACUITY above)
// ---------------------------------------------------------------------

/** The exact shape that shipped broken: CI guard rendered unreachable. */
const FIXTURE_HOLED = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.beforeAll(() => {
        if (!HAS_TOOL && process.env.CI) throw new Error('required in CI');
    });
    test.skip(!HAS_TOOL, 'tool missing');
    test('asserts something', async () => {});
});
`;

/** The fixed shape, as it stands in report-unmeasured-pdf.spec.ts. */
const FIXTURE_GUARDED = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
    test.beforeAll(() => {
        if (!HAS_TOOL) throw new Error('required in CI');
    });
    test('asserts something', async () => {});
});
`;

/** One-hop const resolution. */
const FIXTURE_CONST_HOP = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const LOCAL_ONLY = !HAS_TOOL && !process.env.CI;
test.describe('gate', () => {
    test.skip(LOCAL_ONLY, 'tool missing');
    test('asserts something', async () => {});
});
`;

/** Runtime soft gates: allowed, they cannot disarm a beforeAll. */
const FIXTURE_RUNTIME_SOFT_GATE = `
import { test } from '@playwright/test';
test.describe('soft gate', () => {
    test.beforeAll(() => { throw new Error('loud'); });
    test('a', async ({ page }) => {
        const rows = 0;
        if (rows === 0) { test.skip(true, 'seed prerequisite unmet'); }
        test.skip();
    });
    test.skip('statically off, documented hand-off', async () => {});
});
`;

/** Referencing CI is not enough — this one skips *because* of CI. */
const FIXTURE_INVERTED = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL || !!process.env.CI, 'tool missing');
    test('asserts something', async () => {});
});
`;

/** A `beforeAll` skip disables the whole group too, just later. */
const FIXTURE_BEFORE_ALL_GROUP_SKIP = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.beforeAll(() => {
        test.skip(!HAS_TOOL, 'tool missing');
    });
    test('asserts something', async () => {});
});
`;

/** A shadowed name must not be resolved to the outer, CI-guarded one. */
const FIXTURE_SHADOWED_CONST = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const SKIP = !HAS_TOOL && !process.env.CI;
test.describe('gate', () => {
    const SKIP = !HAS_TOOL;
    test.skip(SKIP, 'tool missing');
    test('asserts something', async () => {});
});
`;

/** A per-test `beforeEach` skip is the ordinary runtime idiom. */
const FIXTURE_BEFORE_EACH = `
import { test } from '@playwright/test';
test.describe('soft', () => {
    test.beforeEach(async ({ page }) => {
        test.skip(await page.evaluate(() => false), 'not applicable here');
    });
    test('a', async () => {});
});
`;

/** The escape hatch, used deliberately. */
const FIXTURE_MARKER = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    // ci-skip-ok: covered by the API-side integration suite instead.
    test.skip(!HAS_TOOL, 'tool missing');
    test('asserts something', async () => {});
});
`;

/** Same, as a trailing comment. */
const FIXTURE_MARKER_TRAILING = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL, 'tool missing'); // ci-skip-ok: covered elsewhere
    test('asserts something', async () => {});
});
`;

/** Punctuation that changes the call's TEXT but not what it calls. */
const FIXTURE_PARENTHESISED_CALLEE = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    (test.skip)(!HAS_TOOL, 'tool missing');
});
`;

/** A callback PARAMETER shadowing the file-scope, CI-guarded constant. */
const FIXTURE_PARAM_SHADOW = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const LOCAL_ONLY = !HAS_TOOL && !process.env.CI;
test.describe('gate', (LOCAL_ONLY = !HAS_TOOL) => {
    test.skip(LOCAL_ONLY, 'tool missing');
});
`;

/** `test['skip']` is the same call, spelled differently. */
const FIXTURE_ELEMENT_ACCESS_CALLEE = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test['skip'](!HAS_TOOL, 'tool missing');
});
`;

/** A CI-safe initialiser is not a CI-safe value when the binding is `let`. */
const FIXTURE_MUTABLE_BINDING = `
import { test } from '@playwright/test';
let LOCAL_ONLY = !process.env.CI;
LOCAL_ONLY = true;
test.describe('gate', () => {
    test.skip(LOCAL_ONLY, 'tool missing');
});
`;

/** A named function expression binds its own name inside itself. */
const FIXTURE_FUNCTION_EXPR_SHADOW = `
import { test } from '@playwright/test';
const LOCAL_ONLY = !process.env.CI;
test.describe('gate', function LOCAL_ONLY() {
    test.skip(LOCAL_ONLY, 'tool missing');
});
`;

/** A locally-bound `process` proves nothing about the environment. */
const FIXTURE_SHADOWED_PROCESS = `
import { test } from '@playwright/test';
const process = { env: { CI: undefined } };
test.describe('gate', () => {
    test.skip(true && !process.env.CI, 'tool missing');
});
`;

/** A locally-bound `undefined` inverts the equality proof. */
const FIXTURE_SHADOWED_UNDEFINED = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const undefined = process.env.CI;
test.describe('gate', () => {
    test.skip(!HAS_TOOL && process.env.CI === undefined, 'tool missing');
});
`;

/** Mutating the environment makes the proof false without rebinding anything. */
const FIXTURE_DELETED_ENV_CI = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
delete process.env.CI;
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
});
`;

/** Assignment counts too. */
const FIXTURE_ASSIGNED_ENV_CI = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
process.env.CI = '';
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
});
`;

/** The same mutation, one alias away. */
const FIXTURE_ALIASED_ENV = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const env = process.env;
env.CI = '';
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
});
`;

/** ...and spelled with brackets. */
const FIXTURE_BRACKETED_ENV = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
process['env'].CI = '';
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
});
`;

/** A test's TITLE is evaluated eagerly, at collection time. */
const FIXTURE_SKIP_IN_TEST_TITLE = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test(\`\${(test.skip(!HAS_TOOL, 'tool missing'), 'probe')}\`, async () => {});
});
`;

/**
 * The escape hatch smuggled into the skip's DESCRIPTION rather than a
 * comment. It reads as an ordinary message; it must not buy an exemption.
 */
const FIXTURE_MARKER_IN_STRING = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL, 'ci-skip-ok: tool missing');
    test('asserts something', async () => {});
});
`;

// ---------------------------------------------------------------------
// Spec bodies
// ---------------------------------------------------------------------

/**
 * Playwright's default `testMatch`, near enough:
 * `**\/*.@(spec|test).?(c|m)[jt]s?(x)`. Matching only `*.spec.ts` would
 * leave a future `foo.test.ts` collected by the runner but invisible to
 * this gate.
 */
const TEST_FILE = /\.(spec|test)\.[cm]?[jt]sx?$/;

function specFiles(root: string): string[] {
    const out: string[] = [];
    const walk = (dir: string): void => {
        for (const entry of readdirSync(dir).sort()) {
            if (entry === 'node_modules') continue;
            const p = join(dir, entry);
            if (statSync(p).isDirectory()) walk(p);
            else if (TEST_FILE.test(entry)) out.push(p);
        }
    };
    walk(root);
    return out;
}

test.describe('e2e skip reachability (hermetic meta-gate)', () => {
    test('analyzer detects the hole it exists for', () => {
        // Positive control — the shape that shipped broken must be caught,
        // and must be diagnosed as a dead beforeAll guard.
        const holed = violations(analyzeSource('holed.spec.ts', FIXTURE_HOLED));
        expect(
            holed.map((v) => `${v.line}:${v.condition}`),
            'the holed fixture must produce exactly one violation',
        ).toEqual(['8:!HAS_TOOL']);
        expect(holed[0].guardedByThrowingBeforeAll).toBe(true);

        // Referencing process.env.CI is not sufficient: this one skips
        // *when* CI is set, which is the failure mode wearing a disguise.
        const inverted = violations(analyzeSource('inverted.spec.ts', FIXTURE_INVERTED));
        expect(inverted, 'an ||-CI condition must still be a violation').toHaveLength(1);

        // Same blast radius, different timing: a beforeAll skip switches
        // the whole group off under CI just as thoroughly.
        expect(
            violations(analyzeSource('before-all.spec.ts', FIXTURE_BEFORE_ALL_GROUP_SKIP)).map(
                (v) => v.scope,
            ),
            'a group-wide beforeAll skip must be a violation',
        ).toEqual(['beforeAll']);

        // The one-hop const resolution must not be fooled by shadowing:
        // the inner `SKIP` is live under CI even though the outer is not.
        expect(
            violations(analyzeSource('shadowed.spec.ts', FIXTURE_SHADOWED_CONST)),
            'a shadowed const must not be resolved to the outer CI-guarded one',
        ).toHaveLength(1);

        // The matcher must key off what is CALLED, not how it is spelled.
        expect(
            violations(analyzeSource('parens.spec.ts', FIXTURE_PARENTHESISED_CALLEE)),
            '`(test.skip)(...)` must still be recognised',
        ).toHaveLength(1);

        // Every shape that spells the same call, or defeats the one-hop
        // resolution, must still land as a violation. Each of these was a
        // review finding; keeping them in one table makes it obvious that
        // the analyzer's job is to be conservative, not clever.
        for (const [name, source] of [
            ['element-access-callee', FIXTURE_ELEMENT_ACCESS_CALLEE],
            ['param-shadow', FIXTURE_PARAM_SHADOW],
            ['function-expr-shadow', FIXTURE_FUNCTION_EXPR_SHADOW],
            ['mutable-binding', FIXTURE_MUTABLE_BINDING],
            ['shadowed-process', FIXTURE_SHADOWED_PROCESS],
            ['shadowed-undefined', FIXTURE_SHADOWED_UNDEFINED],
            ['deleted-env-ci', FIXTURE_DELETED_ENV_CI],
            ['assigned-env-ci', FIXTURE_ASSIGNED_ENV_CI],
            ['aliased-env', FIXTURE_ALIASED_ENV],
            ['bracketed-env', FIXTURE_BRACKETED_ENV],
            ['skip-in-test-title', FIXTURE_SKIP_IN_TEST_TITLE],
        ] as const) {
            expect(
                violations(analyzeSource(`${name}.spec.ts`, source)).length,
                `${name} must be reported as a violation`,
            ).toBe(1);
        }

        // The escape hatch must be a COMMENT. Putting `ci-skip-ok:` in the
        // skip's own description reads like an ordinary message and must
        // not buy the exemption.
        expect(
            violations(analyzeSource('marker-in-string.spec.ts', FIXTURE_MARKER_IN_STRING)),
            'the marker inside a string literal must not exempt anything',
        ).toHaveLength(1);

        // Negative controls — none of these may be reported.
        for (const [name, source] of [
            ['guarded', FIXTURE_GUARDED],
            ['const-hop', FIXTURE_CONST_HOP],
            ['runtime-soft-gate', FIXTURE_RUNTIME_SOFT_GATE],
            ['before-each', FIXTURE_BEFORE_EACH],
            ['marker', FIXTURE_MARKER],
            ['marker-trailing', FIXTURE_MARKER_TRAILING],
        ] as const) {
            expect(
                violations(analyzeSource(`${name}.spec.ts`, source)).map(describeViolation),
                `${name} fixture must be clean`,
            ).toEqual([]);
        }

        // The classifier must still recognise the runtime idioms as runtime,
        // otherwise "0 violations" above would be true for the wrong reason.
        const soft = analyzeSource('soft.spec.ts', FIXTURE_RUNTIME_SOFT_GATE);
        expect(soft.map((s) => `${s.form}/${s.scope}`).sort()).toEqual([
            'conditional/test',
            'declaration/describe',
            'noarg/test',
        ]);
    });

    test('no e2e spec can be silently skipped in CI', () => {
        // Scan unit: every *.spec.ts under apps/web/e2e/, recursively
        // (this file's own directory), parsed with the TypeScript AST —
        // not grepped, so comments and string literals cannot trip it.
        const e2eRoot = dirname(test.info().file);
        const files = specFiles(e2eRoot);

        // Anti-vacuity: a broken walk must not read as "all clean".
        expect(files.length, `expected to find e2e specs under ${e2eRoot}`).toBeGreaterThan(20);

        const sites = files.flatMap((f) =>
            analyzeSource(relative(e2eRoot, f), readFileSync(f, 'utf8')),
        );
        expect(
            sites.length,
            'the AST matcher recognised no test.skip call at all — it has drifted',
        ).toBeGreaterThan(0);

        const bad = violations(sites);
        expect(bad.map(describeViolation).join('\n\n'), 'collection-time skip(s) not CI-proof').toBe(
            '',
        );
    });
});

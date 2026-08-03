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
 * THREAT MODEL — read this before "hardening" anything here
 * ---------------------------------------------------------
 * This gate catches ACCIDENTS BY HONEST AUTHORS. That is the whole of
 * its threat model, and it is a deliberate choice, not a shortfall:
 *
 *   - a CI guard "simplified" away (`cond && !process.env.CI` → `cond`)
 *   - collection-time evaluation mistaken for run-time evaluation
 *   - a new spec copying the holed shape from an old one
 *
 * It does NOT resist an author who WANTS the gate gone, and it cannot:
 * deleting this file removes it entirely. Every call-shape trick that
 * could be closed here — spelling `test.skip` differently, rebinding a
 * global, smuggling the exemption marker somewhere unusual — is strictly
 * more effort than `rm`, so closing them buys no adversarial resistance
 * whatsoever. It only buys robustness against the shapes an honest
 * refactor actually produces, which is why the ones handled below are
 * handled: an extracted `const skip = test.skip` alias is something
 * people really write; `process['env'].CI = ''` is not.
 *
 * Consequence for review: "an author could deliberately write X to evade
 * this" is not, by itself, a finding. It becomes one only with an
 * account of how an author writes X BY MISTAKE. Reviewing this file
 * against a sabotage model produces an unbounded stream of syntactic
 * corners and never converges — the repo has already paid for that
 * lesson once (anti-pattern 98, the migration lock-budget lint: 12
 * rounds of "cleverly-crafted SQL" findings that stopped the moment the
 * threat model was written down).
 *
 * The gates that DO have to survive an adversary are the ones about
 * tenant isolation and credentials (RLS, api-key scope, encryption-key
 * refusal). This is not one of them; it is a spelling checker for CI
 * guards.
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
 *   A skip written inside a plain HELPER function is judged by where the
 *   helper is CALLED, not where it is written: called from a describe
 *   body it is group-wide, called from a test body it is not. An
 *   EXPORTED helper is treated as group-wide because its call sites are
 *   not all visible. Attributing it to the declaration site instead
 *   turned an ordinary `const skipIf = () => test.skip(...)` used
 *   per-test into a red gate.
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
 *     `&& !process.env.CI` or by adding the `ci-skip-ok` marker.
 *   - A helper defined OUTSIDE `apps/web/e2e/**` (say in
 *     `apps/web/test-utils/`). Helpers under `e2e/` are scanned; ones
 *     that are not are invisible.
 *   - An anonymous closure with no name to match call sites against.
 *   - Mutating `process.env` through an alias
 *     (`const env = process.env; env.CI = ''`). Direct
 *     `process.env.CI = …` / `delete process.env.CI` ARE caught; the
 *     aliased form is sabotage-class (see THREAT MODEL) and chasing it
 *     cost a false positive on an innocent `process.platform` read.
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
    scope:
        | 'file'
        | 'describe'
        | 'beforeAll'
        | 'test'
        | 'eachHook'
        | 'step'
        /**
         * Inside a plain (non-test-construct) function. The blast radius
         * depends on WHERE that function is called, not on where it is
         * written — see `closureIsGroupWide`.
         */
        | 'closure';
    condition: string;
    ciNeutral: boolean;
    allowMarker: boolean;
    /** Name of the innermost enclosing plain function, if it has one. */
    closureName: string | null;
    /** That function is exported, so its call sites are not all visible. */
    closureExported: boolean;
    /**
     * Whether this skip can take a whole GROUP with it. Syntactic scope
     * decides it directly; for a `closure` scope it is decided by where
     * that closure is called (see analyzeSource).
     */
    groupWide: boolean;
    /** The enclosing describe has a `beforeAll` that can `throw`. */
    guardedByThrowingBeforeAll: boolean;
}

/** Scopes at which one skip call takes an entire group with it. */
const GROUP_SCOPES: ReadonlySet<SkipSite['scope']> = new Set([
    'file',
    'describe',
    'beforeAll',
] as const);

/** Function-ish nodes that are NOT a Playwright construct's callback. */
type PlainFunction = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction;

function isPlainFunction(n: ts.Node): n is PlainFunction {
    return ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n);
}

function hasExportModifier(n: ts.Node): boolean {
    const mods = ts.canHaveModifiers(n) ? ts.getModifiers(n) : undefined;
    return (mods ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
}

/**
 * Names exported through an `export { a, b as c }` clause.
 *
 * The `export` modifier is not on the declaration in that form, and it is
 * the shape an IDE's "move to another file" refactor usually writes.
 * (Review finding under the declared threat model.)
 */
function exportListNames(sf: ts.SourceFile): Set<string> {
    const names = new Set<string>();
    for (const stmt of sf.statements) {
        if (!ts.isExportDeclaration(stmt) || !stmt.exportClause) continue;
        if (ts.isNamedExports(stmt.exportClause)) {
            for (const el of stmt.exportClause.elements) {
                // `export { local as public }` exports the LOCAL binding.
                names.add((el.propertyName ?? el.name).text);
            }
        }
    }
    return names;
}

/**
 * The name a helper function is reachable by, and whether it escapes the
 * file. `function f(){}`, `const f = () => {}` and `export const f = ...`
 * all resolve; an anonymous inline callback does not.
 */
function plainFunctionIdentity(
    fn: PlainFunction,
    exportList: Set<string>,
): { name: string | null; exported: boolean } {
    const result = (name: string | null, exported: boolean) => ({
        name,
        exported: exported || (name !== null && exportList.has(name)),
    });
    if (ts.isFunctionDeclaration(fn)) {
        return result(fn.name?.text ?? null, hasExportModifier(fn));
    }
    const decl = fn.parent;
    if (decl && ts.isVariableDeclaration(decl) && ts.isIdentifier(decl.name)) {
        const list = decl.parent;
        const stmt = list?.parent;
        return result(decl.name.text, stmt !== undefined && hasExportModifier(stmt));
    }
    if (ts.isFunctionExpression(fn) && fn.name) {
        return result(fn.name.text, false);
    }
    return result(null, false);
}

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

/** The literal key being read off `process.env`, or null. */
function envKeyOf(access: ts.Node): string | null {
    if (ts.isPropertyAccessExpression(access)) return access.name.text;
    if (ts.isElementAccessExpression(access)) return literalKey(access.argumentExpression);
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
 * True when nothing in the file writes to `process.env.CI`.
 *
 * `delete process.env.CI;` or `process.env.CI = '';` at file scope makes
 * `!process.env.CI` true under CI at collection time, so a guard written
 * with the `&& !process.env.CI` suffix silently stops guarding. That IS
 * an accident an honest author can have: poking at env vars to reproduce
 * something locally and leaving the line in.
 *
 * Scoped to DIRECT writes on purpose. An earlier revision of this check
 * treated every appearance of `process` or `process.env` that was not a
 * single member read as a possible mutation, to catch
 * `const env = process.env; env.CI = '';`. That is a sabotage shape (see
 * the THREAT MODEL above — the same author can delete this file), and
 * the over-approximation had a real cost in the other direction: an
 * ordinary `const IS_LINUX = process.platform === 'linux';` in a spec
 * made the whole file "not CI-neutral" and turned a CORRECT
 * `!IS_LINUX && !process.env.CI` guard into a red gate. Blocking `main`
 * over an unrelated `process.platform` read is a much likelier and much
 * more damaging accident than the one it was buying.
 */
function envIsPristine(sf: ts.SourceFile): boolean {
    let mutated = false;
    const visit = (n: ts.Node): void => {
        if (mutated) return;
        if (isProcessEnv(n)) {
            const [child, parent] = skipParens(n);
            const isMemberAccess =
                parent !== undefined &&
                (ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) &&
                parent.expression === child;
            // ONLY a write to `CI` can break the proof. An ordinary
            // `process.env.TZ = 'UTC'` inside a test used to invalidate the
            // whole file and turn a correct `&& !process.env.CI` guard red.
            // (Review finding under the declared threat model.)
            if (isMemberAccess && envKeyOf(parent) === 'CI') {
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

/**
 * Playwright also accepts `test.skip(callback, description)`, where the
 * callback receives fixtures. MEASURED: at describe scope it behaves
 * exactly like the literal form — the group is skipped and a throwing
 * `beforeAll` never runs — so it is in the same dangerous class and has
 * to be checked. Unwrap it to the expression it returns so
 * `test.skip(() => !HAS_TOOL && !process.env.CI, '…')` can still be
 * proven; a callback with real statements in it is not analysable and is
 * reported (the `ci-skip-ok` marker is the way out).
 */
function conditionExpression(arg: ts.Expression): ts.Expression | null {
    const cur = unwrap(arg);
    if (!ts.isArrowFunction(cur) && !ts.isFunctionExpression(cur)) return cur;
    const body = cur.body;
    if (!ts.isBlock(body)) return body;
    if (body.statements.length === 1) {
        const only = body.statements[0];
        if (ts.isReturnStatement(only) && only.expression) return only.expression;
    }
    return null;
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
    const fullStart = stmt.getFullStart();
    const leading = (ts.getLeadingCommentRanges(text, fullStart) ?? []).filter((r) =>
        // A comment with no newline between it and the previous token is
        // that token's TRAILING comment, and TypeScript hands it back as
        // this statement's leading trivia too. Without this filter a
        // `// ci-skip-ok:` on one skip silently exempted the next one.
        // (Review finding, High.)
        text.slice(fullStart, r.pos).includes('\n'),
    );
    const trailing = ts.getTrailingCommentRanges(text, stmt.getEnd()) ?? [];
    return [...leading, ...trailing].some((r) => ALLOW_MARKER.test(text.slice(r.pos, r.end)));
}

/**
 * File-scope `const skip = test.skip;`-style aliases, so a call through
 * the alias resolves to the same dotted name.
 *
 * Extracting a helper alias is an ordinary refactor, and without this the
 * aliased call was not recorded at all. Only `const` and only names
 * rooted at `test` are followed, and only when the name is bound exactly
 * once in the file (same shadowing rule as the condition resolver).
 * (Review finding, High.)
 */
function calleeAliases(sf: ts.SourceFile, bound: Map<string, number>): Map<string, string> {
    const aliases = new Map<string, string>();
    const rootedAtTest = (name: string | null): boolean =>
        name !== null && (name === 'test' || name.startsWith('test.'));

    // Any scope, not just file scope: `const skip = test.skip;` inside the
    // describe is the same refactor. Names bound more than once are
    // skipped for the same shadowing reason as the condition resolver.
    const visit = (n: ts.Node): void => {
        if (ts.isVariableDeclaration(n) && n.initializer) {
            const list = n.parent;
            const isConst =
                ts.isVariableDeclarationList(list) && (list.flags & ts.NodeFlags.Const) !== 0;
            if (isConst) {
                const target = calleeName(n.initializer);
                if (ts.isIdentifier(n.name)) {
                    if (bound.get(n.name.text) === 1 && rootedAtTest(target)) {
                        aliases.set(n.name.text, target as string);
                    }
                } else if (ts.isObjectBindingPattern(n.name) && rootedAtTest(target)) {
                    // `const { skip } = test;`
                    for (const el of n.name.elements) {
                        if (!ts.isIdentifier(el.name) || el.dotDotDotToken) continue;
                        const prop =
                            el.propertyName && ts.isIdentifier(el.propertyName)
                                ? el.propertyName.text
                                : el.name.text;
                        if (bound.get(el.name.text) === 1) {
                            aliases.set(el.name.text, `${target as string}.${prop}`);
                        }
                    }
                }
            }
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    return aliases;
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
    const exportList = exportListNames(sf);
    const aliases = calleeAliases(sf, bound);
    /** Dotted callee name, with a file-scope alias expanded. */
    const resolvedCallee = (expr: ts.Expression): string => {
        const name = calleeName(expr);
        if (name === null) return '';
        const head = name.split('.')[0];
        const target = aliases.get(head);
        return target === undefined ? name : target + name.slice(head.length);
    };
    const globalsIntact = !PROOF_GLOBALS.some((g) => bound.has(g)) && envIsPristine(sf);
    const sites: SkipSite[] = [];
    // Enclosing test-construct scopes, innermost last.
    const stack: SkipSite['scope'][] = [];
    // Enclosing `test.describe` callbacks, for the beforeAll-throws diagnosis.
    const describeStack: ts.Node[] = [];
    // Enclosing plain (non-construct) functions, innermost last.
    const closureStack: { name: string | null; exported: boolean }[] = [];
    /**
     * Scopes from which each bare-identifier call is made, so a skip
     * inside a named helper can be judged by WHERE THE HELPER IS CALLED
     * rather than where it is written. Attributing it to the declaration
     * site made `const only = () => test.skip(...)` declared in a
     * describe but called from a test body — a per-test skip, out of
     * scope by design — a violation that blocks `main`. (Review finding
     * under the declared threat model.)
     */
    const callScopes = new Map<string, Set<SkipSite['scope']>>();

    const describeHasThrowingBeforeAll = (describeBody: ts.Node): boolean => {
        let found = false;
        const visit = (n: ts.Node): void => {
            if (found) return;
            if (
                ts.isCallExpression(n) &&
                resolvedCallee(n.expression) === 'test.beforeAll' &&
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
            const callee = resolvedCallee(node.expression);
            const args = node.arguments;
            // A `test.describe` body extracted into a named function and
            // passed by reference is an ordinary refactor of a long block.
            // Accepting only inline functions here left its skips filed as
            // a closure nobody calls. (Review finding under the declared
            // threat model.)
            const hasCallback =
                args.length >= 1 &&
                args.some(
                    (a) =>
                        ts.isArrowFunction(a) || ts.isFunctionExpression(a) || ts.isIdentifier(a),
                );

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

            if (callee !== '' && !callee.includes('.')) {
                const at = stack.length ? stack[stack.length - 1] : 'file';
                const seen = callScopes.get(callee) ?? new Set<SkipSite['scope']>();
                seen.add(at);
                callScopes.set(callee, seen);
            }

            // `test.describe('gate', suite)` runs `suite`'s body AS the
            // describe body, so record it exactly like a call from there.
            if (pushed) {
                for (const arg of args) {
                    if (ts.isIdentifier(arg)) {
                        const seen = callScopes.get(arg.text) ?? new Set<SkipSite['scope']>();
                        seen.add(pushed);
                        callScopes.set(arg.text, seen);
                    }
                }
            }

            if (CALLEE_SKIP.test(callee)) {
                // `test.skip(title, body)` / `test.skip(title, details, body)`
                // declares a statically-off test. What distinguishes it from
                // `test.skip(condition, description)` is that a LATER argument
                // is a function — a description is always a string. Keying off
                // the title being a string LITERAL instead made the ordinary
                // `const title = '…'; test.skip(title, async () => {})` look
                // like a conditional group skip and turned `main` red.
                // (Review finding under the declared threat model.)
                const isDeclaration =
                    args.length >= 2 &&
                    args
                        .slice(1)
                        .some((a) => ts.isArrowFunction(a) || ts.isFunctionExpression(a));
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
                            ? (() => {
                                  const expr = conditionExpression(args[0]);
                                  return (
                                      expr !== null && isCiNeutral(expr, consts, globalsIntact)
                                  );
                              })()
                            : true,
                    closureName: closureStack.length
                        ? closureStack[closureStack.length - 1].name
                        : null,
                    closureExported: closureStack.length
                        ? closureStack[closureStack.length - 1].exported
                        : false,
                    // Filled in by the post-pass below.
                    groupWide: false,
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
                    // Descend into the parameters and body rather than the
                    // function node, so the construct's own callback is not
                    // then re-classified as a plain closure below.
                    for (const param of arg.parameters) visit(param);
                    if (arg.body) visit(arg.body);
                    stack.pop();
                } else {
                    visit(arg);
                }
            }
            if (pushedDescribe) describeStack.pop();
            return;
        }

        // A function that is NOT a construct's callback. Where its skips
        // fire depends on its call sites, not on this position.
        if (isPlainFunction(node)) {
            stack.push('closure');
            closureStack.push(plainFunctionIdentity(node, exportList));
            ts.forEachChild(node, visit);
            closureStack.pop();
            stack.pop();
            return;
        }

        ts.forEachChild(node, visit);
    };

    visit(sf);

    // Decide the blast radius now that every call site is known.
    for (const site of sites) {
        if (site.scope !== 'closure') {
            site.groupWide = GROUP_SCOPES.has(site.scope);
            continue;
        }
        // An exported helper can be called from any spec, including at
        // describe scope in one this pass never sees, so it is treated as
        // group-wide. An unnamed closure has no visible call site and is
        // left alone (documented limitation).
        if (site.closureExported) {
            site.groupWide = true;
            continue;
        }
        const calledFrom = site.closureName ? callScopes.get(site.closureName) : undefined;
        site.groupWide =
            calledFrom !== undefined && [...calledFrom].some((sc) => GROUP_SCOPES.has(sc));
    }

    return sites;
}

/** Group-wide conditional skips that are not provably inert under CI. */
export function violations(sites: SkipSite[]): SkipSite[] {
    return sites.filter(
        (s) =>
            s.form === 'conditional' &&
            s.groupWide &&
            !s.ciNeutral &&
            !s.allowMarker,
    );
}

function describeViolation(v: SkipSite): string {
    const collection = v.scope === 'file' || v.scope === 'describe';
    const when = collection
        ? 'evaluated at COLLECTION time'
        : v.scope === 'beforeAll'
          ? 'runs before every test in the group'
          : v.closureExported
            ? `inside exported helper \`${v.closureName ?? '<anonymous>'}\`, whose call sites ` +
              'are not all visible from this file'
            : `inside helper \`${v.closureName ?? '<anonymous>'}\`, which is called at ` +
              'group scope';
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
        '    Fix: append `&& !process.env.CI` to the condition (inside the callback,\n' +
        '    if this is the `test.skip(cb, desc)` form), or, when skipping under CI\n' +
        '    really is intended, add a `// ci-skip-ok: <reason>` comment.'
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


/** Extracting `test.skip` into a local alias is an ordinary refactor. */
const FIXTURE_ALIASED_SKIP = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const skip = test.skip;
test.describe('gate', () => {
    skip(!HAS_TOOL, 'tool missing');
});
`;

/** The alias declared inside the describe, and via destructuring. */
const FIXTURE_INNER_ALIASED_SKIP = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    const skip = test.skip;
    skip(!HAS_TOOL, 'tool missing');
});
`;

const FIXTURE_DESTRUCTURED_SKIP = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const { skip } = test;
test.describe('gate', () => {
    skip(!HAS_TOOL, 'tool missing');
});
`;

/**
 * A trailing `ci-skip-ok:` is ALSO leading trivia of the next statement.
 * Only the first skip here is exempt; the second must be reported.
 */
const FIXTURE_MARKER_BLEED = `
import { test } from '@playwright/test';
const IS_LINUX = false;
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!IS_LINUX, 'unsupported'); // ci-skip-ok: covered elsewhere
    test.skip(!HAS_TOOL, 'tool missing');
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

/**
 * A skip moved into a shared exported helper. Ordinary de-duplication
 * refactor; the helper's call sites are not all visible from here, so it
 * has to carry the guard itself.
 */
const FIXTURE_EXPORTED_HELPER = `
import { test } from '@playwright/test';
export const skipIfMissing = (missing: boolean) =>
    test.skip(missing, 'tool missing');
`;

/**
 * A local helper called from a DESCRIBE body: group-wide, so gated.
 */
const FIXTURE_HELPER_CALLED_AT_DESCRIBE = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const skipIfMissing = () => test.skip(!HAS_TOOL, 'tool missing');
test.describe('gate', () => {
    skipIfMissing();
    test('probe', async () => {});
});
`;

/**
 * The SAME helper called only from a test body: a per-test skip, out of
 * scope by design. Judging it by its declaration site made this a
 * violation and blocked `main` for no reason.
 */
const FIXTURE_HELPER_CALLED_IN_TEST = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    const skipIfMissing = () => test.skip(!HAS_TOOL, 'tool missing');
    test('probe', async () => {
        skipIfMissing();
    });
});
`;

/**
 * An unrelated `process` read must not disarm a correct guard. This was
 * a real false positive: it turned a CORRECT `&& !process.env.CI` red.
 */
const FIXTURE_PROCESS_PLATFORM_READ = `
import { test } from '@playwright/test';
const IS_LINUX = process.platform === 'linux';
test.describe('gate', () => {
    test.skip(!IS_LINUX && !process.env.CI, 'unsupported');
});
`;

/** Reading several env vars is ordinary and must not disarm the guard. */
const FIXTURE_ENV_DESTRUCTURED_READ = `
import { test } from '@playwright/test';
const { PLAYWRIGHT_BASE_URL } = process.env;
const HAS_TOOL = Boolean(PLAYWRIGHT_BASE_URL);
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'unsupported');
});
`;

/**
 * `test.skip(callback, description)` — Playwright's fixture-aware form.
 * MEASURED to behave exactly like the literal form at describe scope
 * (group skipped, throwing beforeAll never runs), so a guard written
 * inside the callback must still be provable.
 */
const FIXTURE_CALLBACK_GUARDED = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(() => !HAS_TOOL && !process.env.CI, 'tool missing');
});
`;

/** ...and unguarded, it is the same hole. */
const FIXTURE_CALLBACK_UNGUARDED = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(() => !HAS_TOOL, 'tool missing');
});
`;

/** A block-bodied callback with a single return is still analysable. */
const FIXTURE_CALLBACK_BLOCK_RETURN = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(() => {
        return !HAS_TOOL && !process.env.CI;
    }, 'tool missing');
});
`;

/** A long describe body extracted into a named function, passed by name. */
const FIXTURE_NAMED_DESCRIBE_CALLBACK = `
import { test } from '@playwright/test';
const HAS_TOOL = false;
function suite() {
    test.skip(!HAS_TOOL, 'tool missing');
    test('gate', async () => {});
}
test.describe('gate', suite);
`;

/** The `export { x }` clause form an IDE "move to file" refactor writes. */
const FIXTURE_EXPORT_CLAUSE_HELPER = `
import { test } from '@playwright/test';
const skipIfMissing = (missing: boolean) => test.skip(missing, 'tool missing');
export { skipIfMissing };
`;

/**
 * A declaration-form skip whose TITLE is a constant. Not a condition at
 * all; reporting it turned `main` red for a plain constant extraction.
 */
const FIXTURE_DECLARATION_TITLE_CONST = `
import { test } from '@playwright/test';
const title = 'temporarily disabled';
test.describe('gate', () => {
    test.skip(title, async () => {});
});
`;

/**
 * Writing an UNRELATED env var inside a test must not invalidate the
 * file's CI proof. This was a false positive on a plain date test.
 */
const FIXTURE_UNRELATED_ENV_WRITE = `
import { test } from '@playwright/test';
const MISSING = true;
test.describe('gate', () => {
    test.skip(MISSING && !process.env.CI, 'tool missing');
    test('date rendering', async () => {
        process.env.TZ = 'UTC';
    });
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
 * Every TS/JS source file under `e2e/`, not just the ones Playwright
 * collects.
 *
 * Two reasons. Playwright's default `testMatch` is
 * `**\/*.@(spec|test).?(c|m)[jt]s?(x)`, so matching only `*.spec.ts`
 * would leave a future `foo.test.ts` collected by the runner but
 * invisible here. And moving a repeated skip into a shared
 * `e2e/skip-helper.ts` is an ordinary refactor that would otherwise
 * carry the skip straight out of the gate's field of view. (Review
 * finding under the declared threat model.)
 */
const SCANNED_FILE = /\.[cm]?[jt]sx?$/;
const DECLARATION_FILE = /\.d\.[cm]?ts$/;

function specFiles(root: string): string[] {
    const out: string[] = [];
    const walk = (dir: string): void => {
        for (const entry of readdirSync(dir).sort()) {
            if (entry === 'node_modules') continue;
            const p = join(dir, entry);
            if (statSync(p).isDirectory()) walk(p);
            else if (SCANNED_FILE.test(entry) && !DECLARATION_FILE.test(entry)) out.push(p);
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
            ['deleted-env-ci', FIXTURE_DELETED_ENV_CI],
            ['assigned-env-ci', FIXTURE_ASSIGNED_ENV_CI],
            ['aliased-skip', FIXTURE_ALIASED_SKIP],
            ['inner-aliased-skip', FIXTURE_INNER_ALIASED_SKIP],
            ['destructured-skip', FIXTURE_DESTRUCTURED_SKIP],
            ['exported-helper', FIXTURE_EXPORTED_HELPER],
            ['helper-called-at-describe', FIXTURE_HELPER_CALLED_AT_DESCRIBE],
            ['callback-unguarded', FIXTURE_CALLBACK_UNGUARDED],
            ['named-describe-callback', FIXTURE_NAMED_DESCRIBE_CALLBACK],
            ['export-clause-helper', FIXTURE_EXPORT_CLAUSE_HELPER],
            ['marker-bleed', FIXTURE_MARKER_BLEED],
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
            ['helper-called-in-test', FIXTURE_HELPER_CALLED_IN_TEST],
            ['process-platform-read', FIXTURE_PROCESS_PLATFORM_READ],
            ['env-destructured-read', FIXTURE_ENV_DESTRUCTURED_READ],
            ['callback-guarded', FIXTURE_CALLBACK_GUARDED],
            ['callback-block-return', FIXTURE_CALLBACK_BLOCK_RETURN],
            ['declaration-title-const', FIXTURE_DECLARATION_TITLE_CONST],
            ['unrelated-env-write', FIXTURE_UNRELATED_ENV_WRITE],
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

        // Anti-vacuity, without encoding a spec count: this very file must
        // be among the results. A broken walk cannot satisfy that, and
        // consolidating or deleting specs cannot break it. An earlier
        // `> 20` floor would have turned `main` red on an ordinary spec
        // merge. (Review finding under the declared threat model.)
        expect(files, `the walk of ${e2eRoot} must include this spec itself`).toContain(
            test.info().file,
        );

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

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
 * whatsoever.
 *
 * Consequence for review: "an author could deliberately write X to evade
 * this" is not, by itself, a finding. It becomes one only with an account
 * of how an author writes X BY MISTAKE. Reviewing this file against a
 * sabotage model produces an unbounded stream of syntactic corners and
 * never converges — the repo has already paid for that lesson twice
 * (anti-pattern 98, and nine rounds of it here).
 *
 * FALSE POSITIVES ARE WORSE THAN MISSES
 * -------------------------------------
 * This spec is collected by `e2e/*.spec.ts`, so it runs inside the
 * REQUIRED status check `Playwright full suite (…)`. A false positive is
 * therefore not an annoyance, it is a red `main` on correct code — and
 * this repo's standing rule is that a gate which is red for no reason
 * gets switched off. A miss costs one accident slipping through, and it
 * is written down below so the next person hitting it knows why.
 *
 * So: WHEN IN DOUBT, DO NOT REPORT. Every ambiguous shape below resolves
 * toward "not a violation".
 *
 * THE RULE
 * --------
 * A `test.skip` / `test.fixme` call carrying a CONDITION, written at
 *
 *   - file scope,
 *   - directly inside an INLINE `test.describe` callback, or
 *   - directly inside an INLINE `test.beforeAll` callback,
 *
 * must be provably inert under CI. "Provably" is structural, not
 * semantic: the condition must be a top-level `&&` chain with one
 * conjunct that is literally
 *
 *     !process.env.CI            (or `process.env.CI === undefined`
 *                                 / `process.env.CI == null`)
 *
 * because `A && B && !process.env.CI` cannot be true when CI is set, no
 * matter what A and B are. One hop of file-scope `const` resolution is
 * performed, so `const LOCAL_ONLY = !HAS_TOOL && !process.env.CI;` +
 * `test.skip(LOCAL_ONLY, ...)` also passes — unless the name is bound
 * more than once in the file, in which case shadowing makes the hop
 * unsound and the site is treated as unproven.
 *
 * Nothing else is examined. In particular there is NO analysis of where a
 * helper function is called from. An earlier revision tried to follow
 * that — exported helpers, `forEach` callbacks, transitive call graphs,
 * identifier-passed callbacks — and it was the single largest source of
 * defects in this file, in BOTH directions: it produced false positives
 * on `const skipIf = () => test.skip(…)` used per-test, and it needed a
 * new special case for every way a callback can be spelled. Deleting it
 * removed about a third of this file.
 *
 * WHAT THIS DOES NOT CATCH — deliberately
 * ---------------------------------------
 * Each of these is a MISS accepted to avoid a false positive. If one of
 * them ever bites, the fix is a targeted fixture, not a return to
 * whole-program analysis.
 *
 *   - A skip inside ANY helper function, wherever that helper is called:
 *
 *         const skipIfMissing = () => test.skip(!HAS_TOOL, 'missing');
 *         test.describe('gate', () => { skipIfMissing(); });
 *
 *     Not reported. The same shape called from inside a test body is a
 *     legitimate per-test skip, and this gate cannot tell the two apart
 *     without following call sites.
 *
 *   - A `describe` body passed by NAME rather than written inline:
 *
 *         function suite() { test.skip(!HAS_TOOL, 'missing'); }
 *         test.describe('gate', suite);
 *
 *     Not reported, same reason.
 *
 *   - A skip in a helper module under `e2e/` that other specs import.
 *
 *   - `test.skip(callback, description)`, Playwright's fixture-aware
 *     form. MEASURED: at describe scope it behaves exactly like the
 *     literal form — the group is skipped and a throwing `beforeAll`
 *     never runs — so this really is a miss, not a non-issue. It is
 *     excluded because the form exists precisely for conditions that
 *     depend on fixtures (`({ browserName }) => browserName !== 'webkit'`),
 *     where `&& !process.env.CI` is the WRONG advice, and a gate that
 *     emits inapplicable advice on a documented idiom is broken.
 *
 *   - Per-test skips: inside a test body, a `test.step`, or a
 *     `beforeEach`. They disable one test, not the gate, and they are the
 *     repo's "soft gate" idiom (48 sites) for seed-dependent assertions.
 *     A `beforeEach` skip with a constant condition is group-wide in
 *     effect; prefer `beforeAll` (which IS checked) for a group-level
 *     precondition.
 *
 *   - Declaration-form `test.skip('name', fn)` and `test.describe.skip`.
 *     Statically and unconditionally off, and self-announcing in the
 *     source, so there is nothing to silently flip.
 *
 *   - A call through a local alias (`const skip = test.skip; skip(cond)`)
 *     or a renamed import (`import { test as t }`). The matcher keys on
 *     the literal `test.` prefix.
 *
 *   - Anything outside `apps/web/e2e/**`, and skips configured outside
 *     the spec source entirely: `testIgnore` / `grep` in
 *     playwright.config.ts, a workflow's spec selector, a step with
 *     `continue-on-error`.
 *
 * ESCAPE HATCH
 * ------------
 * A checked skip that genuinely may skip under CI must say so out loud:
 * put `// ci-skip-ok: <reason>` on or above the call. It has to be a
 * COMMENT — the marker inside the skip's own description string does not
 * count, because that reads to a human as an ordinary message.
 *
 * NON-VACUITY
 * -----------
 * `analyzer verdicts` below runs the analyzer over embedded fixtures on
 * every CI run — both the shapes that must be REPORTED and a larger set
 * of correct-code shapes that must stay CLEAN — so this file cannot
 * degrade into a scan that finds nothing and passes, and cannot quietly
 * become trigger-happy either. Measured externally too: a temp spec
 * carrying the holed shape was dropped into `e2e/` and turned this suite
 * red before being removed.
 */

// ---------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------

interface SkipSite {
    file: string;
    line: number;
    callee: string;
    /**
     * `conditional`  — `test.skip(cond)` / `test.skip(cond, desc)`.
     * `callback`     — `test.skip(fn, desc)`, Playwright's fixture form.
     * `declaration`  — `test.skip('name', fn)`, a statically-off test.
     * `noarg`        — `test.skip()`, only meaningful at runtime.
     */
    form: 'conditional' | 'callback' | 'declaration' | 'noarg';
    /**
     * Where the call is WRITTEN. `file` / `describe` / `beforeAll` are the
     * checked scopes; everything else is either per-test or inside a
     * helper whose call sites this gate deliberately does not follow.
     */
    scope:
        | 'file'
        | 'describe'
        | 'beforeAll'
        | 'test'
        | 'afterAll'
        | 'eachHook'
        | 'step'
        | 'closure';
    condition: string;
    ciNeutral: boolean;
    allowMarker: boolean;
    /** The enclosing describe has a `beforeAll` that can `throw`. */
    guardedByThrowingBeforeAll: boolean;
}

/** Scopes at which one skip call takes an entire group with it. */
const CHECKED_SCOPES: ReadonlySet<SkipSite['scope']> = new Set([
    'file',
    'describe',
    'beforeAll',
] as const);

const CALLEE_SKIP = /^test\.(skip|fixme)$/;
const CALLEE_DESCRIBE = /^(test\.describe(\.(only|serial|parallel|skip|fixme))*|describe)$/;
const CALLEE_TEST = /^test(\.(only|skip|fixme|fail|slow))?$/;
const CALLEE_BEFORE_ALL = /^test\.beforeAll$/;
// `afterAll` runs AFTER the group, so nothing in it can affect a
// collection-time skip. Lumping it in with `beforeAll` meant an
// ordinary `afterAll` that RESTORES process.env.CI invalidated the
// proof of a correct sibling guard. (Review finding: false positive.)
const CALLEE_AFTER_ALL = /^test\.afterAll$/;
const CALLEE_EACH_HOOK = /^test\.(beforeEach|afterEach)$/;
const ALLOW_MARKER = /ci-skip-ok:\s*\S/;

// ---------------------------------------------------------------------
// Expression helpers
// ---------------------------------------------------------------------

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

/** The literal key of a `x['k']` access, or null. */
function literalKey(node: ts.Expression): string | null {
    const k = unwrap(node);
    if (ts.isStringLiteral(k) || ts.isNoSubstitutionTemplateLiteral(k)) return k.text;
    return null;
}

/**
 * Dotted name of a call target — `test.skip`, `test.describe.serial` — or
 * null when it is not a plain identifier chain. Built structurally rather
 * than from `getText()`, so `(test.skip)` and `test['skip']` read the
 * same as `test.skip`.
 */
function calleeName(expr: ts.Expression): string | null {
    const cur = unwrap(expr);
    if (ts.isIdentifier(cur)) return cur.text;
    if (ts.isPropertyAccessExpression(cur)) {
        const left = calleeName(cur.expression);
        return left === null ? null : `${left}.${cur.name.text}`;
    }
    if (ts.isElementAccessExpression(cur)) {
        const key = literalKey(cur.argumentExpression);
        if (key !== null) {
            const left = calleeName(cur.expression);
            return left === null ? null : `${left}.${key}`;
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

/** True when `node` is `process.env.CI`. */
function isProcessEnvCI(node: ts.Node): boolean {
    if (!ts.isExpression(node)) return false;
    const cur = unwrap(node);
    if (ts.isPropertyAccessExpression(cur)) {
        return cur.name.text === 'CI' && isProcessEnv(cur.expression);
    }
    if (ts.isElementAccessExpression(cur)) {
        return literalKey(cur.argumentExpression) === 'CI' && isProcessEnv(cur.expression);
    }
    return false;
}

/** `!process.env.CI`, `process.env.CI === undefined`, `… == null`. */
function assertsCiIsOff(node: ts.Expression): boolean {
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

// ---------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------

/** Names bound to a FUNCTION in this file. */
function functionBindings(sf: ts.SourceFile): Set<string> {
    const names = new Set<string>();
    const visit = (n: ts.Node): void => {
        if (ts.isFunctionDeclaration(n) && n.name) names.add(n.name.text);
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
            const init = unwrap(n.initializer);
            if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) {
                names.add(n.name.text);
            }
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    return names;
}

/** Every name the file binds, however it binds it, with a count. */
function boundNames(sf: ts.SourceFile): Map<string, number> {
    const counts = new Map<string, number>();
    const bump = (name: string): void => void counts.set(name, (counts.get(name) ?? 0) + 1);
    const count = (n: ts.Node): void => {
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
 * File-scope `const NAME = <expr>;` initialisers, for one-hop resolution.
 *
 * A name is dropped rather than resolved when it is bound more than once
 * anywhere in the file (shadowing would make the hop unsound) or when it
 * is not `const` (`let X = !process.env.CI; X = true;` has a CI-safe
 * INITIALISER and a live VALUE). Dropped means "not proven", i.e. the
 * site is reported.
 */
function fileScopeConsts(
    sf: ts.SourceFile,
    bound: Map<string, number>,
): Map<string, ts.Expression> {
    const map = new Map<string, ts.Expression>();
    for (const stmt of sf.statements) {
        if (!ts.isVariableStatement(stmt)) continue;
        if ((stmt.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
        for (const decl of stmt.declarationList.declarations) {
            if (ts.isIdentifier(decl.name) && decl.initializer && bound.get(decl.name.text) === 1) {
                map.set(decl.name.text, decl.initializer);
            }
        }
    }
    return map;
}

function isCiNeutral(cond: ts.Expression, consts: Map<string, ts.Expression>): boolean {
    if (conjuncts(cond).some(assertsCiIsOff)) return true;
    const cur = unwrap(cond);
    if (ts.isIdentifier(cur)) {
        const init = consts.get(cur.text);
        // One hop only, and never back into an identifier (no cycles).
        if (init && conjuncts(init).some(assertsCiIsOff)) return true;
    }
    return false;
}

/**
 * True when a `ci-skip-ok:` marker appears in a COMMENT attached to the
 * statement — never merely somewhere in its source text, and never
 * bleeding from the previous statement's trailing comment.
 */
function hasAllowMarker(text: string, stmt: ts.Node): boolean {
    const fullStart = stmt.getFullStart();
    const leading = (ts.getLeadingCommentRanges(text, fullStart) ?? []).filter((r) =>
        // A comment with no newline between it and the previous token is
        // that token's TRAILING comment, which TypeScript also hands back
        // as this statement's leading trivia.
        text.slice(fullStart, r.pos).includes('\n'),
    );
    const trailing = ts.getTrailingCommentRanges(text, stmt.getEnd()) ?? [];
    return [...leading, ...trailing].some((r) => ALLOW_MARKER.test(text.slice(r.pos, r.end)));
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

function isInlineFunction(n: ts.Node): n is ts.ArrowFunction | ts.FunctionExpression {
    return ts.isArrowFunction(n) || ts.isFunctionExpression(n);
}

function isAnyFunction(n: ts.Node): boolean {
    return (
        isInlineFunction(n) ||
        ts.isFunctionDeclaration(n) ||
        ts.isMethodDeclaration(n) ||
        ts.isGetAccessorDeclaration(n) ||
        ts.isSetAccessorDeclaration(n)
    );
}

// ---------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------

export function analyzeSource(fileName: string, text: string): SkipSite[] {
    // Parse with the grammar the extension implies: `<T>` is a type
    // assertion in .ts and a JSX element in .tsx, so the wrong ScriptKind
    // yields an error-recovered AST in which a skip can simply vanish.
    const kind = fileName.endsWith('x')
        ? /\.[cm]?jsx$/.test(fileName)
            ? ts.ScriptKind.JSX
            : ts.ScriptKind.TSX
        : /\.[cm]?js$/.test(fileName)
          ? ts.ScriptKind.JS
          : ts.ScriptKind.TS;
    const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, kind);

    const bound = boundNames(sf);
    const consts = fileScopeConsts(sf, bound);
    const functionNames = functionBindings(sf);

    const sites: SkipSite[] = [];
    /** Enclosing test-construct scopes, innermost last. */
    const stack: SkipSite['scope'][] = [];
    /** Enclosing inline `test.describe` callbacks, for the diagnosis. */
    const describeStack: ts.Node[] = [];
    /**
     * A `process.env.CI` write that runs while the file is being
     * COLLECTED makes every proof in it meaningless. Writes inside a test
     * body or a hook run long afterwards and are irrelevant.
     */
    let envWrittenAtCollectionTime = false;

    const scopeNow = (): SkipSite['scope'] => (stack.length ? stack[stack.length - 1] : 'file');

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

    /** Detects `process.env.CI = …`, `delete process.env.CI`, `++`/`--`. */
    const noteEnvWrite = (n: ts.Node): void => {
        if (!isProcessEnvCI(n)) return;
        let child: ts.Node = n;
        let parent = n.parent as ts.Node | undefined;
        while (parent && ts.isParenthesizedExpression(parent)) {
            child = parent;
            parent = parent.parent;
        }
        if (parent === undefined) return;
        const isAssign =
            ts.isBinaryExpression(parent) &&
            parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
            parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
            parent.left === child;
        const isDelete = ts.isDeleteExpression(parent);
        const isIncDec =
            (ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent)) &&
            (parent.operator === ts.SyntaxKind.PlusPlusToken ||
                parent.operator === ts.SyntaxKind.MinusMinusToken);
        if ((isAssign || isDelete || isIncDec) && CHECKED_SCOPES.has(scopeNow())) {
            envWrittenAtCollectionTime = true;
        }
    };

    /** A string, a template, a `+` of one, or a one-hop const to one. */
    const isStringish = (e: ts.Expression, depth = 0): boolean => {
        const cur = unwrap(e);
        if (
            ts.isStringLiteral(cur) ||
            ts.isNoSubstitutionTemplateLiteral(cur) ||
            ts.isTemplateExpression(cur)
        ) {
            return true;
        }
        if (ts.isBinaryExpression(cur) && cur.operatorToken.kind === ts.SyntaxKind.PlusToken) {
            return isStringish(cur.left, depth) || isStringish(cur.right, depth);
        }
        if (depth === 0 && ts.isIdentifier(cur)) {
            const init = consts.get(cur.text);
            if (init) return isStringish(init, depth + 1);
        }
        return false;
    };

    const classify = (
        node: ts.CallExpression,
        callee: string,
        args: ts.NodeArray<ts.Expression>,
    ): SkipSite => {
        const last = args.length >= 2 ? unwrap(args[args.length - 1]) : undefined;

        // WHITELIST, not blacklist. A site is only reported when its
        // first argument is RECOGNISABLY A CONDITION. Everything else —
        // a title, a callback, a call, a member read, an imported name —
        // is left alone.
        //
        // The previous shape asked "is this a declaration?" and reported
        // whatever it could not prove was one, so every unfamiliar way of
        // writing a title or a callback became a red `main`:
        // `test.skip(disabledTitle(), body)`, `test.skip(namedCallback,
        // 'msg')`, an imported title. Inverting it makes the failure mode
        // a miss instead. (Review findings: false positives.)
        const isConditionShape = (e: ts.Expression, depth = 0): boolean => {
            const cur = unwrap(e);
            // `!x`
            if (
                ts.isPrefixUnaryExpression(cur) &&
                cur.operator === ts.SyntaxKind.ExclamationToken
            ) {
                return true;
            }
            // `a && b`, `a || b`, `a === b`, `a > b`, ...
            if (ts.isBinaryExpression(cur)) {
                const k = cur.operatorToken.kind;
                return (
                    k === ts.SyntaxKind.AmpersandAmpersandToken ||
                    k === ts.SyntaxKind.BarBarToken ||
                    k === ts.SyntaxKind.QuestionQuestionToken ||
                    k === ts.SyntaxKind.EqualsEqualsToken ||
                    k === ts.SyntaxKind.EqualsEqualsEqualsToken ||
                    k === ts.SyntaxKind.ExclamationEqualsToken ||
                    k === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
                    k === ts.SyntaxKind.LessThanToken ||
                    k === ts.SyntaxKind.GreaterThanToken ||
                    k === ts.SyntaxKind.LessThanEqualsToken ||
                    k === ts.SyntaxKind.GreaterThanEqualsToken ||
                    k === ts.SyntaxKind.InKeyword ||
                    k === ts.SyntaxKind.InstanceOfKeyword
                );
            }
            // `true` / `false`
            if (
                cur.kind === ts.SyntaxKind.TrueKeyword ||
                cur.kind === ts.SyntaxKind.FalseKeyword
            ) {
                return true;
            }
            // A local name bound to something that is itself a condition.
            // An identifier bound to a FUNCTION is the callback form; an
            // identifier this file does not bind at all is imported and
            // could be either, so neither is reported.
            if (depth === 0 && ts.isIdentifier(cur)) {
                if (functionNames.has(cur.text)) return false;
                const init = consts.get(cur.text);
                if (init) return isConditionShape(init, depth + 1);
                // Bound locally but not resolvable (a `let`, a shadowed
                // name): still a condition slot, and the `let` case is one
                // this gate exists to catch.
                return bound.has(cur.text) && !isStringish(cur);
            }
            return false;
        };

        const form: SkipSite['form'] =
            args.length === 0
                ? 'noarg'
                : isInlineFunction(unwrap(args[0]))
                  ? 'callback'
                  : isConditionShape(args[0])
                    ? 'conditional'
                    : 'declaration';

        let stmt: ts.Node = node;
        while (stmt.parent && !ts.isStatement(stmt)) stmt = stmt.parent;

        return {
            file: fileName,
            line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
            callee,
            form,
            scope: scopeNow(),
            condition: form === 'conditional' ? args[0].getText(sf).replace(/\s+/g, ' ') : '',
            ciNeutral: form === 'conditional' ? isCiNeutral(args[0], consts) : true,
            allowMarker: hasAllowMarker(text, stmt),
            guardedByThrowingBeforeAll:
                describeStack.length > 0 &&
                describeHasThrowingBeforeAll(describeStack[describeStack.length - 1]),
        };
    };

    const visit = (node: ts.Node): void => {
        noteEnvWrite(node);

        let construct: SkipSite['scope'] | null = null;
        let isDescribe = false;

        if (ts.isCallExpression(node)) {
            const callee = calleeName(node.expression) ?? '';
            const args = node.arguments;
            const hasInlineCallback = args.some(isInlineFunction);

            if (CALLEE_DESCRIBE.test(callee) && hasInlineCallback) {
                construct = 'describe';
                isDescribe = true;
            } else if (CALLEE_BEFORE_ALL.test(callee) && hasInlineCallback) {
                construct = 'beforeAll';
            } else if (CALLEE_AFTER_ALL.test(callee) && hasInlineCallback) {
                construct = 'afterAll';
            } else if (CALLEE_EACH_HOOK.test(callee) && hasInlineCallback) {
                construct = 'eachHook';
            } else if (callee === 'test.step' && hasInlineCallback) {
                construct = 'step';
            } else if (CALLEE_TEST.test(callee) && args.length >= 2 && hasInlineCallback) {
                construct = 'test';
            }

            if (CALLEE_SKIP.test(callee)) {
                sites.push(classify(node, callee, args));
            }
        }

        // Only the CALLBACK argument of a construct is inside it. Its
        // other arguments — the title above all — are evaluated eagerly,
        // at collection time, in the ENCLOSING scope.
        if (construct !== null && ts.isCallExpression(node)) {
            if (isDescribe) describeStack.push(node);
            visit(node.expression);
            for (const arg of node.arguments) {
                if (isInlineFunction(arg)) {
                    stack.push(construct);
                    for (const param of arg.parameters) visit(param);
                    if (arg.body) visit(arg.body);
                    stack.pop();
                } else {
                    visit(arg);
                }
            }
            if (isDescribe) describeStack.pop();
            return;
        }

        // Any other function. Where its skips fire depends on where it is
        // CALLED, which this gate deliberately does not follow — so its
        // contents are recorded as `closure` and never reported.
        if (isAnyFunction(node)) {
            stack.push('closure');
            ts.forEachChild(node, visit);
            stack.pop();
            return;
        }

        ts.forEachChild(node, visit);
    };

    visit(sf);

    if (envWrittenAtCollectionTime) {
        for (const site of sites) {
            if (site.form === 'conditional') site.ciNeutral = false;
        }
    }
    return sites;
}

/** Checked-scope conditional skips that are not provably inert under CI. */
export function violations(sites: SkipSite[]): SkipSite[] {
    return sites.filter(
        (s) =>
            s.form === 'conditional' &&
            CHECKED_SCOPES.has(s.scope) &&
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
        '    Fix: append `&& !process.env.CI` to the condition, or, when skipping under\n' +
        '    CI really is intended, add a `// ci-skip-ok: <reason>` comment.'
    );
}

// ---------------------------------------------------------------------
// Fixtures
//
// Two groups, and the second is the larger one on purpose: this gate runs
// inside a REQUIRED status check, so "correct code stays green" is the
// property that has to be nailed down hardest.
// ---------------------------------------------------------------------

/** The shape that shipped broken. */
const HOLED = `
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

const MUST_REPORT: ReadonlyArray<readonly [string, string]> = [
    ['holed', HOLED],
    [
        'file scope',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.skip(!HAS_TOOL, 'tool missing');
test('asserts something', async () => {});
`,
    ],
    [
        // Same blast radius, different timing.
        'beforeAll body',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.beforeAll(() => {
        test.skip(!HAS_TOOL, 'tool missing');
    });
    test('asserts something', async () => {});
});
`,
    ],
    [
        // Referencing process.env.CI is not enough: this skips BECAUSE of CI.
        'inverted CI condition',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL || !!process.env.CI, 'tool missing');
});
`,
    ],
    [
        // A shadowed name must not resolve to the outer, CI-guarded one.
        'shadowed const',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const SKIP = !HAS_TOOL && !process.env.CI;
test.describe('gate', () => {
    const SKIP = !HAS_TOOL;
    test.skip(SKIP, 'tool missing');
});
`,
    ],
    [
        // A CI-safe initialiser is not a CI-safe value when it is `let`.
        'mutable binding',
        `
import { test } from '@playwright/test';
let LOCAL_ONLY = !process.env.CI;
LOCAL_ONLY = true;
test.describe('gate', () => {
    test.skip(LOCAL_ONLY, 'tool missing');
});
`,
    ],
    [
        // Punctuation that changes the text but not what is called.
        'parenthesised callee',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    (test.skip)(!HAS_TOOL, 'tool missing');
});
`,
    ],
    [
        'element-access callee',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test['skip'](!HAS_TOOL, 'tool missing');
});
`,
    ],
    [
        // The marker has to be a COMMENT; in the description it reads as
        // an ordinary message and must not buy the exemption.
        'marker smuggled into the description',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL, 'ci-skip-ok: tool missing');
});
`,
    ],
    [
        // A stray env poke left in a describe body runs during collection.
        'CI written in a describe body',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    process.env.CI = '';
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
});
`,
    ],
    [
        'CI deleted at file scope',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
delete process.env.CI;
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
});
`,
    ],
    [
        // A skip in a test's TITLE is evaluated eagerly, at collection.
        'skip in a test title',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test(\`\${(test.skip(!HAS_TOOL, 'tool missing'), 'probe')}\`, async () => {});
});
`,
    ],
    [
        'fixme is checked too',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.fixme(!HAS_TOOL, 'tool missing');
});
`,
    ],
];

/**
 * Correct code. A hit here is a red `main` for no reason, which this gate
 * treats as worse than the miss it would have bought.
 */
const MUST_BE_CLEAN: ReadonlyArray<readonly [string, string]> = [
    [
        'the fixed shape, as report-unmeasured-pdf.spec.ts has it',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
    test.beforeAll(() => {
        if (!HAS_TOOL) throw new Error('required in CI');
    });
});
`,
    ],
    [
        'one-hop const resolution',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const LOCAL_ONLY = !HAS_TOOL && !process.env.CI;
test.describe('gate', () => {
    test.skip(LOCAL_ONLY, 'tool missing');
});
`,
    ],
    [
        'process.env.CI === undefined',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL && process.env.CI === undefined, 'tool missing');
});
`,
    ],
    [
        // The repo's soft-gate idiom, 48 sites.
        'per-test runtime skips',
        `
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
`,
    ],
    [
        'beforeEach with a fixture-dependent condition',
        `
import { test } from '@playwright/test';
test.describe('soft', () => {
    test.beforeEach(async ({ page }) => {
        test.skip(await page.evaluate(() => false), 'not applicable here');
    });
    test('a', async () => {});
});
`,
    ],
    [
        'the escape hatch, as a leading comment',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    // ci-skip-ok: covered by the API-side integration suite instead.
    test.skip(!HAS_TOOL, 'tool missing');
});
`,
    ],
    [
        'the escape hatch, as a trailing comment',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL, 'tool missing'); // ci-skip-ok: covered elsewhere
});
`,
    ],
    [
        // The first skip is exempt; the SECOND must not inherit the marker
        // — and the second is CI-guarded, so the file is clean either way.
        'a trailing marker does not bleed onto the next statement',
        `
import { test } from '@playwright/test';
const IS_LINUX = false;
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!IS_LINUX, 'unsupported'); // ci-skip-ok: covered elsewhere
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
});
`,
    ],
    [
        // An unrelated `process` read must not disarm a correct guard.
        'process.platform read',
        `
import { test } from '@playwright/test';
const IS_LINUX = process.platform === 'linux';
test.describe('gate', () => {
    test.skip(!IS_LINUX && !process.env.CI, 'unsupported');
});
`,
    ],
    [
        'reading several env vars',
        `
import { test } from '@playwright/test';
const { PLAYWRIGHT_BASE_URL } = process.env;
const HAS_TOOL = Boolean(PLAYWRIGHT_BASE_URL);
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'unsupported');
});
`,
    ],
    [
        'making an implicit global explicit',
        `
import { test } from '@playwright/test';
import process from 'node:process';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
});
`,
    ],
    [
        // Writing an unrelated env var, inside a test, long after collection.
        'unrelated env write inside a test',
        `
import { test } from '@playwright/test';
const MISSING = true;
test.describe('gate', () => {
    test.skip(MISSING && !process.env.CI, 'tool missing');
    test('date rendering', async () => {
        process.env.TZ = 'UTC';
    });
});
`,
    ],
    [
        'writing CI itself, inside a test',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
    test('CI parsing', async () => {
        process.env.CI = '1';
    });
});
`,
    ],
    [
        'a declaration whose title is a constant',
        `
import { test } from '@playwright/test';
const title = 'temporarily disabled';
test.describe('gate', () => {
    test.skip(title, async () => {});
});
`,
    ],
    [
        'a declaration whose title is computed',
        `
import { test } from '@playwright/test';
const ticket = 'M12-4';
const title = 'temporarily disabled: ' + ticket;
test.describe('gate', () => {
    test.skip(title, async () => {});
});
`,
    ],
    [
        'a declaration whose title came from a const object',
        `
import { test } from '@playwright/test';
const titles = { disabled: 'temporarily disabled' } as const;
test.describe('gate', () => {
    test.skip(titles.disabled, async () => {});
});
`,
    ],
    [
        'a declaration whose body was extracted',
        `
import { test } from '@playwright/test';
const disabledBody = async () => {};
test.describe('gate', () => {
    test.skip('temporarily disabled', disabledBody);
});
`,
    ],
    [
        'a declaration whose title AND body are both indirect',
        `
import { test } from '@playwright/test';
import { disabledBody } from './disabled-body';
const titles = { disabled: 'temporarily disabled' } as const;
test.describe('gate', () => {
    test.skip(titles.disabled, disabledBody);
});
`,
    ],
    [
        // Playwright's documented fixture-aware form. Excluded by design;
        // see the limitations list in the file header.
        'the callback form',
        `
import { test } from '@playwright/test';
test.describe('gate', () => {
    test.skip(({ browserName }) => browserName !== 'webkit', 'Safari-only');
});
`,
    ],
    [
        // Not followed to its call sites, in either direction.
        'a helper called from a test body',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
test.describe('gate', () => {
    const skipIfMissing = () => test.skip(!HAS_TOOL, 'tool missing');
    test('probe', async () => {
        skipIfMissing();
    });
});
`,
    ],
    [
        'a describe body passed by name',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
function suite() {
    test.skip(!HAS_TOOL, 'tool missing');
    test('gate', async () => {});
}
test.describe('gate', suite);
`,
    ],
    [
        'per-test helpers tidied into an object',
        `
import { test } from '@playwright/test';
test.describe('gate', () => {
    const soft = {
        skipIfMissing(missing: boolean) {
            test.skip(missing, 'not applicable');
        },
    };
    test('probe', async () => soft.skipIfMissing(false));
});
`,
    ],
    [
        // Two independent suites using the same general helper name.
        'same helper name in two suites',
        `
import { test } from '@playwright/test';
const ready = false;
test.describe('a', () => {
    const setup = () => test.skip(!ready, 'seed');
    test('x', async () => { setup(); });
});
test.describe('b', () => {
    const setup = () => { void 0; };
    setup();
});
`,
    ],
    [
        // A function value chosen in a reduce is never called here.
        'a function value in a reduce seed',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const handlers: (() => void)[] = [];
test.describe('soft gate', () => {
    const selected = handlers.reduce<() => void>(
        (chosen, next) => next ?? chosen,
        () => test.skip(!HAS_TOOL, 'not applicable'),
    );
    test('probe', async () => selected());
});
`,
    ],
    [
        // The callback form extracted to a name.
        'a named callback condition',
        `
import { test } from '@playwright/test';
const skipOutsideWebKit = ({ browserName }: { browserName: string }) =>
    browserName !== 'webkit';
test.describe('webkit behavior', () => {
    test.skip(skipOutsideWebKit, 'WebKit only');
});
`,
    ],
    [
        // A declaration whose title is produced by a call.
        'a declaration whose title is computed by a call',
        `
import { test } from '@playwright/test';
const disabledTitle = () => 'temporarily disabled';
const disabledBody = async () => {};
test.describe('handoff', () => {
    test.skip(disabledTitle(), disabledBody);
});
`,
    ],
    [
        // afterAll runs AFTER the group; restoring CI there is correct.
        'afterAll restoring process.env.CI',
        `
import { test } from '@playwright/test';
const HAS_TOOL = false;
const savedCI = process.env.CI;
test.describe('gate', () => {
    test.skip(!HAS_TOOL && !process.env.CI, 'tool missing');
    test.afterAll(() => {
        if (savedCI === undefined) delete process.env.CI;
        else process.env.CI = savedCI;
    });
});
`,
    ],
    [
        'a parameterised suite built with forEach',
        `
import { test } from '@playwright/test';
const TOOLS = [{ missing: true }];
TOOLS.forEach(({ missing }) => {
    test.skip(missing, 'tool missing');
    test('gate', async () => {});
});
`,
    ],
];

// ---------------------------------------------------------------------
// Spec bodies
// ---------------------------------------------------------------------

/**
 * Every TS/JS source file under `e2e/`, not just the ones Playwright
 * collects: matching only `*.spec.ts` would leave a `foo.test.ts`
 * collected by the runner but invisible here.
 */
const SCANNED_FILE = /\.[cm]?[jt]sx?$/;
const DECLARATION_FILE = /\.d\.[cm]?ts$/;

function scannedFiles(root: string): string[] {
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
    test('analyzer verdicts', () => {
        // Positive control — the shape that shipped broken must be caught,
        // and must be diagnosed as a dead beforeAll guard.
        const holed = violations(analyzeSource('holed.spec.ts', HOLED));
        expect(
            holed.map((v) => `${v.line}:${v.condition}`),
            'the holed fixture must produce exactly one violation',
        ).toEqual(['8:!HAS_TOOL']);
        expect(holed[0].guardedByThrowingBeforeAll).toBe(true);

        for (const [name, source] of MUST_REPORT) {
            expect(
                violations(analyzeSource(`${name}.spec.ts`, source)).length,
                `MUST BE REPORTED: ${name}`,
            ).toBeGreaterThan(0);
        }

        // The half that keeps `main` green. A hit here is a false positive
        // on correct code, which this gate treats as worse than a miss.
        for (const [name, source] of MUST_BE_CLEAN) {
            expect(
                violations(analyzeSource(`${name}.spec.ts`, source)).map(describeViolation),
                `MUST BE CLEAN: ${name}`,
            ).toEqual([]);
        }

        // The classifier must still recognise the runtime idioms as
        // runtime, otherwise "0 violations" above would be true for the
        // wrong reason.
        const soft = analyzeSource('soft.spec.ts', MUST_BE_CLEAN[3][1]);
        expect(soft.map((s) => `${s.form}/${s.scope}`).sort()).toEqual([
            'conditional/test',
            'declaration/describe',
            'noarg/test',
        ]);

        // Both halves are non-empty, so neither loop can pass vacuously,
        // and the correct-code half is the larger one by policy.
        expect(MUST_REPORT.length).toBeGreaterThan(5);
        expect(MUST_BE_CLEAN.length).toBeGreaterThan(MUST_REPORT.length);
    });

    test('no e2e spec can be silently skipped in CI', () => {
        // Scan unit: every TS/JS source under apps/web/e2e/, recursively
        // (this file's own directory), parsed with the TypeScript AST —
        // not grepped, so comments and string literals cannot trip it.
        const e2eRoot = dirname(test.info().file);
        const files = scannedFiles(e2eRoot);

        // Anti-vacuity without encoding a file count: this very file must
        // be among the results. A broken walk cannot satisfy that, and
        // consolidating or deleting specs cannot break it.
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
        expect(bad.map(describeViolation).join('\n\n'), 'checked-scope skip(s) not CI-proof').toBe(
            '',
        );
    });
});

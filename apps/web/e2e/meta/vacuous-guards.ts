/**
 * Vacuous-guard analyzer — the second half of the hermetic meta-gate in
 * `../skip-reachability.spec.ts`, which registers the tests that run it.
 * (It lives in a non-spec module so Playwright does not collect it, and is
 * driven from that spec so frontend-ci's hermetic step runs it too.)
 *
 * THE DEFECT THIS EXISTS FOR
 * --------------------------
 *
 *     if (await page.locator('svg.lucide-trash2').isVisible()) {
 *         await button.click();
 *         await expect(dialog).toBeVisible();
 *     }
 *
 * When the selector stops matching, the test passes while asserting
 * nothing. lucide-react 1.x renamed that icon class and six tests went
 * vacuous at once; two of them were hiding real breakage and were found by
 * luck (commit a8ea444). The suite had ~165 such probes when this gate was
 * written. A test that cannot fail certifies nothing.
 *
 * THE RULES (syntax only, per function body)
 * ------------------------------------------
 * A "probe" is a call `.isVisible() .isHidden() .isEnabled() .isDisabled()
 * .isChecked() .isEditable() .count() .ok()` or a `.length` read — or an
 * identifier whose declaration in an enclosing function was initialised
 * with an expression containing one (`const has = await x.isVisible()`).
 *
 * An "assertion" is a call of `expect` / `expect.*`, a `throw`, or a
 * `test.skip|fixme|fail(...)` WITH a reason (see V3).
 *
 *   V1  `if (<probe>)` where one branch calls `expect` and the other has
 *       no assertion at all (a missing `else` has none). The
 *       non-asserting path is the silent pass. A guard whose only
 *       asserting branch is a `throw` / reasoned skip is a loud failure or
 *       an announced skip, not a silent pass, and is not reported. An either/or (`if (p) expect(a) else expect(b)`) is fine —
 *       something is asserted on every path.
 *   V2  `if (<probe>)` whose branch contains a `return` and no assertion,
 *       in a function that calls `expect`: an early exit that skips every
 *       assertion after it.
 *   V3  `test.skip()` / `test.fixme()` with no reason string, anywhere.
 *       A runtime skip is legitimate only when it says why, in the call,
 *       so the report shows it: `test.skip(true, 'why')`.
 *   V4  `try { …expect… } catch { … }` whose catch neither rethrows nor
 *       asserts, and `<…expect…>.catch(…)`: the assertion is swallowed.
 *
 *   V5  a `test(title, fn)` whose body contains no assertion at all and
 *       calls no function that might assert (a same-file function that
 *       does, or any imported name). Clicking around and ending is a
 *       smoke test of nothing: the guarded-action version of V1.
 *
 * ESCAPE HATCH
 * ------------
 * `// vacuous-guard-ok: <reason>` in a comment on or directly above the
 * reported statement. Every use is listed in the gate's output count, so
 * the allowlist stays visible.
 *
 * WHAT THIS DOES NOT CATCH — deliberately (same posture as the skip gate:
 * it runs inside a REQUIRED check, so a false positive costs more than a
 * miss)
 *   - Guards on data that is not a probe (`if (projectId)`, `if (x === y)`,
 *     `if (flag)` where `flag` is a parameter or a module constant).
 *   - Ternaries and `&&`-expression statements (`cond && expect(...)`).
 *   - Probes in a helper's caller (no inter-procedural analysis).
 *   - `expect(a || b).toBeTruthy()` — weak, but it asserts something.
 *   - `.catch(() => false)` on a probe (that is how probes are written);
 *     only a `.catch` whose RECEIVER contains `expect` is reported.
 */
import * as ts from 'typescript';

export interface VacuousSite {
    file: string;
    line: number;
    rule: 'V1' | 'V2' | 'V3' | 'V4' | 'V5';
    text: string;
    allowed: boolean;
    reason: string;
}

const PROBE_METHODS = new Set([
    'isVisible',
    'isHidden',
    'isEnabled',
    'isDisabled',
    'isChecked',
    'isEditable',
    'count',
    'ok',
]);
const ALLOW_MARKER = /vacuous-guard-ok:\s*(\S.*?)\s*(\*\/)?$/m;

function unwrap(node: ts.Expression): ts.Expression {
    let cur = node;
    for (;;) {
        if (ts.isParenthesizedExpression(cur)) cur = cur.expression;
        else if (ts.isNonNullExpression(cur)) cur = cur.expression;
        else if (ts.isAsExpression(cur)) cur = cur.expression;
        else if (ts.isAwaitExpression(cur)) cur = cur.expression;
        else return cur;
    }
}

function calleeName(expr: ts.Expression): string | null {
    const cur = unwrap(expr);
    if (ts.isIdentifier(cur)) return cur.text;
    if (ts.isPropertyAccessExpression(cur)) {
        const left = calleeName(cur.expression);
        return left === null ? null : `${left}.${cur.name.text}`;
    }
    return null;
}

function isFunctionLike(n: ts.Node): n is ts.FunctionLikeDeclaration {
    return (
        ts.isArrowFunction(n) ||
        ts.isFunctionExpression(n) ||
        ts.isFunctionDeclaration(n) ||
        ts.isMethodDeclaration(n)
    );
}

/** Walk `node` without descending into nested function bodies. */
function walkShallow(node: ts.Node, fn: (n: ts.Node) => boolean | void): void {
    const visit = (n: ts.Node): void => {
        if (fn(n) === true) return;
        if (n !== node && isFunctionLike(n)) return;
        ts.forEachChild(n, visit);
    };
    visit(node);
}

/** Does `node` contain a probe call / `.length` read (nested fns included)? */
function containsDirectProbe(node: ts.Node): boolean {
    let found = false;
    const visit = (n: ts.Node): void => {
        if (found) return;
        if (
            ts.isCallExpression(n) &&
            ts.isPropertyAccessExpression(n.expression) &&
            PROBE_METHODS.has(n.expression.name.text)
        ) {
            found = true;
            return;
        }
        if (ts.isPropertyAccessExpression(n) && n.name.text === 'length') {
            found = true;
            return;
        }
        ts.forEachChild(n, visit);
    };
    visit(node);
    return found;
}

function isSkipCall(n: ts.Node): n is ts.CallExpression {
    return ts.isCallExpression(n) && /^test\.(skip|fixme|fail)$/.test(calleeName(n.expression) ?? '');
}

function skipHasReason(call: ts.CallExpression): boolean {
    // `test.skip(cond, 'reason')` / `test.skip(true, why)`. One argument
    // alone is a condition (or nothing), never a reason. A literal reason
    // must be non-blank; any other expression (a constant, a template, a
    // call) is accepted — resolving it is not worth a false positive.
    if (call.arguments.length === 1) {
        // Playwright's `test.skip(description)` / `test.fixme(description)`:
        // a lone non-blank string is a reason; a lone condition is not.
        const only = unwrap(call.arguments[0]);
        if (ts.isStringLiteral(only) || ts.isNoSubstitutionTemplateLiteral(only)) return only.text.trim().length > 0;
        return ts.isTemplateExpression(only);
    }
    if (call.arguments.length < 2) return false;
    const last = unwrap(call.arguments[call.arguments.length - 1]);
    if (ts.isStringLiteral(last) || ts.isNoSubstitutionTemplateLiteral(last)) {
        return last.text.trim().length > 0;
    }
    return true;
}

/** `test.skip('title', body)` — the declaration form, body inline or by name. */
function isDeclarationForm(call: ts.CallExpression): boolean {
    const args = call.arguments;
    if (args.length < 2) return false;
    const last = unwrap(args[args.length - 1]);
    if (isFunctionLike(last)) return true;
    const first = unwrap(args[0]);
    return (
        args.length === 2 &&
        (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first) || ts.isTemplateExpression(first)) &&
        ts.isIdentifier(last)
    );
}

/**
 * Callbacks that run only if something happens later (an event, a matched
 * route). An `expect` inside one is not an assertion the test is
 * guaranteed to make (Codex R1 M5).
 */
const DEFERRED_METHODS = new Set(['on', 'once', 'addListener', 'prependListener', 'route', 'exposeFunction', 'exposeBinding']);

function isDeferredCallback(n: ts.Node): boolean {
    const p = n.parent;
    return (
        p !== undefined &&
        ts.isCallExpression(p) &&
        p.arguments.some((a) => a === n) &&
        ts.isPropertyAccessExpression(p.expression) &&
        DEFERRED_METHODS.has(p.expression.name.text)
    );
}

function isExpectCall(n: ts.Node): boolean {
    if (!ts.isCallExpression(n)) return false;
    // `expect(x).toBe(…)` — the root of the callee chain is `expect(…)` or `expect.poll(…)`.
    let cur: ts.Expression = n.expression;
    for (;;) {
        cur = unwrap(cur);
        if (ts.isIdentifier(cur)) return cur.text === 'expect';
        if (ts.isPropertyAccessExpression(cur)) cur = cur.expression;
        else if (ts.isCallExpression(cur)) cur = cur.expression;
        else return false;
    }
}

/**
 * Assertions, throws, and reasoned skips — nested callbacks included
 * (expect.poll bodies, steps, forEach), except deferred ones (event
 * handlers, routes).
 */
function asserts(node: ts.Node | undefined): boolean {
    if (!node) return false;
    let found = false;
    const visit = (n: ts.Node): void => {
        if (found) return;
        if (isFunctionLike(n) && isDeferredCallback(n)) return;
        if (ts.isThrowStatement(n) || isExpectCall(n) || (isSkipCall(n) && skipHasReason(n))) {
            found = true;
            return;
        }
        ts.forEachChild(n, visit);
    };
    visit(node);
    return found;
}

function containsReturn(node: ts.Node | undefined): boolean {
    if (!node) return false;
    let found = false;
    walkShallow(node, (n) => {
        if (found) return true;
        if (ts.isReturnStatement(n)) found = true;
        return undefined;
    });
    return found;
}

function containsExpect(node: ts.Node): boolean {
    let found = false;
    const visit = (n: ts.Node): void => {
        if (found) return;
        if (isExpectCall(n)) {
            found = true;
            return;
        }
        ts.forEachChild(n, visit);
    };
    visit(node);
    return found;
}

export function analyzeVacuous(fileName: string, text: string): VacuousSite[] {
    const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const out: VacuousSite[] = [];

    const markerFor = (node: ts.Node): string | null => {
        let stmt: ts.Node = node;
        while (stmt.parent && !ts.isStatement(stmt)) stmt = stmt.parent;
        const ranges = [
            ...(ts.getLeadingCommentRanges(text, stmt.getFullStart()) ?? []),
            ...(ts.getTrailingCommentRanges(text, stmt.getStart(sf)) ?? []),
        ];
        // The first line of the statement may also carry it as a trailing comment.
        const lineEnd = text.indexOf('\n', stmt.getStart(sf));
        const firstLine = text.slice(stmt.getStart(sf), lineEnd === -1 ? undefined : lineEnd);
        const candidates = ranges.map((r) => text.slice(r.pos, r.end));
        const inline = firstLine.match(/\/\/.*$/);
        if (inline) candidates.push(inline[0]);
        for (const c of candidates) {
            const m = c.match(ALLOW_MARKER);
            if (m) return m[1];
        }
        return null;
    };

    // Names that may assert. `localAsserting`: same-file functions that
    // contain an assertion or call one (fixed point) — used by V1/V2, where
    // a guarded call to such a helper is a guarded assertion. `mayAssert`:
    // the same plus every imported binding — used by V5 only, where an
    // unfollowed import must count as "might assert" (a miss, never a false
    // positive). Imports are NOT assertions for V1: a guarded imported call
    // is as likely to be setup as a check.
    const importedNames = new Set<string>();
    for (const stmt of sf.statements) {
        if (ts.isImportDeclaration(stmt) && stmt.importClause) {
            const c = stmt.importClause;
            if (c.name) importedNames.add(c.name.text);
            const nb = c.namedBindings;
            if (nb && ts.isNamedImports(nb)) for (const e of nb.elements) importedNames.add(e.name.text);
            if (nb && ts.isNamespaceImport(nb)) importedNames.add(nb.name.text);
        }
    }
    importedNames.delete('test');
    importedNames.delete('expect');
    const fixedPoint = (seed: ReadonlySet<string>): Set<string> => {
        const names = new Set(seed);
        for (let prev = -1; prev !== names.size; ) {
            prev = names.size;
            const visitFns = (n: ts.Node): void => {
                const fnName =
                    ts.isFunctionDeclaration(n) && n.name
                        ? n.name.text
                        : ts.isVariableDeclaration(n) &&
                            ts.isIdentifier(n.name) &&
                            n.initializer &&
                            isFunctionLike(unwrap(n.initializer))
                          ? n.name.text
                          : null;
                if (fnName && !names.has(fnName) && (asserts(n) || callsMayAssert(n, names))) names.add(fnName);
                ts.forEachChild(n, visitFns);
            };
            visitFns(sf);
        }
        return names;
    };
    const localAsserting = fixedPoint(new Set());
    const mayAssert = fixedPoint(importedNames);
    const branchExpects = (n: ts.Node | undefined): boolean =>
        n !== undefined && (containsExpect(n) || callsMayAssert(n, localAsserting));
    const branchAsserts = (n: ts.Node | undefined): boolean =>
        n !== undefined && (asserts(n) || callsMayAssert(n, localAsserting));

    const report = (node: ts.Node, rule: VacuousSite['rule'], what: string): void => {
        const reason = markerFor(node);
        out.push({
            file: fileName,
            line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
            rule,
            text: what,
            allowed: reason !== null,
            reason: reason ?? '',
        });
    };

    /**
     * Lexical scopes (functions and blocks), innermost last: name -> "was
     * initialised with a probe". The NEAREST binding decides, so a
     * non-probe binding shadows an outer probe one (Codex R1 M3).
     */
    const scopes: Array<Map<string, boolean>> = [new Map()];
    const isProbeName = (name: string): boolean => {
        for (let i = scopes.length - 1; i >= 0; i--) {
            const v = scopes[i].get(name);
            if (v !== undefined) return v;
        }
        return false;
    };

    const conditionHasProbe = (cond: ts.Expression): boolean => {
        if (containsDirectProbe(cond)) return true;
        let found = false;
        const visit = (n: ts.Node): void => {
            if (found) return;
            if (ts.isIdentifier(n) && isProbeName(n.text)) {
                // Only a READ of the name, not a property name like `x.has`.
                const p = n.parent;
                if (!(ts.isPropertyAccessExpression(p) && p.name === n)) found = true;
                return;
            }
            ts.forEachChild(n, visit);
        };
        visit(cond);
        return found;
    };

    const visit = (node: ts.Node): void => {
        const pushed = isFunctionLike(node) || ts.isBlock(node) || ts.isCatchClause(node) ||
            ts.isForStatement(node) || ts.isForOfStatement(node) || ts.isForInStatement(node);
        if (pushed) {
            const scope = new Map<string, boolean>();
            // Parameters bind in the function's scope and shadow outer names.
            if (isFunctionLike(node)) {
                for (const prm of node.parameters) if (ts.isIdentifier(prm.name)) scope.set(prm.name.text, false);
            }
            scopes.push(scope);
        }

        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
            const probe =
                node.initializer !== undefined &&
                (containsDirectProbe(node.initializer) || conditionHasProbe(node.initializer));
            scopes[scopes.length - 1].set(node.name.text, probe);
        }

        if (ts.isIfStatement(node) && conditionHasProbe(node.expression)) {
            const cond = node.expression.getText(sf).replace(/\s+/g, ' ').slice(0, 80);
            const thenAsserts = branchAsserts(node.thenStatement);
            const elseAsserts = branchAsserts(node.elseStatement);
            const thenExpects = branchExpects(node.thenStatement);
            const elseExpects = branchExpects(node.elseStatement);
            let fn: ts.Node | undefined = node.parent;
            while (fn && !isFunctionLike(fn)) fn = fn.parent;
            if ((thenExpects && !elseAsserts) || (elseExpects && !thenAsserts)) {
                report(node, 'V1', `if (${cond}) guards assertions on one path only`);
            } else if (
                fn !== undefined &&
                (containsExpect(fn) || callsMayAssert(fn, localAsserting)) &&
                ((containsReturn(node.thenStatement) && !thenAsserts) ||
                    (containsReturn(node.elseStatement) && !elseAsserts))
            ) {
                report(node, 'V2', `if (${cond}) returns early without asserting`);
            }
        }

        if (isSkipCall(node) && !skipHasReason(node)) {
            const callee = calleeName(node.expression);
            // Declaration form `test.skip('title', fn)` is not a runtime skip.
            if (!isDeclarationForm(node) && callee !== 'test.fail') {
                report(node, 'V3', `${callee}(${node.arguments.map((a) => a.getText(sf)).join(', ')}) without a reason`);
            }
        }

        if (ts.isTryStatement(node) && node.catchClause && containsExpect(node.tryBlock)) {
            if (!asserts(node.catchClause.block)) {
                report(node, 'V4', 'try { expect… } catch swallows the assertion');
            }
        }

        if (
            ts.isCallExpression(node) &&
            ts.isPropertyAccessExpression(node.expression) &&
            node.expression.name.text === 'catch' &&
            containsExpect(node.expression.expression) &&
            // A handler that rethrows / asserts propagates the failure (Codex R1 M4).
            !node.arguments.some((a) => asserts(a))
        ) {
            report(node, 'V4', '<expect…>.catch(…) swallows the assertion');
        }

        ts.forEachChild(node, visit);
        if (pushed) scopes.pop();
    };
    visit(sf);

    const visitTests = (n: ts.Node): void => {
        if (
            ts.isCallExpression(n) &&
            /^test(\.(only|slow))?$/.test(calleeName(n.expression) ?? '') &&
            n.arguments.length >= 2
        ) {
            const body = unwrap(n.arguments[n.arguments.length - 1]);
            if (isFunctionLike(body) && !asserts(body) && !callsMayAssert(body, mayAssert)) {
                report(n, 'V5', `test ${n.arguments[0].getText(sf).slice(0, 70)} asserts nothing`);
            }
        }
        ts.forEachChild(n, visitTests);
    };
    visitTests(sf);
    return out;
}

function callsMayAssert(node: ts.Node, names: ReadonlySet<string>): boolean {
    let found = false;
    const visit = (n: ts.Node): void => {
        if (found) return;
        if (ts.isCallExpression(n)) {
            const callee = calleeName(n.expression);
            const root = callee?.split('.')[0];
            if (root && names.has(root)) {
                found = true;
                return;
            }
        }
        ts.forEachChild(n, visit);
    };
    visit(node);
    return found;
}

// ---------------------------------------------------------------------
// Fixtures (driven by skip-reachability.spec.ts)
// ---------------------------------------------------------------------

const HDR = `import { test, expect } from '@playwright/test';\n`;

export const VACUOUS_MUST_REPORT: ReadonlyArray<readonly [string, VacuousSite['rule'], string]> = [
    [
        'the lucide shape',
        'V1',
        `${HDR}test('t', async ({ page }) => {
    if (await page.locator('svg.lucide-trash2').isVisible()) {
        await expect(page.getByRole('dialog')).toBeVisible();
    }
});`,
    ],
    [
        'probe through a const with .catch',
        'V1',
        `${HDR}test('t', async ({ page }) => {
    const hasTable = await page.locator('table').isVisible().catch(() => false);
    if (hasTable) {
        expect(await page.locator('tr').count()).toBeGreaterThan(0);
    }
});`,
    ],
    [
        'count() > 0 guard',
        'V1',
        `${HDR}test('t', async ({ page }) => {
    const rows = page.locator('tr');
    if ((await rows.count()) > 0) {
        await expect(rows.first()).toContainText('x');
    }
});`,
    ],
    [
        'response.ok() guard',
        'V1',
        `${HDR}test('t', async ({ request }) => {
    const res = await request.get('/x');
    if (res.ok()) {
        expect((await res.json()).decision).toBe('defer');
    }
});`,
    ],
    [
        'length guard on data',
        'V1',
        `${HDR}test('t', async ({ request }) => {
    const vulns = await (await request.get('/v')).json();
    if (vulns.length > 0) {
        expect(vulns[0]).toHaveProperty('id');
    }
});`,
    ],
    [
        'negated probe with early return',
        'V2',
        `${HDR}test('t', async ({ page }) => {
    if (!(await page.getByRole('button').isVisible())) {
        return;
    }
    await expect(page.getByRole('dialog')).toBeVisible();
});`,
    ],
    [
        'reasonless runtime skip',
        'V3',
        `${HDR}test('t', async () => {
    const id: string | null = null;
    if (!id) {
        test.skip();
    }
});`,
    ],
    [
        'try/catch swallowing expect',
        'V4',
        `${HDR}test('t', async ({ page }) => {
    try {
        await expect(page.getByText('x')).toBeVisible();
    } catch {
        console.log('not visible');
    }
});`,
    ],
    [
        'expect(...).catch',
        'V4',
        `${HDR}test('t', async ({ page }) => {
    await expect(page.getByText('x')).toBeVisible().catch(() => {});
});`,
    ],
    [
        'a test that only clicks around',
        'V5',
        `${HDR}test('t', async ({ page }) => {
    await page.goto('/settings');
    if (await page.getByLabel('Hour').isVisible()) {
        await page.getByLabel('Hour').selectOption({ index: 9 });
    }
});`,
    ],
    [
        // Codex R1 M5: a handler that may never fire is not an assertion.
        'assertion only inside an event handler',
        'V5',
        `${HDR}test('t', async ({ page }) => {
    page.on('console', (msg) => expect(msg.text()).not.toContain('boom'));
    await page.goto('/');
});`,
    ],
    [
        // Codex R2 Low: the assertion is delegated to a same-file helper.
        'probe guarding a same-file asserting helper',
        'V1',
        `${HDR}async function expectRow(page: any) {
    await expect(page.locator('tr')).toHaveCount(1);
}
test('t', async ({ page }) => {
    if (await page.locator('tr').isVisible()) await expectRow(page);
});`,
    ],
];

export const VACUOUS_MUST_BE_CLEAN: ReadonlyArray<readonly [string, string]> = [
    [
        'unconditional assertion',
        `${HDR}test('t', async ({ page }) => {
    await expect(page.getByRole('heading')).toBeVisible();
    expect(await page.locator('tr').count()).toBe(3);
});`,
    ],
    [
        'either/or assertion on both paths',
        `${HDR}test('t', async ({ page }) => {
    if (await page.getByText('empty').isVisible()) {
        await expect(page.getByRole('button', { name: 'Create' })).toBeVisible();
    } else {
        await expect(page.locator('table')).toBeVisible();
    }
});`,
    ],
    [
        'probe guard with an explicit, reasoned skip on the other path',
        `${HDR}test('t', async ({ page }) => {
    if (!(await page.getByText('x').isVisible())) {
        test.skip(true, 'feature flag off in this build');
    }
    await expect(page.getByText('x')).toBeVisible();
});`,
    ],
    [
        'probe guard that only conditions an action',
        `${HDR}test('t', async ({ page }) => {
    if (await page.getByRole('button', { name: 'Accept cookies' }).isVisible()) {
        await page.getByRole('button', { name: 'Accept cookies' }).click();
    }
    await expect(page.getByRole('main')).toBeVisible();
});`,
    ],
    [
        'failing fast on a bad response',
        `${HDR}test('t', async ({ request }) => {
    const res = await request.get('/x');
    if (!res.ok()) throw new Error('seed failed: ' + res.status());
    expect(await res.json()).toBeTruthy();
});`,
    ],
    [
        'allowlisted with a reason',
        `${HDR}test('t', async ({ page }) => {
    // vacuous-guard-ok: banner only renders on the first visit of a session
    if (await page.getByRole('banner').isVisible()) {
        await expect(page.getByRole('banner')).toContainText('Welcome');
    }
});`,
    ],
    [
        'reasoned runtime skip and declaration-form skip',
        `${HDR}test.skip('not yet implemented', async () => {});
test('t', async () => {
    test.skip(process.platform === 'win32', 'posix-only path handling');
});`,
    ],
    [
        'try/catch that rethrows',
        `${HDR}test('t', async ({ page }) => {
    try {
        await expect(page.getByText('x')).toBeVisible();
    } catch (e) {
        console.log(await page.content());
        throw e;
    }
});`,
    ],
    [
        'a non-probe guard is out of scope',
        `${HDR}test('t', async ({ page }) => {
    const mode = process.env.MODE;
    if (mode === 'full') {
        await expect(page.getByText('x')).toBeVisible();
    }
});`,
    ],
    [
        'catch on a probe is how probes are written',
        `${HDR}test('t', async ({ page }) => {
    const shown = await page.getByText('x').isVisible().catch(() => false);
    expect(shown).toBe(true);
});`,
    ],
    [
        'assertion delegated to a same-file or imported helper',
        `${HDR}import { createProject } from './fixtures';
async function expectRow(page: any) { await expect(page.locator('tr')).toHaveCount(1); }
const openAndCheck = async (page: any) => { await expectRow(page); };
test('a', async ({ page }) => { await openAndCheck(page); });
test('b', async ({ request }) => { await createProject(request); });`,
    ],
    [
        // Codex R1 M3: the probe binding is shadowed by a non-probe one.
        'a shadowed probe name',
        `${HDR}test('t', async ({ page }) => {
    { const ready = await page.locator('#optional').isVisible(); void ready; }
    const ready = process.env.MODE === 'full';
    if (ready) expect(process.env.MODE).toBe('full');
});`,
    ],
    [
        // Codex R1 M4
        'a promise catch that rethrows',
        `${HDR}test('t', async ({ page }) => {
    await expect(page.locator('main')).toBeVisible().catch((error) => {
        console.error(error);
        throw error;
    });
});`,
    ],
    [
        // Codex R1 L7
        'a reason or a body passed by name',
        `${HDR}const why = 'unsupported platform';
const disabledBody = async () => {};
test.skip('temporarily disabled', disabledBody);
test('t', async () => { test.skip(true, why); });`,
    ],
    [
        // Codex R2 Medium: Playwright's one-argument description form.
        'one-argument reason form of skip and fixme',
        `${HDR}test('a', async () => { test.skip('feature unavailable in this environment'); });
test('b', async () => { test.fixme(\`BUG: #123 renders the wrong total\`); });`,
    ],
    [
        // An imported helper inside a probe guard is NOT treated as an
        // assertion for V1 (it may just be setup), so this stays clean.
        'probe guarding an imported setup helper',
        `${HDR}import { uploadSbom } from './fixtures';
test('t', async ({ page, request }) => {
    if (await page.getByText('empty').isVisible()) await uploadSbom(request);
    await expect(page.locator('table')).toBeVisible();
});`,
    ],
];

export function describeVacuous(v: VacuousSite): string {
    return `${v.file}:${v.line}  [${v.rule}] ${v.text}`;
}

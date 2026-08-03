import { test, expect, Page, Locator } from '@playwright/test';

/**
 * M49 (fdaebe4) + its frontend follow-up (209b55e) render gate.
 *
 * WHAT THIS PINS AND WHY IT NEEDS A BROWSER
 * -----------------------------------------
 * M49 turned "not measured" into a type: mttr_hours / on_target /
 * achievement_pct / average_mttr_hours / overall_slo_achievement_pct /
 * percentage all became nullable, all the way from the SQL to the JSON. The
 * Go side is covered by unit + integration tests, but the JSON contract only
 * matters because of what the operator ends up looking at, and the TSX half
 * of that change shipped verified by `tsc` and ESLint alone (M49's own
 * "honest limitations" says so).
 *
 * A null that the page reads back as 0 would restore the exact defect M49
 * exists to remove — and it would do so silently, because for MTTR and SLO
 * achievement the sentinel is the BEST possible value: `mttr_hours ?? 0`
 * renders "0.0 時間" and a full-width green on-target bar for a severity
 * nobody has ever remediated. `typecheck` cannot see that; only a rendered
 * page can. So these tests assert on real pixels' worth of DOM produced by
 * the real API against a real database.
 *
 * TWO STATES, ONE TENANT
 * ----------------------
 * The page is tenant-scoped through self-hosted auth, so both states are
 * produced from the same tenant by moving the PERIOD window instead:
 *
 *   30 days (the page default) — nothing was resolved inside the window.
 *     Every MTTR / SLO figure is unmeasured. This is byte-identical in shape
 *     to a fresh installation that has never remediated anything, which is
 *     the state M49 found reporting "0.0 時間 / 100.0%".
 *
 *   90 days — docker/seed/analytics-mttr.sql puts two resolutions 60 days
 *     back, so the window contains real measurements.
 *
 * That split is also 209b55e's regression in situ. Before that commit the
 * headline average MTTR came from GetQuickStats, whose MTTR query is
 * hard-wired to "the last 30 days", while the panel directly below it was
 * period-scoped. On a 90-day view the panel therefore listed real
 * remediations under a headline reading "未計測" whose tooltip asserted that
 * nothing had been resolved in the selected period — two numbers on one
 * screen, disagreeing, the narrower presented as the summary of the wider.
 * `headline agrees with the MTTR panel` below is that contradiction turned
 * into an invariant.
 *
 * FIXTURE DEPENDENCY
 * ------------------
 * Requires docker/seed/analytics-mttr.sql on top of docker/seed/web-e2e.sql
 * (see apps/web/e2e/README.md). beforeAll fails loudly rather than skipping
 * if it is absent: a gate that quietly downgrades itself to nothing when its
 * fixture is missing is not a gate.
 */

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

type Locale = 'ja' | 'en';

interface LocaleStrings {
    /** Analytics.notMeasured */
    notMeasured: string;
    /** Analytics.notMeasuredHint — the MTTR / SLO tooltip. */
    notMeasuredHint: string;
    /** Analytics.notMeasuredComplianceHint */
    notMeasuredComplianceHint: string;
    /** Headline tile labels (the <p> above the value <p>). */
    averageMttrTile: string;
    sloTile: string;
    /**
     * Expected values in the 90-day (measured) window. Derived from the
     * fixture: CRITICAL 48 h, HIGH 12 h, count-weighted headline mean 30 h,
     * 1 of 2 resolutions inside its SLO target.
     */
    headlineMttr: string;
    criticalMttr: string;
    highMttr: string;
}

const STRINGS: Record<Locale, LocaleStrings> = {
    ja: {
        notMeasured: '未計測',
        notMeasuredHint: '選択期間内に解決済みの脆弱性がないため計測できません',
        notMeasuredComplianceHint: 'チェックリストが未設定のため計測できません',
        averageMttrTile: '平均MTTR',
        sloTile: 'SLO達成率',
        headlineMttr: '1 日 6 時間',
        criticalMttr: '2 日',
        highMttr: '12.0 時間',
    },
    en: {
        notMeasured: 'Not measured',
        notMeasuredHint:
            'No vulnerabilities were resolved in the selected period, so this cannot be measured',
        notMeasuredComplianceHint: 'No checklist has been configured, so this cannot be measured',
        averageMttrTile: 'Average MTTR',
        sloTile: 'SLO Achievement Rate',
        headlineMttr: '1 day 6 hours',
        criticalMttr: '2 days',
        highMttr: '12.0 hours',
    },
};

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

/**
 * The headline tiles are `<div><p>{label}</p><p class="text-2xl">{value}</p></div>`.
 * Anchoring on the label <p> (rather than a class) keeps this readable and
 * survives styling changes; `main p` excludes the panel <h2> headings, which
 * in both locales carry a string that would otherwise collide with the SLO
 * tile label.
 */
function headlineValue(page: Page, label: string): Locator {
    return page
        .locator('main p', { hasText: new RegExp(`^${escapeRegExp(label)}$`) })
        .locator('xpath=following-sibling::p[1]');
}

/** The card <div> that owns a level-2 heading (h2 is its direct child). */
function panel(page: Page, headingPattern: RegExp): Locator {
    return page.getByRole('heading', { level: 2, name: headingPattern }).locator('xpath=..');
}

/** One severity row inside a panel: the parent of the severity chip. */
function severityRow(card: Locator, severity: string): Locator {
    return card.getByText(severity, { exact: true }).locator('xpath=..');
}

/**
 * Count of progress-bar fills inside a row. The bar lives in a
 * `div.h-2.bg-muted` track and is rendered ONLY when the metric is measured
 * — feeding a null into `(mttr_hours / target_hours)` would coerce to 0 and
 * paint a full-width bar, so its absence is a load-bearing part of the fix
 * and not merely cosmetic. Class-coupled because the page ships no test ids.
 */
function barFills(row: Locator): Locator {
    return row.locator('div.h-2.bg-muted > div');
}

function escapeRegExp(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function gotoAnalytics(page: Page, locale: Locale, days: number): Promise<void> {
    await page.goto(`/${locale}/analytics`);
    // The MTTR panel only exists once the summary resolved.
    await expect(panel(page, /^MTTR/)).toBeVisible({ timeout: 30_000 });
    if (days !== 30) {
        await page.locator('main select').selectOption(String(days));
        // The period switch refetches; wait for a value that only the new
        // window can produce rather than for a bare timeout.
        await expect(page.locator('main select')).toHaveValue(String(days));
        await expect(severityRow(panel(page, /^MTTR/), 'CRITICAL')).not.toContainText(
            STRINGS[locale].notMeasured,
            { timeout: 30_000 },
        );
    }
}

test.describe('Analytics — unmeasured metrics render as a label, never as 0', () => {
    test.beforeAll(async ({ request }) => {
        // Guard the fixture. Without docker/seed/analytics-mttr.sql the
        // 90-day window is as empty as the 30-day one and every "state B"
        // assertion below would be vacuous.
        const res = await request.get(`${API_BASE_URL}/api/v1/analytics/summary?days=90`);
        expect(
            res.ok(),
            `GET /api/v1/analytics/summary failed (${res.status()}) — is the API up?`,
        ).toBeTruthy();
        const body = await res.json();
        const measured = (body.mttr ?? []).filter(
            (m: { mttr_hours: number | null }) => m.mttr_hours !== null,
        );
        expect(
            measured.length,
            'No measured MTTR row in the 90-day window. Load docker/seed/analytics-mttr.sql ' +
                'after docker/seed/web-e2e.sql (see apps/web/e2e/README.md).',
        ).toBeGreaterThan(0);
        expect(
            body.compliance_trend?.some(
                (p: { percentage: number | null }) => p.percentage === null,
            ),
            'No max_score=0 compliance snapshot. Load docker/seed/analytics-mttr.sql.',
        ).toBeTruthy();
    });

    for (const locale of ['ja', 'en'] as Locale[]) {
        const s = STRINGS[locale];

        test(`[${locale}] 30d: headline MTTR / SLO tiles say "${s.notMeasured}", not 0`, async ({
            page,
        }) => {
            await gotoAnalytics(page, locale, 30);

            const mttrTile = headlineValue(page, s.averageMttrTile);
            const sloTile = headlineValue(page, s.sloTile);

            await expect(mttrTile).toHaveText(s.notMeasured);
            await expect(sloTile).toHaveText(s.notMeasured);

            // The tooltip that explains the label — 209b55e traced a bug by
            // following exactly this claim back to its source, so the claim
            // itself is part of the contract.
            await expect(mttrTile).toHaveAttribute('title', s.notMeasuredHint);
            await expect(sloTile).toHaveAttribute('title', s.notMeasuredHint);

            // The pre-M49 rendering, spelled out.
            await expect(mttrTile).not.toContainText('0.0');
            await expect(sloTile).not.toContainText('0.0');
            await expect(sloTile).not.toContainText('100.0');
        });

        test(`[${locale}] 30d: every MTTR row is unmeasured — no bar, no verdict icon`, async ({
            page,
        }) => {
            await gotoAnalytics(page, locale, 30);
            const card = panel(page, /^MTTR/);

            for (const severity of SEVERITIES) {
                const row = severityRow(card, severity);
                await expect(row).toContainText(s.notMeasured);
                // "0.0 時間" / "0.0 hours" and the day-form "0 日" / "0 days".
                await expect(row).not.toContainText(/\d+\.\d+\s*(時間|hours?)/);
                // No bar: a null coerced to 0 would paint a full-width green
                // "within target" bar for a severity with no remediation.
                await expect(barFills(row)).toHaveCount(0);
                // MinusCircle (aria-label = notMeasured), not CheckCircle2.
                await expect(row.locator(`[aria-label="${s.notMeasured}"]`)).toHaveCount(1);
            }
        });

        test(`[${locale}] 30d: every SLO row is unmeasured — never 100%`, async ({ page }) => {
            await gotoAnalytics(page, locale, 30);
            const card = panel(page, /^SLO/);

            for (const severity of SEVERITIES) {
                const row = severityRow(card, severity);
                await expect(row).toContainText(s.notMeasured);
                await expect(row).not.toContainText(/\d+\.\d+%/);
                await expect(barFills(row)).toHaveCount(0);
            }
        });

        test(`[${locale}] 90d: measured values render as numbers, unmeasured ones keep the label`, async ({
            page,
        }) => {
            await gotoAnalytics(page, locale, 90);
            const mttrCard = panel(page, /^MTTR/);
            const sloCard = panel(page, /^SLO/);

            // Measured — 48 h against a 24 h target: a number, a red bar and
            // no "not measured" icon.
            const critical = severityRow(mttrCard, 'CRITICAL');
            await expect(critical).toContainText(s.criticalMttr);
            await expect(critical).not.toContainText(s.notMeasured);
            await expect(barFills(critical)).toHaveCount(1);
            await expect(critical.locator(`[aria-label="${s.notMeasured}"]`)).toHaveCount(0);

            // Measured — 12 h against a 168 h target.
            const high = severityRow(mttrCard, 'HIGH');
            await expect(high).toContainText(s.highMttr);
            await expect(high).not.toContainText(s.notMeasured);
            await expect(barFills(high)).toHaveCount(1);

            // Still unmeasured in the SAME window, on the SAME panel — a
            // partially-measured tenant must not have its unremediated
            // severities dropped or shown as on-target (mergeUnmeasuredMTTR).
            for (const severity of ['MEDIUM', 'LOW']) {
                const row = severityRow(mttrCard, severity);
                await expect(row).toContainText(s.notMeasured);
                await expect(barFills(row)).toHaveCount(0);
            }

            // A MEASURED 0.0% is a real (bad) finding and must be
            // distinguishable from an unmeasured one. Both were the same bare
            // 0 before M49, so a gate that only ever sees the label would
            // pass on a page that replaced every number with it.
            const sloCritical = severityRow(sloCard, 'CRITICAL');
            await expect(sloCritical).toContainText('0.0%');
            await expect(sloCritical).not.toContainText(s.notMeasured);

            const sloHigh = severityRow(sloCard, 'HIGH');
            await expect(sloHigh).toContainText('100.0%');
            await expect(sloHigh).not.toContainText(s.notMeasured);

            for (const severity of ['MEDIUM', 'LOW']) {
                await expect(severityRow(sloCard, severity)).toContainText(s.notMeasured);
            }
        });

        test(`[${locale}] 90d: headline agrees with the MTTR panel (209b55e)`, async ({ page }) => {
            await gotoAnalytics(page, locale, 90);
            const card = panel(page, /^MTTR/);

            // Invariant first, exact values second. The invariant is the
            // actual contract: if the panel measured anything in the selected
            // window, the headline summarising that panel cannot claim the
            // window is unmeasured, and its tooltip cannot claim nothing was
            // resolved.
            const measuredRows = [];
            for (const severity of SEVERITIES) {
                const text = await severityRow(card, severity).innerText();
                if (!text.includes(s.notMeasured)) {
                    measuredRows.push(severity);
                }
            }
            expect(measuredRows.length).toBeGreaterThan(0);

            const mttrTile = headlineValue(page, s.averageMttrTile);
            await expect(mttrTile).not.toHaveText(s.notMeasured);
            await expect(mttrTile).not.toHaveAttribute('title', s.notMeasuredHint);
            // Count-weighted mean of the panel's own rows: (48 + 12) / 2.
            await expect(mttrTile).toHaveText(s.headlineMttr);

            // Population-weighted, over the same window: 1 on-target of 2.
            await expect(headlineValue(page, s.sloTile)).toHaveText('50.0%');
        });

        test(`[${locale}] compliance trend: an unassessed snapshot is the localised label, not an em dash`, async ({
            page,
        }) => {
            await gotoAnalytics(page, locale, 30);
            const card = panel(page, /Compliance Score Trend|コンプライアンススコア推移/);
            await expect(card).toBeVisible();

            // The fixture holds one assessed snapshot (8/10) and one with no
            // checklist (0/0). Both on one screen: a "0 / 0 renders as 未計測"
            // assertion is only meaningful next to a real percentage.
            await expect(card).toContainText('80%');
            await expect(card).toContainText(s.notMeasured);
            // 209b55e replaced a hard-coded em dash that bypassed next-intl.
            await expect(card).not.toContainText('—');
            // 0/0 used to render literally as "NaN%".
            await expect(card).not.toContainText('NaN');

            const unmeasuredCell = card
                .locator('span', { hasText: new RegExp(`^${escapeRegExp(s.notMeasured)}$`) })
                .first();
            await expect(unmeasuredCell).toHaveAttribute('title', s.notMeasuredComplianceHint);
        });
    }
});

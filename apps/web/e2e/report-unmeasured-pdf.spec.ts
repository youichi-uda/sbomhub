import { test, expect, APIRequestContext } from '@playwright/test';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * M49 (fdaebe4) executive-report gate — reads the GENERATED PDF, not the
 * function that feeds it.
 *
 * WHY THIS EXISTS
 * ---------------
 * The report is the artefact an auditor is handed. Before M49 the summary
 * line of every generated report read "平均MTTR: 0.0 時間" and
 * "SLO達成率: 0.0%" — one of them because gatherReportData copied
 * SLOAchievementPct out of GetQuickStats, which never sets that field, so the
 * zero VALUE of the struct was printed as a measurement in every report ever
 * produced. For MTTR the sentinel points the other way: 0 hours is the best
 * conceivable remediation time, so an unremediated tenant's PDF certified
 * instant response.
 *
 * apps/api/internal/service/report_mttr_test.go already pins the text
 * helpers, the Excel cells, and that generatePDF returns non-empty bytes. It
 * cannot see what is actually IN those bytes — maroto could stop emitting a
 * row, the font could fail to carry the label's glyphs, the summary block
 * could be reordered so the value lands under the wrong label — and the
 * commit that introduced all of this said as much in its own limitations
 * section ("生成 PDF はビューアで未確認"). This test decodes the real
 * document with pdftotext and asserts on the text an auditor would read.
 *
 * TWO WINDOWS, SAME TENANT
 * ------------------------
 *   30 days — nothing resolved inside the window: every metric must be the
 *     localised "not measured" label, and the string "0.0" must not appear
 *     next to MTTR / SLO at all.
 *   90 days — docker/seed/analytics-mttr.sql's two resolutions are inside:
 *     real numbers must appear. Without this half the suite would pass on a
 *     regression that hard-codes the label everywhere.
 *
 * pdftotext (poppler-utils) is required. Under CI its absence is a hard
 * failure — a gate that skips itself when its tool is missing gates nothing.
 * Locally it degrades to a skip with an actionable message. See the comment
 * on the skip condition below: getting that condition wrong makes the
 * hard-fail unreachable while still LOOKING like a guard.
 */

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

const HAS_PDFTOTEXT = spawnSync('pdftotext', ['-v']).error === undefined;

interface ReportRequest {
    reportType: 'executive' | 'technical' | 'compliance';
    locale: 'ja' | 'en';
    days: number;
}

/** POST /reports/generate, poll to completion, GET the file bytes. */
async function generateAndDownload(
    request: APIRequestContext,
    { reportType, locale, days }: ReportRequest,
): Promise<Buffer> {
    const end = new Date();
    const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);

    const created = await request.post(`${API_BASE_URL}/api/v1/reports/generate`, {
        data: {
            report_type: reportType,
            format: 'pdf',
            period_start: start.toISOString(),
            period_end: end.toISOString(),
            locale,
        },
    });
    expect(
        created.ok(),
        `POST /reports/generate -> ${created.status()}: ${await created.text()}`,
    ).toBeTruthy();
    const { id } = await created.json();

    // The PDF build is deferred to after the request's tenant tx commits, so
    // the row is "generating" for a moment.
    let status = '';
    for (let i = 0; i < 60; i++) {
        const res = await request.get(`${API_BASE_URL}/api/v1/reports/${id}`);
        expect(res.ok()).toBeTruthy();
        status = (await res.json()).status;
        if (status === 'completed' || status === 'failed') break;
        await new Promise((r) => setTimeout(r, 500));
    }
    expect(status, `report ${id} never completed`).toBe('completed');

    const download = await request.get(`${API_BASE_URL}/api/v1/reports/${id}/download`);
    expect(download.ok(), `download -> ${download.status()}`).toBeTruthy();
    const body = await download.body();
    // A PDF, not a JSON error body that happened to come back 200.
    expect(body.subarray(0, 5).toString('latin1')).toBe('%PDF-');
    return body;
}

/** Decode the document's text layer. */
function pdfText(pdf: Buffer): string {
    const dir = mkdtempSync(join(tmpdir(), 'sbomhub-report-'));
    try {
        const file = join(dir, 'report.pdf');
        writeFileSync(file, pdf);
        return execFileSync('pdftotext', ['-enc', 'UTF-8', '-layout', file, '-'], {
            encoding: 'utf8',
            maxBuffer: 32 * 1024 * 1024,
        });
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}

/**
 * The line whose left column is `label`. -layout preserves the two-column
 * key/value geometry, so asserting per line (rather than on the whole
 * document) is what makes "the label sits next to ITS value" checkable — a
 * whole-document `toContain('未計測')` would pass even if the label landed on
 * the compliance row and the MTTR row still printed 0.0.
 */
function lineFor(text: string, label: string): string {
    const line = text.split('\n').find((l) => l.trimStart().startsWith(label));
    expect(line, `no line starting with ${JSON.stringify(label)} in:\n${text}`).toBeDefined();
    return line as string;
}

const LABELS = {
    ja: {
        averageMttr: '平均MTTR',
        slo: 'SLO達成率',
        complianceScore: 'スコア',
        resolvedInPeriod: '期間内解決数',
        notMeasured: '未計測',
        measuredMttr: '30.0 時間',
    },
    en: {
        averageMttr: 'Average MTTR',
        slo: 'SLO Achievement',
        complianceScore: 'Score',
        resolvedInPeriod: 'Resolved in Period',
        notMeasured: 'Not measured',
        measuredMttr: '30.0 hours',
    },
} as const;

test.describe('Executive report PDF — unmeasured metrics are a label, never 0.0', () => {
    // Under CI, a missing pdftotext must FAIL. Anywhere else it may skip.
    //
    // The `&& !process.env.CI` is load-bearing and must not be "simplified"
    // away: a describe-level `test.skip(cond)` is evaluated at COLLECTION
    // time and skips the whole group INCLUDING its beforeAll. With the
    // condition written as a bare `!HAS_PDFTOTEXT`, the beforeAll below is
    // unreachable in exactly the situation it exists for, and a CI run
    // without poppler-utils reports "7 skipped" and a green job — a gate
    // that certifies the PDF's contents without ever opening one. Measured,
    // not assumed: with the bare condition, `CI=1` + a PATH without
    // /usr/bin gave `7 skipped`, exit 0.
    test.skip(
        !HAS_PDFTOTEXT && !process.env.CI,
        'pdftotext not installed — apt-get install poppler-utils',
    );

    test.beforeAll(() => {
        if (!HAS_PDFTOTEXT) {
            // Only reachable under CI, because of the skip above.
            throw new Error(
                'pdftotext (poppler-utils) is required to verify generated PDFs in CI. ' +
                    'Install it in the workflow (apt-get install -y poppler-utils).',
            );
        }
    });

    for (const locale of ['ja', 'en'] as const) {
        const L = LABELS[locale];

        test(`[${locale}] executive PDF over an unmeasured period prints the label`, async ({
            request,
        }) => {
            const text = pdfText(
                await generateAndDownload(request, { reportType: 'executive', locale, days: 30 }),
            );

            // Sanity: this really is the period with nothing resolved.
            expect(lineFor(text, L.resolvedInPeriod)).toMatch(/\s0$/);

            expect(lineFor(text, L.averageMttr)).toContain(L.notMeasured);
            expect(lineFor(text, L.slo)).toContain(L.notMeasured);
            // "0 / 0" is the absence of a scorecard, not a score of zero.
            expect(lineFor(text, L.complianceScore)).toContain(L.notMeasured);

            // The pre-M49 output, verbatim.
            expect(lineFor(text, L.averageMttr)).not.toMatch(/\d+\.\d/);
            expect(lineFor(text, L.slo)).not.toMatch(/\d+\.\d%/);
            expect(lineFor(text, L.complianceScore)).not.toMatch(/\d+\s*\/\s*\d+/);
        });

        test(`[${locale}] executive PDF over a measured period prints numbers`, async ({
            request,
        }) => {
            const text = pdfText(
                await generateAndDownload(request, { reportType: 'executive', locale, days: 90 }),
            );

            // Fixture guard: the 90-day window must actually contain the two
            // seeded resolutions, otherwise this test is vacuous.
            expect(
                lineFor(text, L.resolvedInPeriod),
                'the 90-day report resolved nothing — load docker/seed/analytics-mttr.sql',
            ).toMatch(/\s2$/);

            // Count-weighted mean of 48 h and 12 h.
            expect(lineFor(text, L.averageMttr)).toContain(L.measuredMttr);
            expect(lineFor(text, L.averageMttr)).not.toContain(L.notMeasured);
            // 1 on-target resolution out of 2, population-weighted.
            expect(lineFor(text, L.slo)).toContain('50.0%');
            expect(lineFor(text, L.slo)).not.toContain(L.notMeasured);
        });

        test(`[${locale}] technical PDF carries the same verdict as the executive one`, async ({
            request,
        }) => {
            // The technical template repeats the two metrics through a
            // different builder (buildTechnicalPDFContent). M49 fixed one
            // sibling method and not the other more than once in this repo.
            const unmeasured = pdfText(
                await generateAndDownload(request, { reportType: 'technical', locale, days: 30 }),
            );
            expect(lineFor(unmeasured, L.averageMttr)).toContain(L.notMeasured);
            expect(lineFor(unmeasured, L.slo)).toContain(L.notMeasured);

            const measured = pdfText(
                await generateAndDownload(request, { reportType: 'technical', locale, days: 90 }),
            );
            expect(lineFor(measured, L.averageMttr)).toContain(L.measuredMttr);
            expect(lineFor(measured, L.slo)).toContain('50.0%');
        });
    }

    test('[ja] compliance PDF renders an unassessed scorecard as the label', async ({ request }) => {
        const text = pdfText(
            await generateAndDownload(request, { reportType: 'compliance', locale: 'ja', days: 30 }),
        );
        expect(lineFor(text, LABELS.ja.complianceScore)).toContain(LABELS.ja.notMeasured);
        expect(lineFor(text, LABELS.ja.complianceScore)).not.toMatch(/\d+\s*\/\s*\d+/);
        // Japanese glyphs survived the embedded IPAGothic subset — if the
        // font failed to embed, pdftotext would yield blanks here and the
        // label assertions above would already have failed, but pinning a
        // heading keeps the reason legible when it does.
        expect(text).toContain('コンプライアンススコア');
    });
});

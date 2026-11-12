import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// SSO settings page (src/app/[locale]/(dashboard)/settings/sso/page.tsx).
//
// The page is a Japanese-only information page: one API call (GET /subscription, for the plan / self-host notice), no
// configuration form, no LDAP/OIDC tabs. SSO itself is configured in the
// Clerk dashboard. The strings below are copied from the page.
//
// Removed (asserted nothing that exists): the former "LDAP configuration
// fields" / "OIDC configuration fields" tests (the page has no tabs or
// inputs), and the "SSO link in settings navigation" / "return to settings"
// tests (/settings has no index page and nothing links to /settings/sso;
// the page has no back link).
//
// M12-1 #82: `domcontentloaded` instead of `networkidle` (the dashboard
// layout's billing fetch kept `networkidle` from settling); the explicit
// web-first timeouts are the gate.
const TITLE = 'シングルサインオン (SSO)';

test.describe('SSO Settings', () => {
    test('should navigate to SSO settings page', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await page.waitForLoadState('domcontentloaded');

        await expect(page.getByRole('heading', { level: 1, name: TITLE })).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('企業のアイデンティティプロバイダーと連携して、セキュアな認証を実現')).toBeVisible();
    });

    test('should display SSO provider options', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await expect(page.getByText('対応アイデンティティプロバイダー')).toBeVisible({ timeout: 15000 });

        for (const provider of ['Microsoft Entra ID (Azure AD)', 'Okta', 'Google Workspace', 'SAML 2.0']) {
            await expect(page.getByRole('heading', { level: 4, name: provider, exact: true })).toBeVisible();
        }
    });

    test('should show the current authentication state', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await expect(page.getByText('認証設定', { exact: true })).toBeVisible({ timeout: 15000 });

        // The hermetic stack is self-hosted (SBOMHUB_AUTH_MODE=anonymous): no
        // user authentication, and the page says so (M65 bug 6) instead of
        // claiming e-mail/password sign-in is enabled.
        const standard = page.locator('div.rounded-lg.border', { has: page.getByRole('heading', { name: '標準認証' }) });
        await expect(standard.getByText('なし', { exact: true })).toBeVisible();
        await expect(standard.getByText('セルフホスト環境のため、ユーザー認証はありません')).toBeVisible();
        await expect(standard.getByText('有効', { exact: true })).toHaveCount(0);
        const enterprise = page.locator('div.rounded-lg.border', { has: page.getByRole('heading', { name: 'Enterprise SSO', exact: true }) });
        await expect(enterprise.getByText('未設定', { exact: true })).toBeVisible();
    });

    test('should not show the enterprise plan requirement to an enterprise tenant', async ({ page, request }) => {
        // M65 bug 6: isEnterprise was hard-coded to false.
        const sub = await request.get(`${API_BASE_URL}/api/v1/subscription`);
        expect(sub.status()).toBe(200);
        const body = await sub.json();
        expect(body.plan).toBe('enterprise');
        expect(body.is_self_hosted).toBe(true);

        const answered = page.waitForResponse((r) => new URL(r.url()).pathname === '/api/v1/subscription');
        await page.goto('/en/settings/sso');
        await expect(page.getByRole('heading', { level: 1, name: TITLE })).toBeVisible({ timeout: 15000 });
        expect((await answered).status()).toBe(200);
        // Self-host: the honest notice instead of an upgrade prompt.
        const notice = page.getByTestId('sso-self-hosted-notice');
        await expect(notice).toBeVisible();
        await expect(notice.getByRole('link', { name: 'デプロイモードのドキュメント' })).toHaveAttribute(
            'href',
            /github\.com\/youichi-uda\/sbomhub\/blob\/main\/docs\/configuration\.ja\.md#/,
        );
        await expect(page.getByText('Enterprise プランが必要です', { exact: true })).toHaveCount(0);
        // No "upgrade to Enterprise" setup step for a tenant that already is.
        await expect(page.getByRole('heading', { name: 'Enterprise プランにアップグレード' })).toHaveCount(0);
    });

    test('should send a non-enterprise SaaS tenant to the real billing page', async ({ page }) => {
        // Stubbed: the hermetic stack is self-hosted, so a Clerk-mode tenant on
        // a lower plan can only be shown with a stubbed subscription.
        await page.route(`${API_BASE_URL}/api/v1/subscription`, (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    has_subscription: true,
                    plan: 'pro',
                    limits: { features: {} },
                    billing_enabled: true,
                    is_self_hosted: false,
                }),
            }),
        );
        await page.goto('/en/settings/sso');
        const alert = page.getByTestId('sso-enterprise-required');
        await expect(alert).toBeVisible({ timeout: 15000 });
        await expect(alert.getByText('Enterprise プランが必要です', { exact: true })).toBeVisible();
        // Clerk mode: no self-host notice next to the upgrade prompt (asserted
        // on this page, before navigating away — Codex R3 Low).
        await expect(page.getByTestId('sso-self-hosted-notice')).toHaveCount(0);
        const link = alert.getByRole('link', { name: '料金プラン' });
        // The old link pointed at /settings/billing, which does not exist.
        await expect(link).toHaveAttribute('href', '/billing');
        await expect(page.getByRole('heading', { name: 'Enterprise プランにアップグレード' })).toBeVisible();
        await link.click();
        await expect(page).toHaveURL(/\/en\/billing$/);
    });

    test('should not guess the auth mode when the subscription cannot be loaded', async ({ page }) => {
        // Codex R1 Medium: a failed GET /subscription used to fall through
        // to "e-mail/password sign-in enabled" on an anonymous self-host.
        let fail = true;
        await page.route(`${API_BASE_URL}/api/v1/subscription`, (route) =>
            fail
                ? route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'boom' }) })
                : route.continue(),
        );
        await page.goto('/en/settings/sso');
        const error = page.getByTestId('sso-subscription-error');
        await expect(error).toBeVisible({ timeout: 15000 });
        const standard = page.locator('div.rounded-lg.border', { has: page.getByRole('heading', { name: '標準認証' }) });
        await expect(standard.getByText('不明', { exact: true })).toBeVisible();
        await expect(standard.getByText('有効', { exact: true })).toHaveCount(0);
        await expect(page.getByText('Enterprise プランが必要です', { exact: true })).toHaveCount(0);

        fail = false;
        await error.getByRole('button', { name: '再試行' }).click();
        await expect(page.getByTestId('sso-self-hosted-notice')).toBeVisible();
        await expect(error).toHaveCount(0);
        await expect(standard.getByText('なし', { exact: true })).toBeVisible();
    });

    test('should handle Clerk Enterprise SSO info', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await expect(page.getByText('SSO 設定手順')).toBeVisible({ timeout: 15000 });

        await expect(page.getByRole('heading', { name: 'Clerk ダッシュボードで SSO を設定' })).toBeVisible();
        const dashboard = page.getByRole('link', { name: 'Clerk ダッシュボードを開く' });
        await expect(dashboard).toHaveAttribute('href', 'https://dashboard.clerk.com');
        await expect(dashboard).toHaveAttribute('target', '_blank');

        const docs = page.getByRole('link', { name: /Clerk Enterprise SSO ガイド/ });
        await expect(docs).toHaveAttribute('href', 'https://clerk.com/docs/authentication/enterprise-connections');
        await expect(page.getByRole('link', { name: /SAML 設定ガイド/ })).toHaveAttribute('href', 'https://clerk.com/docs/authentication/saml');
    });
});

test.describe('SSO Settings in Japanese', () => {
    test('should display SSO settings in Japanese', async ({ page }) => {
        await page.goto('/ja/settings/sso');
        await page.waitForLoadState('domcontentloaded');

        await expect(page.getByRole('heading', { level: 1, name: TITLE })).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('対応アイデンティティプロバイダー')).toBeVisible();
        // The support action is a real link to the project's GitHub Issues
        // (it used to be a button with no handler).
        const support = page.getByRole('link', { name: 'GitHub Issues で質問する' });
        await expect(support).toBeVisible();
        await expect(support).toHaveAttribute('href', 'https://github.com/youichi-uda/sbomhub/issues');
        await expect(support).toHaveAttribute('target', '_blank');
        await expect(support).toHaveAttribute('rel', 'noopener noreferrer');
        await expect(page.getByRole('button', { name: 'サポートに問い合わせ' })).toHaveCount(0);
    });
});

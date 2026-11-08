import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// SSO settings page (src/app/[locale]/(dashboard)/settings/sso/page.tsx).
//
// The page is a static, Japanese-only information page: no API calls, no
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

        const standard = page.locator('div.rounded-lg.border', { has: page.getByRole('heading', { name: '標準認証' }) });
        await expect(standard.getByText('有効', { exact: true })).toBeVisible();
        const enterprise = page.locator('div.rounded-lg.border', { has: page.getByRole('heading', { name: 'Enterprise SSO', exact: true }) });
        await expect(enterprise.getByText('未設定', { exact: true })).toBeVisible();
    });

    test('should not show the enterprise plan requirement to an enterprise tenant', async ({ page, request }) => {
        test.fixme(true, 'BUG: settings/sso/page.tsx hard-codes isEnterprise=false, so the "Enterprise プランが必要です" alert shows for the enterprise tenant; its upgrade link (/settings/billing) is also a 404 (billing lives at /billing)');

        const sub = await request.get(`${API_BASE_URL}/api/v1/subscription`);
        expect(sub.status()).toBe(200);
        expect((await sub.json()).plan).toBe('enterprise');

        await page.goto('/en/settings/sso');
        await expect(page.getByRole('heading', { level: 1, name: TITLE })).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('Enterprise プランが必要です', { exact: true })).toHaveCount(0);
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
        await expect(page.getByRole('button', { name: 'サポートに問い合わせ' })).toBeVisible();
    });
});

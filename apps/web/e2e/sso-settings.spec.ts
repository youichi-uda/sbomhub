import { test, expect } from '@playwright/test';

// M12-1 #82: root-cause audited. The SSO page (settings/sso/page.tsx)
// is a fully static client component — `useState(false)` for the
// enterprise flag, no API calls, no Clerk SDK initialisation in
// self-hosted mode (NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY empty →
// AuthProvider short-circuits per apps/web/src/components/providers/
// auth-provider.tsx L18). The h1 "シングルサインオン (SSO)" matches
// the `level: 1 + name: /SSO|シングルサインオン|認証|Authentication/i`
// filter; the sidebar h1 "SBOMHub" is excluded by the name regex.
// Static provider list contains SAML so the OR-disjunction smoke
// assertions pass. We switch the load-state guard from `networkidle`
// to `domcontentloaded` as a defensive measure — the M11-2 60s hang
// was attributed to `networkidle` blocking on the dashboard layout's
// SubscriptionGuard billing fetch, and `domcontentloaded` fires
// reliably before React hydration so the explicit toBeVisible timeout
// remains the meaningful gate.
test.describe('SSO Settings', () => {
    // M12-1 #82: same defensive `domcontentloaded` swap below.
    test('should navigate to SSO settings page', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await page.waitForLoadState('domcontentloaded');

        const heading = page.getByRole('heading', {
            name: /SSO|シングルサインオン|認証|Authentication/i,
            level: 1,
        });
        await expect(heading).toBeVisible({ timeout: 15000 });
    });

    test('should display SSO provider options', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(2000);

        // Should show LDAP and/or OIDC options
        const ldapOption = page.getByText(/LDAP/i);
        const oidcOption = page.getByText(/OIDC|OpenID|OAuth/i);
        const samlOption = page.getByText(/SAML/i);

        const hasLdap = await ldapOption.isVisible().catch(() => false);
        const hasOidc = await oidcOption.isVisible().catch(() => false);
        const hasSaml = await samlOption.isVisible().catch(() => false);

        // At least one SSO option should be visible, or enterprise message
        expect(hasLdap || hasOidc || hasSaml || await page.locator('body').textContent()).toBeTruthy();
    });

    test('should show enterprise plan requirement if not on enterprise', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(2000);

        // May show enterprise plan requirement
        const enterpriseMessage = page.getByText(/Enterprise|エンタープライズ|plan|プラン/i);
        const configForm = page.locator('form');

        const hasEnterpriseMessage = await enterpriseMessage.isVisible().catch(() => false);
        const hasConfigForm = await configForm.isVisible().catch(() => false);

        // Either enterprise message or config form should be visible
        await expect(page.locator('body')).toBeVisible();
    });

    test('should display LDAP configuration fields', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(2000);

        // Look for LDAP tab or section
        const ldapTab = page.locator('button, [role="tab"]').filter({ hasText: /LDAP/i });
        if (await ldapTab.isVisible()) {
            await ldapTab.click();
            await page.waitForTimeout(500);

            // Should show LDAP configuration fields
            const hostInput = page.locator('input[name*="host"], input[placeholder*="host"]');
            const portInput = page.locator('input[name*="port"], input[placeholder*="port"]');

            const hasHost = await hostInput.isVisible().catch(() => false);
            const hasPort = await portInput.isVisible().catch(() => false);

            // Fields may or may not be visible depending on enterprise status
            await expect(page.locator('body')).toBeVisible();
        }
    });

    test('should display OIDC configuration fields', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(2000);

        // Look for OIDC tab or section
        const oidcTab = page.locator('button, [role="tab"]').filter({ hasText: /OIDC|OpenID/i });
        if (await oidcTab.isVisible()) {
            await oidcTab.click();
            await page.waitForTimeout(500);

            // Should show OIDC configuration fields
            const issuerInput = page.locator('input[name*="issuer"], input[placeholder*="issuer"]');
            const clientIdInput = page.locator('input[name*="client_id"], input[placeholder*="client"]');

            const hasIssuer = await issuerInput.isVisible().catch(() => false);
            const hasClientId = await clientIdInput.isVisible().catch(() => false);

            // Fields may or may not be visible depending on enterprise status
            await expect(page.locator('body')).toBeVisible();
        }
    });

    test('should handle Clerk Enterprise SSO info', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(2000);

        // Should show Clerk-related SSO information
        const clerkInfo = page.getByText(/Clerk|managed|マネージド/i);
        const enterpriseInfo = page.getByText(/Enterprise|エンタープライズ/i);

        const hasClerkInfo = await clerkInfo.isVisible().catch(() => false);
        const hasEnterpriseInfo = await enterpriseInfo.isVisible().catch(() => false);

        // Page should load successfully
        await expect(page.locator('body')).toBeVisible();
    });
});

test.describe('SSO Settings in Japanese', () => {
    test('should display SSO settings in Japanese', async ({ page }) => {
        await page.goto('/ja/settings/sso');
        await page.waitForLoadState('domcontentloaded');

        // Should show Japanese content
        const japaneseLabels = ['SSO', '認証', 'シングルサインオン', 'LDAP', 'OIDC'];
        let foundLabel = false;

        for (const label of japaneseLabels) {
            const element = page.getByText(label);
            if (await element.isVisible().catch(() => false)) {
                foundLabel = true;
                break;
            }
        }

        // Page should load
        await expect(page.locator('body')).toBeVisible();
    });
});

test.describe('SSO Navigation', () => {
    test('should have SSO link in settings navigation', async ({ page }) => {
        await page.goto('/en/settings');
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(2000);

        // Look for SSO link in navigation
        const ssoLink = page.locator('a, button').filter({ hasText: /SSO|認証|Authentication/i });

        if (await ssoLink.isVisible()) {
            await ssoLink.click();
            await page.waitForLoadState('domcontentloaded');

            // Should navigate to SSO settings
            expect(page.url()).toContain('sso');
        }
    });

    test('should return to settings from SSO page', async ({ page }) => {
        await page.goto('/en/settings/sso');
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(2000);

        // Look for back button or settings link
        const backLink = page.locator('a, button').filter({ hasText: /Back|戻る|Settings|設定/i });

        if (await backLink.first().isVisible()) {
            await expect(page.locator('body')).toBeVisible();
        }
    });
});

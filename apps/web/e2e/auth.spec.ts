import { test, expect } from '@playwright/test';
import en from '../messages/en.json';
import ja from '../messages/ja.json';

const L = en.Landing;

const jaNav = ja.Navigation;
const jaProjects = ja.Projects;

test.describe('Authentication Flow', () => {
    test('should allow access to public pages without auth', async ({ page }) => {
        await page.goto('/en');

        // The landing page renders (no redirect) with its hero and sunset banner.
        await expect(page).toHaveURL(/\/en$/);
        await expect(page.getByRole('heading', { level: 1, name: L.hero.title.replace(/\n/g, ' ') })).toBeVisible();
        await expect(page.getByText(L.sunsetBanner, { exact: false })).toBeVisible();
    });

    test('should access legal page', async ({ page }) => {
        await page.goto('/en/legal');
        await page.waitForLoadState('networkidle');

        // Legal page should load
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    });

    test('should access privacy page', async ({ page }) => {
        await page.goto('/en/privacy');
        await page.waitForLoadState('networkidle');

        // Privacy page should load
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    });

    test('should access terms page', async ({ page }) => {
        await page.goto('/en/terms');
        await page.waitForLoadState('networkidle');

        // Terms page should load
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    });

    test('should have sign in link in header', async ({ page }) => {
        await page.goto('/en');

        // Self-hosted landing page: the header and the footer both link to
        // the locale's sign-in route.
        const headerLink = page.locator('header').getByRole('link', { name: L.nav.signIn, exact: true });
        await expect(headerLink).toBeVisible();
        await expect(headerLink).toHaveAttribute('href', '/en/sign-in');
        await expect(page.locator('footer').getByRole('link', { name: L.nav.signIn, exact: true }))
            .toHaveAttribute('href', '/en/sign-in');
    });

    test('should not redirect protected routes to sign-in in anonymous mode', async ({ page }) => {
        // The CI stack is self-hosted with no Clerk key: the dashboard is
        // open to the anonymous (seeded admin) user.
        await page.goto('/en/projects');
        await expect(page).toHaveURL(/\/en\/projects$/);
        await expect(page.getByRole('heading', { level: 1, name: en.Projects.title })).toBeVisible({ timeout: 15000 });
    });

    test('should display header with navigation', async ({ page }) => {
        await page.goto('/en');
        await page.waitForLoadState('networkidle');

        // Header should have navigation links
        const header = page.locator('header, nav').first();
        await expect(header).toBeVisible();

        // Should have logo or brand
        const logo = page.getByText(/SBOM|SBOMHub/i).first();
        await expect(logo).toBeVisible();
    });

    test('should have language switcher', async ({ page }) => {
        // The dashboard header shows the current locale on its toggle.
        await page.goto('/en/dashboard');
        await expect(page.getByRole('banner').getByRole('button', { name: 'EN', exact: true })).toBeVisible({ timeout: 15000 });
        await page.goto('/ja/dashboard');
        await expect(page.getByRole('banner').getByRole('button', { name: 'JA', exact: true })).toBeVisible({ timeout: 15000 });
    });

    // M11-2 #77: re-enabled. The lang switcher (Header.toggleLocale)
    // uses router.push("/ja...") which is synchronous in dev:test
    // mode; the previous failure mode was tied to a stale Clerk
    // OrganizationSwitcher mount that has since been resolved by
    // empty-publishable-key short-circuiting in M10-3. The assertion
    // tolerates any URL containing `/ja` to stay robust against home
    // redirects.
    test('should switch language from EN to JA', async ({ page }) => {
        await page.goto('/en/dashboard');
        await page.waitForLoadState('networkidle');

        // The header button shows "EN" on /en/* and "JA" on /ja/*.
        const langButton = page.getByRole('button', { name: /^EN$/ }).first();
        await expect(langButton).toBeVisible({ timeout: 10000 });
        await langButton.click();

        await expect(page).toHaveURL(/\/ja(\/|$)/, { timeout: 5000 });
    });

    test('should maintain language preference across pages', async ({ page }) => {
        // Start in Japanese on a dashboard page (the sidebar is there).
        await page.goto('/ja/dashboard');
        await page.waitForLoadState('networkidle');

        // Sidebar links are locale-less (href="/projects"); the locale
        // must be carried over to the next page.
        const projectsLink = page.getByRole('link', { name: jaNav.projects, exact: true });
        await expect(projectsLink).toBeVisible({ timeout: 10000 });
        await projectsLink.click();

        await expect(page).toHaveURL(/\/ja\/projects$/);
        await expect(page.getByRole('heading', { level: 1, name: jaProjects.title })).toBeVisible();
    });

    test('should access public SBOM link without auth', async ({ page }) => {
        // An unknown token is served by the public page itself (no sign-in
        // redirect), which shows the access form with the denial message.
        await page.goto('/en/public/test-token-12345');
        await expect(page).toHaveURL(/\/en\/public\/test-token-12345$/);
        await expect(page.getByText('Public SBOM Access')).toBeVisible({ timeout: 15000 });
        await expect(page.getByText('Access denied. Password may be required.')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Access' })).toBeDisabled();
    });
});

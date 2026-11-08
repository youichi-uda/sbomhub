import { test, expect, type Page } from '@playwright/test';
import en from '../messages/en.json';
import { API_BASE_URL, createProject, deleteProject, uniqueName, uploadSbom } from './fixtures/vuln-project';

// Records every native dialog (alert/confirm/prompt) the page opens: an
// injected handler that ran would show up here.
function recordDialogs(page: Page): string[] {
    const seen: string[] = [];
    page.on('dialog', async (dialog) => {
        seen.push(`${dialog.type()}: ${dialog.message()}`);
        await dialog.dismiss();
    });
    return seen;
}

test.describe('Security Tests', () => {
    let projectId = '';

    test.beforeAll(async ({ request }) => {
        const project = await createProject(request, uniqueName('Security Test Project'), 'Project for security E2E tests');
        projectId = project.id;
    });

    test.afterAll(async ({ request }) => {
        await deleteProject(request, projectId);
    });

    test.describe('XSS Prevention', () => {
        test('should sanitize script tags in project name', async ({ page, request }) => {
            const xssPayload = `<script>alert('XSS')</script>Test${Date.now()}`;
            const project = await createProject(request, xssPayload, 'XSS test project');
            try {
                const dialogs = recordDialogs(page);

                // Listed as literal text...
                await page.goto('/en/projects');
                await expect(page.getByRole('link', { name: xssPayload, exact: true })).toBeVisible({ timeout: 15000 });

                // ...and shown as the literal page title on the detail page.
                await page.goto(`/en/projects/${project.id}`);
                await expect(page.getByRole('heading', { level: 1, name: xssPayload, exact: true })).toBeVisible({ timeout: 15000 });
                await expect(page.locator('main script')).toHaveCount(0);
                expect(dialogs).toEqual([]);
            } finally {
                await deleteProject(request, project.id);
            }
        });

        test('should sanitize img tag with onerror in project name', async ({ page, request }) => {
            const xssPayload = `<img src=x onerror=alert('XSS')>Project${Date.now()}`;
            const project = await createProject(request, xssPayload, 'Image XSS test');
            try {
                const dialogs = recordDialogs(page);
                await page.goto(`/en/projects/${project.id}`);

                await expect(page.getByRole('heading', { level: 1, name: xssPayload, exact: true })).toBeVisible({ timeout: 15000 });
                await expect(page.locator('main img[src="x"]')).toHaveCount(0);
                expect(dialogs).toEqual([]);
            } finally {
                await deleteProject(request, project.id);
            }
        });

        test('should sanitize event handlers in project description', async ({ page, request }) => {
            const xssPayload = `<div onmouseover="alert('XSS')">Hover me</div>`;
            const project = await createProject(request, uniqueName('Event Handler Test'), xssPayload);
            try {
                const dialogs = recordDialogs(page);
                await page.goto(`/en/projects/${project.id}`);

                // The description is literal text; hovering it runs nothing.
                const description = page.getByText(xssPayload, { exact: true });
                await expect(description).toBeVisible({ timeout: 15000 });
                await description.hover();
                await expect(page.locator('main [onmouseover]')).toHaveCount(0);
                expect(dialogs).toEqual([]);
            } finally {
                await deleteProject(request, project.id);
            }
        });

        test('should handle javascript: protocol in links', async ({ page }) => {
            await page.goto('/en/projects');

            // Check that no javascript: links exist in the page
            const jsLinks = await page.locator('a[href^="javascript:"]').count();
            expect(jsLinks).toBe(0);
        });
    });

    test.describe('HTML Injection Prevention', () => {
        test('should escape HTML entities in component names', async ({ page, request }) => {
            const htmlPayload = `<b>Bold</b><i>Italic</i><a href="http://evil.com">Link</a>`;

            await uploadSbom(request, projectId, {
                bomFormat: 'CycloneDX',
                specVersion: '1.4',
                version: 1,
                components: [
                    { type: 'library', name: htmlPayload, version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] },
                ],
            });

            await page.goto(`/en/projects/${projectId}`);
            await page.getByRole('button', { name: /Components/i }).click();

            // The raw markup is shown as text; none of it became elements.
            await expect(page.getByText(htmlPayload, { exact: true })).toBeVisible({ timeout: 15000 });
            await expect(page.locator('main b', { hasText: 'Bold' })).toHaveCount(0);
            await expect(page.locator('main i', { hasText: 'Italic' })).toHaveCount(0);
            await expect(page.locator('main a[href="http://evil.com"]')).toHaveCount(0);
        });

        // M11-2 #77: re-enabled. The previous failure was the spec
        // expecting a Japanese button label ('検索') on the /en
        // search page, where the rendered label is 'Search'. Use a
        // language-agnostic name regex.
        test('should escape HTML in search results', async ({ page }) => {
            await page.goto('/en/search');

            // Search with HTML payload
            const cveInput = page.getByPlaceholder('CVE-2021-44228');
            await cveInput.fill('<b>CVE-TEST</b>');
            await page.getByRole('button', { name: /^(Search|検索)$/ }).first().click();
            await page.waitForTimeout(1000);

            // Check that no bold element was created from our input
            await expect(cveInput).toHaveValue('<b>CVE-TEST</b>');
            await expect(page.locator('main b', { hasText: 'CVE-TEST' })).toHaveCount(0);
        });
    });

    test.describe('Special Character Handling', () => {
        test('should handle Unicode characters correctly', async ({ page, request }) => {
            const unicodeName = `Project 日本語 中文 한국어 العربية ${Date.now()}`;
            const description = '多言語テスト Multilingual test مشروع';
            const project = await createProject(request, unicodeName, description);
            try {
                await page.goto(`/en/projects/${project.id}`);
                await expect(page.getByRole('heading', { level: 1, name: unicodeName, exact: true })).toBeVisible({ timeout: 15000 });
                await expect(page.getByText(description, { exact: true })).toBeVisible();
            } finally {
                await deleteProject(request, project.id);
            }
        });

        test('should handle emoji in project names', async ({ page, request }) => {
            const emojiName = `🚀 Rocket Project 🔥💻🛡️ ${Date.now()}`;
            const project = await createProject(request, emojiName, 'Project with 🎉 emoji 🎊');
            try {
                await page.goto(`/en/projects/${project.id}`);
                await expect(page.getByRole('heading', { level: 1, name: emojiName, exact: true })).toBeVisible({ timeout: 15000 });
                await expect(page.getByText('Project with 🎉 emoji 🎊', { exact: true })).toBeVisible();
            } finally {
                await deleteProject(request, project.id);
            }
        });

        test('should reject null bytes and control characters as invalid input', async ({ request }) => {
            const controlChars = `Project\x00Test\x1F${Date.now()}`;

            const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
                data: { name: controlChars, description: 'Control character test' },
            });
            try {
                expect(response.status()).toBe(400);
            } finally {
                if (response.ok()) await deleteProject(request, (await response.json()).id);
            }
        });

        // (Removed: "should handle very long input strings". It asserted
        // `value.length <= 10000` after filling 10000 characters, which
        // cannot fail. Over-long names are covered by projects.spec.ts
        // "should handle long project name".)
    });

    test.describe('SQL Injection Prevention', () => {
        // M11-2 #77: re-enabled. The previous failure was the spec
        // expecting Japanese button + heading labels ('検索' /
        // '横断検索') on the /en search page. Use language-agnostic
        // name regexes ('Search' / 'Cross Search') so the assertion
        // matches the actual EN render.
        test('should handle SQL injection attempts in search', async ({ page }) => {
            await page.goto('/en/search');

            // Common SQL injection payloads
            const sqlPayloads = [
                "'; DROP TABLE projects; --",
                "1' OR '1'='1",
                "1; SELECT * FROM users",
                "UNION SELECT * FROM projects",
            ];

            for (const payload of sqlPayloads) {
                const cveInput = page.getByPlaceholder('CVE-2021-44228');
                await cveInput.fill(payload);
                await page.getByRole('button', { name: /^(Search|検索)$/ }).first().click();
                await page.waitForTimeout(500);

                // Page should remain functional. Scope to main to
                // disambiguate from the sidebar h1 ("SBOMHub").
                await expect(
                    page.locator('main').getByRole('heading', { level: 1 }),
                ).toBeVisible();

                // Clear for next iteration
                await cveInput.clear();
            }
        });

        // M11-2 #77: re-enabled. With parameterised INSERTs the SQL
        // payload is stored verbatim and no injection runs. The
        // assertion now checks (a) the projects list endpoint is
        // still healthy after the payload submission and (b) the
        // page heading remains mounted — both of which prove "no
        // table dropped" without requiring a specific error-message
        // i18n match.
        // M13-1 #87 (F174): un-skipped. Two-part root cause:
        //   (a) The custom Dialog shim under apps/web/src/components/ui/dialog.tsx
        //       rendered no `role="dialog"` attribute, so the original
        //       `[role="dialog"]` scope matched nothing and the Create
        //       button click timed out at the 60s per-test budget. The
        //       shim now sets role + aria-modal (also a genuine a11y
        //       win); the spec scope works against it.
        //   (b) `getByRole('button', { name: /New Project/i })` without
        //       `.first()` is strict-mode-violating whenever the empty
        //       state Card also surfaces a New Project CTA. Pin
        //       `.first()` to match projects.spec.ts L21.
        //   We also wait on the create-project POST response so the
        //   subsequent projects-list health check sees the post-write
        //   state rather than racing it.
        test('should handle SQL injection in project creation', async ({ page, request }) => {
            const sqlPayload = `Test'; DROP TABLE projects; -- ${Date.now()}`;
            const description = "1'; DELETE FROM projects;--";

            await page.goto('/en/projects');
            await page.getByRole('button', { name: /New Project/i }).first().click();
            await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });
            await page.getByPlaceholder('My Project').fill(sqlPayload);
            await page.getByPlaceholder('Project description').fill(description);

            const createResponse = page.waitForResponse(
                (resp) => resp.url().endsWith('/api/v1/projects') && resp.request().method() === 'POST',
                { timeout: 15000 },
            );
            await page.locator('[role="dialog"]').getByRole('button', { name: /^Create$/ }).click();
            const created = await createResponse;
            expect(created.status()).toBe(201);
            const createdId = (await created.json()).id as string;

            try {
                // Stored verbatim (parameterised), listed as text, and the
                // projects table is intact (the suite's own project survives).
                await expect(page.getByRole('link', { name: sqlPayload, exact: true })).toBeVisible({ timeout: 10000 });
                const projectsResponse = await request.get(`${API_BASE_URL}/api/v1/projects`);
                expect(projectsResponse.status()).toBe(200);
                const projects = (await projectsResponse.json()) as Array<{ id: string; name: string; description: string }>;
                expect(projects.find((p) => p.id === createdId)).toMatchObject({ name: sqlPayload, description });
                expect(projects.map((p) => p.id)).toContain(projectId);
            } finally {
                await deleteProject(request, createdId);
            }
        });
    });

    test.describe('Path Traversal Prevention', () => {
        test('should handle path traversal in project ID', async ({ page }) => {
            const pathTraversalPayloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\config\\sam',
                '%2e%2e%2f%2e%2e%2f',
                '....//....//....//etc/passwd',
            ];

            for (const payload of pathTraversalPayloads) {
                await page.goto(`/en/projects/${encodeURIComponent(payload)}`);
                // Treated as an unknown project id; no file content leaks.
                await expect(page.locator('main')).toHaveText(en.Common.projectNotFound, { timeout: 15000 });
                await expect(page.locator('body')).not.toContainText('root:');
            }
        });
    });

    test.describe('CSRF Protection', () => {
        // The API is JSON-only, so a cross-site write needs a CORS
        // preflight; what protects it is that the API never grants CORS to
        // a foreign origin. (Server-side, a request carrying a foreign
        // Origin is processed like any other — CORS is browser-enforced.)
        test('should not grant CORS to a foreign origin', async ({ request, baseURL }) => {
            const preflight = (origin: string) =>
                request.fetch(`${API_BASE_URL}/api/v1/projects`, {
                    method: 'OPTIONS',
                    headers: {
                        Origin: origin,
                        'Access-Control-Request-Method': 'POST',
                        'Access-Control-Request-Headers': 'content-type',
                    },
                });

            const evil = await preflight('http://evil.com');
            expect(evil.status()).toBe(204);
            expect(evil.headers()['access-control-allow-origin']).toBeUndefined();
            expect(evil.headers()['access-control-allow-methods']).toBeUndefined();

            // Positive control: the web app's own origin is allowed.
            const appOrigin = new URL(baseURL!).origin;
            const own = await preflight(appOrigin);
            expect(own.headers()['access-control-allow-origin']).toBe(appOrigin);
        });
    });

    test.describe('Content Security', () => {
        // M65 bug 9: pages used to carry no security headers and sent
        // X-Powered-By. Policy: apps/web/security-headers.mjs.
        test('should have appropriate security headers', async ({ page }) => {
            const response = await page.goto('/en/projects');
            expect(response).not.toBeNull();
            const headers = response!.headers();
            expect(headers['x-content-type-options']).toBe('nosniff');
            expect(headers['x-frame-options']).toBe('DENY');
            expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
            expect(headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
            expect(headers['permissions-policy']).toContain('camera=()');
            expect(headers['x-powered-by']).toBeUndefined();
        });

        test('should load the main pages without any CSP violation', async ({ page }) => {
            const violations: string[] = [];
            page.on('console', (msg) => {
                if (/Content[- ]Security[- ]Policy|Refused to (load|execute|connect|apply|frame)/i.test(msg.text())) {
                    violations.push(`${page.url()}: ${msg.text()}`);
                }
            });
            await page.addInitScript(() => {
                document.addEventListener('securitypolicyviolation', (e) => {
                    console.error(`Content Security Policy violation: ${e.violatedDirective} ${e.blockedURI}`);
                });
            });
            for (const path of ['/en', '/en/dashboard', '/en/projects', '/en/search', '/en/settings/apikeys', '/en/settings/sso', '/ja/projects']) {
                const res = await page.goto(path);
                expect(res?.status(), path).toBe(200);
                expect(res?.headers()['content-security-policy'], path).toContain("default-src 'self'");
                // The page really ran its client code (hydrated + talked to the API).
                await page.waitForLoadState('networkidle');
            }
            expect(violations).toEqual([]);
        });

        test('should not expose sensitive information in error pages', async ({ page }) => {
            await page.goto('/en/projects/invalid-id-12345');
            await expect(page.locator('main')).toHaveText(en.Common.projectNotFound, { timeout: 15000 });

            // The rendered text carries no stack trace, internal path or secret.
            const text = await page.locator('body').innerText();
            for (const pattern of [/at\s+\w+\s+\(/, /node_modules/i, /\.go:\d+/, /password/i, /secret/i, /api[_-]?key/i, /sql/i]) {
                expect(text, `rendered error page must not match ${pattern}`).not.toMatch(pattern);
            }
        });
    });
});

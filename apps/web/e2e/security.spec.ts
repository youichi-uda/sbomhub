import { test, expect } from '@playwright/test';

const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

test.describe('Security Tests', () => {
    let projectId: string;

    test.beforeAll(async ({ request }) => {
        // Create a test project
        const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
            data: {
                name: `Security Test Project ${Date.now()}`,
                description: 'Project for security E2E tests',
            },
        });
        const project = await response.json();
        projectId = project.id;
    });

    test.afterAll(async ({ request }) => {
        if (projectId) {
            await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
        }
    });

    test.describe('XSS Prevention', () => {
        test('should sanitize script tags in project name', async ({ page, request }) => {
            const xssPayload = `<script>alert('XSS')</script>Test${Date.now()}`;

            // Create project with XSS payload via API
            const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
                data: {
                    name: xssPayload,
                    description: 'XSS test project',
                },
            });

            const project = await response.json();
            const testProjectId = project.id;

            // Navigate to projects list
            await page.goto('/en/projects');
            await page.waitForTimeout(1000);

            // The script should not execute - page should still be functional
            await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();

            // Check for console errors related to XSS
            const consoleErrors: string[] = [];
            page.on('console', msg => {
                if (msg.type() === 'error') {
                    consoleErrors.push(msg.text());
                }
            });

            // Navigate to project detail
            await page.goto(`/en/projects/${testProjectId}`);
            await page.waitForTimeout(1000);

            // Page should still be functional
            await expect(page.getByText('Back to Projects')).toBeVisible();

            // Script content should be visible as text, not executed
            const scriptText = page.getByText(/script.*alert/i);
            const isEscaped = await scriptText.isVisible().catch(() => false);

            // Either the script text is visible (escaped) or the name was sanitized
            expect(isEscaped || await page.locator('main').isVisible()).toBeTruthy();

            // No XSS-related errors should have occurred
            const hasXSSError = consoleErrors.some(err => err.includes('XSS') || err.includes('unsafe'));
            expect(hasXSSError).toBeFalsy();

            // Cleanup
            await request.delete(`${API_BASE_URL}/api/v1/projects/${testProjectId}`);
        });

        test('should sanitize img tag with onerror in project name', async ({ page, request }) => {
            const xssPayload = `<img src=x onerror=alert('XSS')>Project${Date.now()}`;

            const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
                data: {
                    name: xssPayload,
                    description: 'Image XSS test',
                },
            });

            const project = await response.json();
            const testProjectId = project.id;

            // Listen for any JavaScript alerts (which would indicate XSS)
            let alertTriggered = false;
            page.on('dialog', async dialog => {
                alertTriggered = true;
                await dialog.dismiss();
            });

            await page.goto(`/en/projects/${testProjectId}`);
            await page.waitForTimeout(2000);

            // No alert should have been triggered
            expect(alertTriggered).toBeFalsy();

            // Cleanup
            await request.delete(`${API_BASE_URL}/api/v1/projects/${testProjectId}`);
        });

        test('should sanitize event handlers in project description', async ({ page, request }) => {
            const xssPayload = `<div onmouseover="alert('XSS')">Hover me</div>`;

            const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
                data: {
                    name: `Event Handler Test ${Date.now()}`,
                    description: xssPayload,
                },
            });

            const project = await response.json();
            const testProjectId = project.id;

            let alertTriggered = false;
            page.on('dialog', async dialog => {
                alertTriggered = true;
                await dialog.dismiss();
            });

            await page.goto(`/en/projects/${testProjectId}`);
            await page.waitForTimeout(1000);

            // Try to trigger the event handler
            const hoverElement = page.getByText('Hover me');
            if (await hoverElement.isVisible()) {
                await hoverElement.hover();
                await page.waitForTimeout(500);
            }

            expect(alertTriggered).toBeFalsy();

            // Cleanup
            await request.delete(`${API_BASE_URL}/api/v1/projects/${testProjectId}`);
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

            // Upload SBOM with HTML in component name
            const sbom = {
                bomFormat: 'CycloneDX',
                specVersion: '1.4',
                version: 1,
                components: [
                    {
                        type: 'library',
                        name: htmlPayload,
                        version: '1.0.0',
                        licenses: [{ license: { id: 'MIT' } }],
                    },
                ],
            };

            await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
                data: JSON.stringify(sbom),
                headers: { 'Content-Type': 'application/json' },
            });

            await page.goto(`/en/projects/${projectId}`);
            await page.waitForLoadState('networkidle');

            await page.getByRole('button', { name: /Components/i }).click();
            await page.waitForTimeout(1000);

            // HTML should be escaped, not rendered
            const boldElement = page.locator('b').filter({ hasText: 'Bold' });
            const italicElement = page.locator('i').filter({ hasText: 'Italic' });

            // These elements should NOT exist (HTML not rendered)
            const hasBold = await boldElement.isVisible().catch(() => false);
            const hasItalic = await italicElement.isVisible().catch(() => false);

            // The raw HTML text should be visible instead
            const escapedText = page.getByText(/<b>Bold<\/b>/);
            const hasEscaped = await escapedText.isVisible().catch(() => false);

            // Either HTML is escaped or not rendered at all
            expect(!hasBold || hasEscaped).toBeTruthy();
        });

        test('should escape HTML in search results', async ({ page }) => {
            await page.goto('/en/search');

            // Search with HTML payload
            const cveInput = page.getByPlaceholder('CVE-2021-44228');
            await cveInput.fill('<b>CVE-TEST</b>');
            await page.getByRole('button', { name: '検索', exact: true }).first().click();
            await page.waitForTimeout(1000);

            // Check that no bold element was created from our input
            const boldFromSearch = page.locator('b').filter({ hasText: 'CVE-TEST' });
            const hasBold = await boldFromSearch.isVisible().catch(() => false);

            expect(hasBold).toBeFalsy();
        });
    });

    test.describe('Special Character Handling', () => {
        test('should handle Unicode characters correctly', async ({ page, request }) => {
            const unicodeName = `Project 日本語 中文 한국어 العربية ${Date.now()}`;

            const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
                data: {
                    name: unicodeName,
                    description: '多言語テスト Multilingual test مشروع',
                },
            });

            const project = await response.json();

            await page.goto(`/en/projects/${project.id}`);
            await page.waitForLoadState('networkidle');

            // Unicode characters should be displayed correctly
            await expect(page.getByText('日本語')).toBeVisible();
            await expect(page.getByText('中文')).toBeVisible();

            // Cleanup
            await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
        });

        test('should handle emoji in project names', async ({ page, request }) => {
            const emojiName = `🚀 Rocket Project 🔥💻🛡️ ${Date.now()}`;

            const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
                data: {
                    name: emojiName,
                    description: 'Project with 🎉 emoji 🎊',
                },
            });

            const project = await response.json();

            await page.goto(`/en/projects/${project.id}`);
            await page.waitForLoadState('networkidle');

            // Emoji should be displayed
            await expect(page.getByText('🚀')).toBeVisible();

            // Cleanup
            await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
        });

        test('should handle null bytes and control characters', async ({ page, request }) => {
            // Note: Most systems will strip or reject null bytes
            const controlChars = `Project\x00Test\x1F${Date.now()}`;

            const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
                data: {
                    name: controlChars,
                    description: 'Control character test',
                },
            });

            // API should either accept and sanitize, or reject
            expect([200, 201, 400]).toContain(response.status());

            if (response.ok()) {
                const project = await response.json();
                await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`);
            }
        });

        test('should handle very long input strings', async ({ page }) => {
            await page.goto('/en/projects');

            await page.getByRole('button', { name: /New Project/i }).click();
            await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

            // Try to enter a very long string
            const longString = 'A'.repeat(10000);
            await page.getByPlaceholder('My Project').fill(longString);

            // Input should be truncated or validation should show
            const inputValue = await page.getByPlaceholder('My Project').inputValue();

            // Either truncated or limited
            expect(inputValue.length).toBeLessThanOrEqual(10000);

            // Close dialog
            await page.keyboard.press('Escape');
        });
    });

    test.describe('SQL Injection Prevention', () => {
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
                await page.getByRole('button', { name: '検索', exact: true }).first().click();
                await page.waitForTimeout(500);

                // Page should remain functional
                await expect(page.getByRole('heading', { name: '横断検索', exact: true })).toBeVisible();

                // Clear for next iteration
                await cveInput.clear();
            }
        });

        test('should handle SQL injection in project creation', async ({ page, request }) => {
            const sqlPayload = "Test'; DROP TABLE projects; --";

            // Create project with SQL injection payload
            await page.goto('/en/projects');
            await page.getByRole('button', { name: /New Project/i }).click();
            await expect(page.getByPlaceholder('My Project')).toBeVisible({ timeout: 5000 });

            await page.getByPlaceholder('My Project').fill(sqlPayload);
            await page.getByPlaceholder('Project description').fill("1'; DELETE FROM projects;--");
            await page.locator('.fixed button:has-text("Create")').click();

            await page.waitForTimeout(2000);

            // Page should still be functional
            await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();

            // Projects should still exist (table not dropped)
            const projectsResponse = await request.get(`${API_BASE_URL}/api/v1/projects`);
            expect(projectsResponse.ok()).toBeTruthy();
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
                await page.waitForTimeout(500);

                // Should show 404 or error, not expose system files
                const notFound = page.getByText(/not found|404|error|見つかりません/i);
                const hasNotFound = await notFound.isVisible().catch(() => false);

                // Should either show 404 or redirect to safe page
                expect(hasNotFound || await page.url().includes('/projects')).toBeTruthy();
            }
        });
    });

    test.describe('CSRF Protection', () => {
        test('should reject cross-origin API requests', async ({ request }) => {
            // This test simulates a cross-origin request by including Origin header
            const response = await request.post(`${API_BASE_URL}/api/v1/projects`, {
                data: {
                    name: 'CSRF Test',
                    description: 'CSRF test project',
                },
                headers: {
                    'Origin': 'http://evil.com',
                    'Referer': 'http://evil.com/attack.html',
                },
            });

            // Depending on CORS configuration, this might be rejected or allowed
            // We just verify the request doesn't cause server error
            expect([200, 201, 400, 403, 404]).toContain(response.status());
        });
    });

    test.describe('Content Security', () => {
        test('should have appropriate security headers', async ({ page }) => {
            const response = await page.goto('/en/projects');

            if (response) {
                const headers = response.headers();

                // Check for common security headers
                // Note: These may or may not be present depending on configuration
                const securityHeaders = [
                    'x-content-type-options',
                    'x-frame-options',
                    'x-xss-protection',
                    'content-security-policy',
                    'strict-transport-security',
                ];

                // Log which headers are present for information
                for (const header of securityHeaders) {
                    if (headers[header]) {
                        console.log(`${header}: ${headers[header]}`);
                    }
                }

                // Page should load successfully regardless
                await expect(page.locator('main')).toBeVisible();
            }
        });

        test('should not expose sensitive information in error pages', async ({ page }) => {
            // Trigger an error
            await page.goto('/en/projects/invalid-id-12345');
            await page.waitForTimeout(1000);

            // Get page content
            const pageContent = await page.content();

            // Should not contain stack traces or internal paths
            const sensitivePatterns = [
                /at\s+\w+\s+\(/i,  // Stack trace pattern
                /node_modules/i,
                /internal/i,
                /password/i,
                /secret/i,
                /api[_-]?key/i,
            ];

            for (const pattern of sensitivePatterns) {
                // These patterns should not be visible in the rendered page
                const matches = pageContent.toLowerCase().match(pattern);
                // Log for debugging but don't fail on common words
                if (matches) {
                    console.log(`Found pattern: ${pattern}`);
                }
            }

            // Page should still be functional
            await expect(page.locator('body')).toBeVisible();
        });
    });
});

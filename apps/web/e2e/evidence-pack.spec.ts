import { test, expect, type Page } from '@playwright/test';

// M31 F406 (#141) — Evidence Pack format toggle (Markdown / Zip).
//
// The project detail page grows a format <select> next to the "Build
// Evidence Pack" button. Markdown keeps the original text bundle download;
// Zip requests the machine-readable submittable bundle (application/zip)
// and triggers a browser download of the binary blob.
//
// The POST /evidence-pack/build endpoint is fully mock-intercepted
// (page.route) so the web render + download contract is exercised
// deterministically with no backend seed — CI never provisions approved
// VEX / CRA / METI rows, and the real Zip assembly (byte-determinism,
// manifest sha256, approved-only bundling) is covered by the Wave A / F405
// real builder tests (issue #140). This pins only the web layer:
//   - the format toggle renders with both options
//   - selecting Zip POSTs {format:"zip"} and downloads the blob with the
//     Content-Disposition filename
//   - Markdown still POSTs the markdown path and downloads
//   - an HTTP error (403 / 400) is surfaced to the operator, not swallowed
//
// The endpoint is intercepted host-agnostically (**/api/v1/...) so the
// intercept holds regardless of the NEXT_PUBLIC_API_URL the web build
// points at.

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// Helper to check if the page was redirected to sign-in (SaaS/auth mode).
async function isRedirectedToSignIn(page: Page): Promise<boolean> {
  const url = page.url();
  return url.includes('/sign-in') || url.includes('/login');
}

test.describe('Evidence Pack format toggle (M31 F406)', () => {
  let projectId: string;

  test.beforeAll(async ({ request }) => {
    const projectResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `Evidence Pack Test Project ${Date.now()}`,
        description: 'Project for Evidence Pack format toggle E2E tests',
      },
    });
    const project = await projectResponse.json();
    projectId = project.id;
  });

  test.afterAll(async ({ request }) => {
    if (projectId) {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    }
  });

  test('renders the format toggle with Markdown + Zip options', async ({ page }) => {
    await page.goto(`/en/projects/${projectId}`);
    await page.waitForLoadState('networkidle');
    if (await isRedirectedToSignIn(page)) return;

    const select = page.getByTestId('evidence-pack-format');
    await expect(select).toBeVisible({ timeout: 10000 });
    // Both formats are offered; Zip is the default (machine-readable,
    // matches the CLI default).
    await expect(select).toHaveValue('zip');
    await expect(select.locator('option')).toHaveCount(2);
    await expect(select.locator('option[value="zip"]')).toHaveCount(1);
    await expect(select.locator('option[value="markdown"]')).toHaveCount(1);
    await expect(page.getByTestId('evidence-pack-build')).toBeVisible();
  });

  test('selecting Zip POSTs format:"zip" and downloads the binary blob', async ({ page }) => {
    // Accept the success alert() the handler fires after the download.
    page.on('dialog', (dialog) => dialog.accept());

    let sentFormat: string | undefined;
    let contentType: string | undefined;
    await page.route('**/api/v1/projects/*/evidence-pack/build', async (route) => {
      const bodyText = route.request().postData() || '{}';
      try {
        sentFormat = JSON.parse(bodyText).format;
      } catch {
        sentFormat = undefined;
      }
      contentType = route.request().headers()['content-type'];
      await route.fulfill({
        status: 200,
        contentType: 'application/zip',
        headers: {
          // Replicate production CORS exposure (main.go ExposeHeaders): a
          // cross-origin fetch can only read these headers when the server
          // lists them in Access-Control-Expose-Headers. Without it the
          // browser hides Content-Disposition → download falls back to the
          // UUID filename (the F406 CI failure).
          'Access-Control-Expose-Headers':
            'Content-Disposition, X-Evidence-Pack-Format, X-Evidence-Pack-VEX-Count, X-Evidence-Pack-CRA-Count',
          'Content-Disposition': 'attachment; filename="evidence-pack-demo-20260704.zip"',
          'X-Evidence-Pack-Format': 'zip',
          'X-Evidence-Pack-VEX-Count': '2',
          'X-Evidence-Pack-CRA-Count': '1',
        },
        // Any bytes suffice: the web download path only blobs + saves them.
        body: 'PKmock-zip-bytes',
      });
    });

    await page.goto(`/en/projects/${projectId}`);
    await page.waitForLoadState('networkidle');
    if (await isRedirectedToSignIn(page)) return;

    const select = page.getByTestId('evidence-pack-format');
    await expect(select).toBeVisible({ timeout: 10000 });
    await select.selectOption('zip');

    const downloadPromise = page.waitForEvent('download');
    await page.getByTestId('evidence-pack-build').click();
    const download = await downloadPromise;

    // The Zip path was requested and the server filename honoured.
    expect(sentFormat).toBe('zip');
    expect(contentType).toContain('application/json'); // request body is JSON
    expect(download.suggestedFilename()).toBe('evidence-pack-demo-20260704.zip');
  });

  test('Markdown still POSTs the markdown path and downloads', async ({ page }) => {
    page.on('dialog', (dialog) => dialog.accept());

    let sentFormat: string | undefined;
    await page.route('**/api/v1/projects/*/evidence-pack/build', async (route) => {
      const bodyText = route.request().postData() || '{}';
      try {
        sentFormat = JSON.parse(bodyText).format;
      } catch {
        sentFormat = undefined;
      }
      await route.fulfill({
        status: 200,
        contentType: 'text/markdown',
        headers: {
          'Access-Control-Expose-Headers':
            'Content-Disposition, X-Evidence-Pack-Format, X-Evidence-Pack-VEX-Count, X-Evidence-Pack-CRA-Count',
          'Content-Disposition': 'attachment; filename="evidence-pack-demo-20260704.md"',
          'X-Evidence-Pack-Format': 'markdown',
          'X-Evidence-Pack-VEX-Count': '0',
          'X-Evidence-Pack-CRA-Count': '0',
        },
        body: '# Evidence Pack\n\nmock markdown bundle\n',
      });
    });

    await page.goto(`/en/projects/${projectId}`);
    await page.waitForLoadState('networkidle');
    if (await isRedirectedToSignIn(page)) return;

    const select = page.getByTestId('evidence-pack-format');
    await expect(select).toBeVisible({ timeout: 10000 });
    await select.selectOption('markdown');

    const downloadPromise = page.waitForEvent('download');
    await page.getByTestId('evidence-pack-build').click();
    const download = await downloadPromise;

    expect(sentFormat).toBe('markdown');
    expect(download.suggestedFilename()).toBe('evidence-pack-demo-20260704.md');
  });

  test('surfaces an HTTP error (403) instead of swallowing it', async ({ page }) => {
    // Capture the alert() message so we can assert the backend error is
    // surfaced verbatim, not swallowed to a silent no-op.
    const dialogMessages: string[] = [];
    page.on('dialog', (dialog) => {
      dialogMessages.push(dialog.message());
      dialog.accept();
    });

    await page.route('**/api/v1/projects/*/evidence-pack/build', (route) =>
      route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'write permission required' }),
      }),
    );

    await page.goto(`/en/projects/${projectId}`);
    await page.waitForLoadState('networkidle');
    if (await isRedirectedToSignIn(page)) return;

    const select = page.getByTestId('evidence-pack-format');
    await expect(select).toBeVisible({ timeout: 10000 });

    await page.getByTestId('evidence-pack-build').click();

    // The failure alert fires with the backend's honest message; no
    // download event occurs on the error path.
    await expect.poll(() => dialogMessages.length, { timeout: 10000 }).toBeGreaterThan(0);
    expect(dialogMessages.join(' ')).toMatch(/write permission required/i);
  });
});

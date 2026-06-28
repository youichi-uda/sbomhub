import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000';
const serverPort = new URL(baseURL).port || '3000';
const apiBaseURL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// PLAYWRIGHT_SKIP_WEB_SERVER=1 disables the bundled `npm run dev:test`
// launcher so the test runner targets an externally-managed server
// (e.g. a docker compose stack in CI, see .github/workflows/web-e2e.yml).
// When unset (local dev default), Playwright spins up the dev:test server
// and reuses it across runs.
const skipWebServer = process.env.PLAYWRIGHT_SKIP_WEB_SERVER === '1';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI
    ? [['html', { open: 'never' }], ['list']]
    : 'html',
  use: {
    baseURL,
    trace: process.env.CI ? 'retain-on-failure' : 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: skipWebServer
    ? undefined
    : {
        // Use dev:test script that runs with auth disabled (self-hosted mode)
        command: 'npm run dev:test',
        url: baseURL,
        // Reuse existing server if available (faster development)
        reuseExistingServer: !process.env.CI,
        timeout: 120000,
        env: {
          PORT: serverPort,
          NEXT_PUBLIC_API_URL: apiBaseURL,
          NEXT_PUBLIC_APP_URL: baseURL,
        },
      },
});

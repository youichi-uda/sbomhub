import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000';
const serverPort = new URL(baseURL).port || '3000';
const apiBaseURL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
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

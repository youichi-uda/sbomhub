// SBOMHub - Web smoke (api/v1/health reachability) — M8 #67
//
// This spec proves the api the web image talks to is reachable from the
// **same network the tests run on**. In CI that is the GitHub Actions
// host, hitting the docker-compose-published port via
// PLAYWRIGHT_API_URL. Locally it falls back to http://localhost:8080,
// matching docker-compose.yml.
//
// We deliberately do NOT route through the browser context: this is an
// origin/reachability check, not a CORS or cookie check. The
// authenticated component-list / vulnerability endpoints are exercised
// by golden-path-e2e.yml (apps/api side, curl + jq). Here we only pin
// the always-public /api/v1/health contract:
//   - status 200
//   - body.status === "ok"
//   - body.mode is a non-empty string (records which auth mode the api
//     booted in; presence proves the response actually came from our api
//     and not from an intermediate proxy returning a generic 200)
import { test, expect } from '@playwright/test';

const apiBaseURL =
  process.env.PLAYWRIGHT_API_URL ||
  process.env.API_BASE_URL ||
  'http://localhost:8080';

test.describe('API health endpoint reachability', () => {
  test('GET /api/v1/health returns status=ok', async ({ request }) => {
    const response = await request.get(`${apiBaseURL}/api/v1/health`);
    expect(response.ok(), `expected 2xx from ${apiBaseURL}/api/v1/health, got ${response.status()}`).toBeTruthy();
    expect(response.status()).toBe(200);

    const body = (await response.json()) as { status?: string; mode?: string };
    expect(body.status).toBe('ok');
    expect(
      typeof body.mode === 'string' && body.mode.length > 0,
      `expected non-empty body.mode, got ${JSON.stringify(body)}`,
    ).toBeTruthy();
  });
});

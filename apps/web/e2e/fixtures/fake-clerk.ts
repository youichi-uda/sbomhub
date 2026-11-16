// A stand-in for Clerk, so the Clerk-mode ("login mode") dashboard can be
// driven without real Clerk keys or network access.
//
// The web app has to be BUILT in Clerk mode (NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
// is inlined at build time) with FAKE_CLERK_PUBLISHABLE_KEY below, and started
// with:
//   CLERK_SECRET_KEY=sk_live_<anything>
//   CLERK_API_URL=http://localhost:<FAKE_CLERK_BAPI_PORT>
// Two halves are faked:
//   - server: clerkMiddleware verifies the `__session` cookie against the JWKS
//     it fetches from CLERK_API_URL/v1/jwks. startFakeBackendApi() serves a
//     key this file generated, and mintSessionToken() signs with it, so the
//     middleware sees a signed-in user with an active organization. A
//     production (pk_live) key is used because a development key needs Clerk's
//     dev-browser handshake.
//   - browser: ClerkProvider loads clerk-js and the Clerk UI bundle from the
//     key's frontend API host, which does not exist; routeFakeClerkJs()
//     answers those requests with a minimal Clerk object that is loaded,
//     signed in, and mounts an OrganizationSwitcher trigger shaped like
//     Clerk's (avatar, then the name in a column text container, then a
//     chevron; nothing in it shrinks or truncates by itself) and honouring
//     the `appearance.elements` classes the app passes, under Clerk's
//     element keys.
//
// LIMIT: the switcher is a stand-in. It proves how the app's header lays out
// around a switcher of that shape, not how Clerk's own component renders.

import { createServer, type Server } from 'node:http';
import { createSign, generateKeyPairSync, randomUUID, type KeyObject } from 'node:crypto';
import type { BrowserContext, Page } from '@playwright/test';

export const FAKE_CLERK_FRONTEND_API = 'clerk.sbomhub-e2e.test';
/** pk_live_ + base64("clerk.sbomhub-e2e.test$"): build the web app with this. */
export const FAKE_CLERK_PUBLISHABLE_KEY = `pk_live_${Buffer.from(`${FAKE_CLERK_FRONTEND_API}$`).toString('base64')}`;
export const FAKE_CLERK_BAPI_PORT = Number(process.env.PLAYWRIGHT_CLERK_BAPI_PORT || 13522);
/** The Clerk-mode web app, if one is running (see the header of this file). */
export const CLERK_BASE_URL = process.env.PLAYWRIGHT_CLERK_BASE_URL || '';

// A new kid per run: the middleware caches the JWKS by kid, so a reused kid
// with a new key would fail verification against the cached one.
const KID = `ins_e2e_${randomUUID()}`;
let keys: { privateKey: KeyObject; publicKey: KeyObject } | undefined;
function keyPair() {
  keys ??= generateKeyPairSync('rsa', { modulusLength: 2048 });
  return keys;
}

/** Serves GET /v1/jwks with this run's public key. */
export async function startFakeBackendApi(port = FAKE_CLERK_BAPI_PORT): Promise<Server> {
  if (CLERK_BASE_URL) assertLocalTarget(CLERK_BASE_URL);
  const jwk = { ...keyPair().publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };
  const server = createServer((req, res) => {
    if (req.method === 'GET' && req.url?.split('?')[0] === '/v1/jwks') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ errors: [{ code: 'not_found' }] }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return server;
}

const b64url = (v: object | Buffer) => (Buffer.isBuffer(v) ? v : Buffer.from(JSON.stringify(v))).toString('base64url');

export interface FakeOrg {
  id: string;
  name: string;
  slug: string;
}

/** An RS256 session token (v1 claims) for `sub` in `org`, valid for an hour. */
export function mintSessionToken(origin: string, org: FakeOrg, sub = 'user_e2e_fake'): { token: string; iat: number } {
  assertLocalTarget(origin);
  const iat = Math.floor(Date.now() / 1000) - 5;
  const header = { alg: 'RS256', typ: 'JWT', kid: KID };
  const payload = {
    iss: `https://${FAKE_CLERK_FRONTEND_API}`,
    sub,
    sid: 'sess_e2e_fake',
    azp: origin,
    iat,
    nbf: iat,
    exp: iat + 3600,
    org_id: org.id,
    org_role: 'org:admin',
    org_slug: org.slug,
    org_permissions: [],
  };
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const signature = createSign('RSA-SHA256').update(signingInput).sign(keyPair().privateKey);
  return { token: `${signingInput}.${b64url(signature)}`, iat };
}

/**
 * The fixture mints an org:admin session: it only ever targets this machine
 * (Codex R1 Medium). A deployment that verifies against real Clerk would
 * reject the token anyway; this keeps it from being aimed elsewhere at all.
 */
export function assertLocalTarget(url: string): void {
  const host = new URL(url).hostname;
  if (!['localhost', '127.0.0.1', '[::1]', '::1'].includes(host)) {
    throw new Error(`fake Clerk: refusing non-loopback target ${url}`);
  }
}

/** Sets the cookies clerkMiddleware reads for a signed-in browser. */
export async function signIn(context: BrowserContext, baseURL: string, org: FakeOrg): Promise<string> {
  assertLocalTarget(baseURL);
  const { origin } = new URL(baseURL);
  const { token, iat } = mintSessionToken(origin, org);
  await context.addCookies([
    { name: '__session', value: token, url: origin },
    { name: '__client_uat', value: String(iat), url: origin },
  ]);
  return token;
}

function clerkJsStub(org: FakeOrg, token: string): string {
  return `(() => {
  const org = ${JSON.stringify({ ...org, imageUrl: '', hasImage: false, membersCount: 1, maxAllowedMemberships: 5, adminDeleteEnabled: true, publicMetadata: {} })};
  const membership = { id: 'orgmem_e2e', role: 'org:admin', permissions: [], organization: org, publicMetadata: {} };
  const user = {
    id: 'user_e2e_fake', firstName: 'E2E', lastName: 'User', fullName: 'E2E User', username: null,
    imageUrl: '', hasImage: false, primaryEmailAddress: { emailAddress: 'e2e@example.test' },
    emailAddresses: [{ emailAddress: 'e2e@example.test' }], organizationMemberships: [membership],
    publicMetadata: {}, unsafeMetadata: {},
  };
  const session = {
    id: 'sess_e2e_fake', status: 'active', user, actor: null, currentTask: undefined,
    lastActiveOrganizationId: org.id, factorVerificationAge: null,
    lastActiveToken: { getRawString: () => ${JSON.stringify(token)}, jwt: { claims: { sub: 'user_e2e_fake', sid: 'sess_e2e_fake', org_id: org.id, org_role: 'org:admin', org_slug: org.slug } } },
    getToken: async () => ${JSON.stringify(token)},
    checkAuthorization: () => true,
  };
  const client = { id: 'client_e2e', sessions: [session], signedInSessions: [session], activeSessions: [session], lastActiveSessionId: session.id };
  const resources = { client, session, user, organization: org };
  const listeners = new Set();
  const statusListeners = new Set();
  const cls = (elements, key) => (elements && typeof elements[key] === 'string' ? ' ' + elements[key] : '');
  const base = {
    loaded: false,
    version: '0.0.0-e2e-fake',
    frontendApi: ${JSON.stringify(FAKE_CLERK_FRONTEND_API)},
    publishableKey: ${JSON.stringify(FAKE_CLERK_PUBLISHABLE_KEY)},
    instanceType: 'production',
    isSatellite: false,
    isStandardBrowser: true,
    isSignedIn: true,
    client, session, user, organization: org,
    // What the React hooks read once loaded (useAuthBase and friends).
    __internal_lastEmittedResources: resources,
    async load() { this.loaded = true; },
    addListener(fn, opts) { listeners.add(fn); if (!(opts && opts.skipInitialEmit)) fn(resources); return () => listeners.delete(fn); },
    on(event, fn, opts) { if (event === 'status') { statusListeners.add(fn); if (opts && opts.notify) fn('ready'); } },
    off(event, fn) { statusListeners.delete(fn); },
    async signOut() {},
    async setActive() {},
    __internal_getOption() { return undefined; },
    mountOrganizationSwitcher(node, props) {
      const el = (props && props.appearance && props.appearance.elements) || {};
      node.innerHTML =
        '<div class="cl-rootBox cl-organizationSwitcher-root' + cls(el, 'rootBox') + '" data-fake-clerk="organization-switcher">' +
        '<button type="button" aria-label="Open organization switcher" class="cl-organizationSwitcherTrigger' + cls(el, 'organizationSwitcherTrigger') + '" style="display:flex;align-items:center;gap:0.5rem">' +
        '<span class="cl-organizationPreview' + cls(el, 'organizationPreview') + '" style="display:flex;align-items:center;gap:0.5rem;min-width:0">' +
        '<span class="cl-organizationPreviewAvatarBox' + cls(el, 'organizationPreviewAvatarBox') + '" style="flex:none;width:1.25rem;height:1.25rem;border-radius:0.25rem;background:#6c47ff"></span>' +
        '<span class="cl-organizationPreviewTextContainer' + cls(el, 'organizationPreviewTextContainer') + '" style="display:flex;flex-direction:column">' +
        '<span class="cl-organizationPreviewMainIdentifier' + cls(el, 'organizationPreviewMainIdentifier') + '" style="white-space:nowrap">' + org.name.replace(/</g, '&lt;') + '</span>' +
        '</span></span>' +
        '<svg width="16" height="16" viewBox="0 0 16 16" style="flex:none" aria-hidden="true"><path d="M4 6l4 4 4-4" stroke="currentColor" fill="none"/></svg>' +
        '</button></div>';
    },
    unmountOrganizationSwitcher(node) { node.innerHTML = ''; },
  };
  const noop = () => {};
  window.Clerk = new Proxy(base, {
    get(target, key) {
      if (key in target) return target[key];
      if (typeof key === 'string' && /^(mount|unmount|open|close|redirect|__internal_|__experimental_|navigate|handle|authenticate|build|create|join|set)/.test(key)) return noop;
      return undefined;
    },
  });
})();`;
}

/** Answers the browser's requests for clerk-js / Clerk UI with the stub. */
export async function routeFakeClerkJs(page: Page, org: FakeOrg, token: string): Promise<{ scripts: string[] }> {
  const scripts: string[] = [];
  await page.route(
    (url) => url.hostname === FAKE_CLERK_FRONTEND_API,
    async (route) => {
      const path = new URL(route.request().url()).pathname;
      scripts.push(path);
      if (/clerk-js|clerk\.browser/.test(path)) {
        return route.fulfill({ contentType: 'application/javascript', body: clerkJsStub(org, token) });
      }
      if (/@clerk\/ui|clerk-ui|\/ui\b/.test(path)) {
        return route.fulfill({ contentType: 'application/javascript', body: 'window.__internal_ClerkUICtor = class { constructor() {} };' });
      }
      return route.fulfill({ status: 404, contentType: 'application/json', body: '{"errors":[{"code":"not_found"}]}' });
    },
  );
  return { scripts };
}

import createNextIntlPlugin from 'next-intl/plugin';
import { buildSecurityHeaders } from './security-headers.mjs';

// Debug: log env vars at config load time
console.log('=== NEXT CONFIG ENV ===');
console.log('CLERK:', process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY ? 'SET' : 'EMPTY');
console.log('API:', process.env.NEXT_PUBLIC_API_URL ? 'SET' : 'EMPTY');
console.log('=======================');

const withNextIntl = createNextIntlPlugin('./src/i18n/request.ts');

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // M65 bug 9: no `X-Powered-By: Next.js`, and security headers (nosniff,
  // frame denial, Referrer-Policy, Permissions-Policy) on every route. The
  // CSP carries a per-request nonce and is set by src/proxy.ts (M71). See
  // security-headers.mjs for the policy and why.
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: buildSecurityHeaders() }];
  },
  env: {
    NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY,
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL,
    // Build-time switch read by src/proxy.ts (CSP as Report-Only).
    SBOMHUB_CSP_REPORT_ONLY: process.env.SBOMHUB_CSP_REPORT_ONLY ?? '',
  },
};

export default withNextIntl(nextConfig);

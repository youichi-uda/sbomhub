import createNextIntlPlugin from 'next-intl/plugin';
import { securityHeadersFromProcessEnv } from './security-headers.mjs';

// Debug: log env vars at config load time
console.log('=== NEXT CONFIG ENV ===');
console.log('CLERK:', process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY ? 'SET' : 'EMPTY');
console.log('API:', process.env.NEXT_PUBLIC_API_URL ? 'SET' : 'EMPTY');
console.log('=======================');

const withNextIntl = createNextIntlPlugin('./src/i18n/request.ts');

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // M65 bug 9: no `X-Powered-By: Next.js`, and security headers (CSP,
  // nosniff, frame denial, Referrer-Policy, Permissions-Policy) on every
  // route. See security-headers.mjs for the policy and why.
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: securityHeadersFromProcessEnv(process.env) }];
  },
  env: {
    NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY,
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL,
  },
};

export default withNextIntl(nextConfig);

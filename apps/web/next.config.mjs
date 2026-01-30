import createNextIntlPlugin from 'next-intl/plugin';

// Debug: log env vars at config load time
console.log('=== NEXT CONFIG ENV ===');
console.log('CLERK:', process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY ? 'SET' : 'EMPTY');
console.log('API:', process.env.NEXT_PUBLIC_API_URL ? 'SET' : 'EMPTY');
console.log('=======================');

const withNextIntl = createNextIntlPlugin('./src/i18n/request.ts');

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  env: {
    NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY,
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL,
  },
};

export default withNextIntl(nextConfig);

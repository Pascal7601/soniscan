// next.config.ts
import type { NextConfig } from 'next';

const backend = process.env.BACKEND_URL ?? 'http://127.0.0.1:8000';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Without this Next redirects /x/ to /x before the rewrite runs.
  skipTrailingSlashRedirect: true,
  async rewrites() {
    return [
      // allauth's headless endpoints have NO trailing slash.
      { source: '/api/auth/browser/:path*', destination: `${backend}/api/auth/browser/:path*` },
      // Everything else on Django ends with a slash (REST views, docs, social callbacks),
      // and Next drops it when proxying, so put it back.
      { source: '/api/:path*', destination: `${backend}/api/:path*/` },
    ];
  },
};

export default nextConfig;
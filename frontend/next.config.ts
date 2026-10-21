import type { NextConfig } from "next";

// The browser only ever talks to this origin. /api/* is proxied to Django, so session cookies
// stay same-site and no CORS configuration is needed.
const backend = process.env.BACKEND_URL ?? "http://localhost:8000";

const config: NextConfig = {
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
  },
};

export default config;

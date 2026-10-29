import type { NextConfig } from "next";

const apiOrigin = process.env.OID_API_URL ?? "http://127.0.0.1:8784";

const parsedApiOrigin = new URL(apiOrigin);
if (parsedApiOrigin.pathname !== "/" || parsedApiOrigin.search || parsedApiOrigin.hash) {
  throw new Error("OID_API_URL must be an origin without a path, query, or fragment");
}

const nextConfig: NextConfig = {
  logging: { incomingRequests: false },
  experimental: { cpus: 2 },
  async rewrites() {
    return [
      {
        source: "/.well-known/oauth-authorization-server/api/auth",
        destination: `${parsedApiOrigin.origin}/api/auth/.well-known/oauth-authorization-server`,
      },
      {
        source: "/.well-known/oauth-protected-resource/api/agent",
        destination: `${parsedApiOrigin.origin}/.well-known/oauth-protected-resource/api/agent`,
      },
      {
        source: "/api/:path*",
        destination: `${parsedApiOrigin.origin}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;

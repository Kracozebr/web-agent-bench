import type { NextConfig } from "next";

const apiOrigin = process.env.OID_API_URL ?? "http://127.0.0.1:8784";

const parsedApiOrigin = new URL(apiOrigin);
if (parsedApiOrigin.pathname !== "/" || parsedApiOrigin.search || parsedApiOrigin.hash) {
  throw new Error("OID_API_URL must be an origin without a path, query, or fragment");
}

const nextConfig: NextConfig = {
  logging: { incomingRequests: false },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${parsedApiOrigin.origin}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;

import assert from "node:assert/strict";
import test from "node:test";
import Fastify from "fastify";
import { allowedAgentRequestHosts } from "./agents.js";
import type { OwnerDatabase } from "./db.js";
import { registerRunRoutes, type RunRouteDependencies } from "./run-routes.js";

const PUBLIC_ORIGIN = "https://bench.example";
const CONFIGURED_API_HOST = "127.0.0.2:8784";
const runId = "019a1122-3344-7556-8778-99aabbccddee";
const actionId = "019a1122-3344-7556-8778-99aabbccddef";
const intentId = "019a1122-3344-7556-8778-99aabbccddea";

const agentRoutes = [
  { name: "accept", method: "POST" as const, url: `/api/agent/run-intents/${intentId}/accept`, payload: { operationId: "accept-operation-0001" } },
  { name: "current-task", method: "GET" as const, url: `/api/agent/runs/${runId}/current-task` },
  { name: "action-status", method: "GET" as const, url: `/api/agent/runs/${runId}/actions/${actionId}` },
  { name: "admit-action", method: "POST" as const, url: `/api/agent/runs/${runId}/tasks/0/actions`, payload: { operationId: "action-operation-0001" } },
  { name: "finish-task", method: "POST" as const, url: `/api/agent/runs/${runId}/tasks/0/finish`, payload: { operationId: "finish-operation-0001" } },
];

function makeDependencies(withConfiguredHosts = true): RunRouteDependencies {
  return {
    db: {} as OwnerDatabase,
    publicOrigin: PUBLIC_ORIGIN,
    ...(withConfiguredHosts ? { agentRequestHosts: allowedAgentRequestHosts({
      publicOrigin: PUBLIC_ORIGIN, apiHost: "127.0.0.2", apiPort: 8784,
    }) } : {}),
    resolveOwner: async () => { throw new Error("owner routes are outside this test"); },
    resolveAgentPrincipal: async () => undefined,
    requireOrigin: async () => undefined,
    rateLimit: async () => undefined,
    rateLimitMax: 10,
  };
}

async function withRunRoutes<T>(withConfiguredHosts: boolean, run: (app: ReturnType<typeof Fastify>) => Promise<T>): Promise<T> {
  const app = Fastify({ logger: false, trustProxy: false });
  registerRunRoutes(app, makeDependencies(withConfiguredHosts));
  try {
    await app.ready();
    return await run(app);
  } finally {
    await app.close();
  }
}

function requestFor(route: (typeof agentRoutes)[number], headers: Record<string, string> = {}) {
  return {
    method: route.method,
    url: route.url,
    headers: {
      ...(route.payload ? { "content-type": "application/json" } : {}),
      ...headers,
    },
    ...(route.payload ? { payload: route.payload } : {}),
  };
}

test("all run-agent routes accept configured hosts but still require bearer credentials", async () => {
  await withRunRoutes(true, async (app) => {
    for (const route of agentRoutes) {
      for (const host of ["bench.example", CONFIGURED_API_HOST]) {
        const response = await app.inject(requestFor(route, { host }));
        assert.equal(response.statusCode, 401, `${route.name} on ${host} must reach bearer authentication`);
      }
    }
  });
});

test("all run-agent routes reject unknown hosts even when forwarded host is allowed", async () => {
  await withRunRoutes(true, async (app) => {
    for (const route of agentRoutes) {
      const response = await app.inject(requestFor(route, {
        host: "attacker.example", "x-forwarded-host": "bench.example",
      }));
      assert.equal(response.statusCode, 421, `${route.name} must ignore x-forwarded-host`);
    }
  });
});

test("all run-agent routes reject a mismatched Origin on each allowed host", async () => {
  await withRunRoutes(true, async (app) => {
    for (const route of agentRoutes) {
      for (const host of ["bench.example", CONFIGURED_API_HOST]) {
        const response = await app.inject(requestFor(route, { host, origin: "https://attacker.example" }));
        assert.equal(response.statusCode, 403, `${route.name} must reject an untrusted Origin`);
      }
    }
  });
});

test("omitting the optional host set retains public-origin-only behavior", async () => {
  await withRunRoutes(false, async (app) => {
    const publicResponse = await app.inject(requestFor(agentRoutes[1]!, { host: "bench.example" }));
    assert.equal(publicResponse.statusCode, 401);
    const backendResponse = await app.inject(requestFor(agentRoutes[1]!, { host: CONFIGURED_API_HOST }));
    assert.equal(backendResponse.statusCode, 421);
  });
});

test("configured host helper omits wildcard bind addresses and formats IPv6 host headers", () => {
  const wildcard = allowedAgentRequestHosts({ publicOrigin: PUBLIC_ORIGIN, apiHost: "0.0.0.0", apiPort: 8784 });
  assert.equal(wildcard.has("bench.example"), true);
  assert.equal(wildcard.has("0.0.0.0:8784"), false);
  const ipv6 = allowedAgentRequestHosts({ publicOrigin: PUBLIC_ORIGIN, apiHost: "::1", apiPort: 8784 });
  assert.equal(ipv6.has("[::1]:8784"), true);
});

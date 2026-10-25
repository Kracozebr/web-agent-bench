import { createConnection, createServer, type Server, type Socket } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

/**
 * Fixed TCP bridges for Docker Desktop hosts that do not publish ports from an
 * internal-only network. Ports are intentionally mapped in code: callers cannot
 * choose a destination host or port, and Anvil's admin RPC is never exposed.
 */
const TARGETS = [
  { listenPort: 8783, host: "api", port: 3000 },
  { listenPort: 55432, host: "postgres", port: 5432 },
  { listenPort: 18545, host: "local-proxy-a", port: 8545 },
  { listenPort: 28545, host: "local-proxy-b", port: 8545 },
  { listenPort: 14021, host: "facilitator-a", port: 4021 },
  { listenPort: 24021, host: "facilitator-b", port: 4021 },
] as const;

const MAX_CONNECTIONS = 128;
const CONNECT_TIMEOUT_MS = 5_000;
const IDLE_TIMEOUT_MS = 120_000;

const activeSockets = new Set<Socket>();
const servers: Server[] = [];
let activeConnections = 0;

function bridge(client: Socket, host: string, port: number): void {
  if (activeConnections >= MAX_CONNECTIONS) {
    client.destroy();
    return;
  }

  activeConnections += 1;
  activeSockets.add(client);
  client.pause();
  client.setNoDelay(true);

  const upstream = createConnection({ host, port, allowHalfOpen: true });
  activeSockets.add(upstream);
  upstream.setNoDelay(true);

  let closed = false;
  let connectTimer: NodeJS.Timeout | undefined = setTimeout(() => {
    finish();
  }, CONNECT_TIMEOUT_MS);
  let idleTimer: NodeJS.Timeout | undefined;

  const clearTimers = (): void => {
    if (connectTimer) clearTimeout(connectTimer);
    if (idleTimer) clearTimeout(idleTimer);
    connectTimer = undefined;
    idleTimer = undefined;
  };

  const finalize = (): void => {
    if (closed) return;
    closed = true;
    activeConnections -= 1;
    activeSockets.delete(client);
    activeSockets.delete(upstream);
    clearTimers();
  };

  const finish = (): void => {
    finalize();
    client.destroy();
    upstream.destroy();
  };

  const refreshIdleTimeout = (): void => {
    if (closed || upstream.connecting) return;
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(finish, IDLE_TIMEOUT_MS);
  };

  client.on("data", refreshIdleTimeout);
  upstream.on("data", refreshIdleTimeout);
  client.on("error", finish);
  upstream.on("error", finish);
  client.on("close", () => {
    activeSockets.delete(client);
    const wasClosed = closed;
    finalize();
    if (!wasClosed) upstream.destroy();
  });
  upstream.on("close", () => {
    activeSockets.delete(upstream);
    const wasClosed = closed;
    finalize();
    if (!wasClosed) client.destroy();
  });

  upstream.once("connect", () => {
    if (connectTimer) clearTimeout(connectTimer);
    connectTimer = undefined;
    refreshIdleTimeout();
    client.pipe(upstream);
    upstream.pipe(client);
    client.resume();
  });
}

function listen(bind: string, target: (typeof TARGETS)[number]): Promise<Server> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const server = createServer({ allowHalfOpen: true }, (client) => {
      bridge(client, target.host, target.port);
    });
    server.on("error", () => {
      if (!settled) {
        settled = true;
        server.close(() => undefined);
        reject(new Error("BEF_GATEWAY_LISTEN_FAILED"));
        return;
      }
      void stopGateway().finally(() => {
        process.exitCode = 1;
      });
    });
    server.once("listening", () => {
      settled = true;
      resolve(server);
    });
    server.listen(target.listenPort, bind);
  });
}

export async function startGateway(): Promise<void> {
  const bindAddress = process.env.BEF_GATEWAY_BIND ?? "127.0.0.1";
  if (bindAddress !== "127.0.0.1" && bindAddress !== "0.0.0.0") {
    throw new Error("BEF_GATEWAY_BIND must be 127.0.0.1 or 0.0.0.0");
  }

  try {
    for (const target of TARGETS) servers.push(await listen(bindAddress, target));
  } catch {
    await stopGateway();
    throw new Error("BEF_GATEWAY_START_FAILED");
  }

  const shutdown = (): void => {
    void stopGateway().finally(() => process.exit(0));
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

async function stopGateway(): Promise<void> {
  for (const socket of activeSockets) socket.destroy();
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
        }),
    ),
  );
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  startGateway().catch(() => {
    process.stderr.write("BEF_GATEWAY_START_FAILED\n");
    process.exitCode = 1;
  });
}

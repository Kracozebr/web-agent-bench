import assert from 'node:assert/strict';
import { createConnection, createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { createBefObservationPorts } from './bef-observation-ports.js';

const TEST_ENABLED = process.env.BEF_OBSERVER_RECONNECT_PG_TEST === '1';
const OBSERVER_PORT = Number(process.env.BEF_DATABASE_OBSERVER_HOST_PORT ?? process.env.BEF_DATABASE_HOST_PORT ?? '55432');
const DROPPED_CONNECTIONS_PER_CYCLE = 12;
const MAX_RECONNECT_GAP_MS = 1_500;
const CONNECT_TIMEOUT_MS = 30_000;
const ENVIRONMENT_ID = 'bef-env-a';

/**
 * A loopback TCP proxy which resets the next N incoming PostgreSQL connections, then forwards
 * subsequent connections to the real BEF PostgreSQL observer endpoint. It records only timing and
 * counts, never protocol bytes or credentials.
 */
class ObserverReconnectProxy {
  readonly #server: Server;
  readonly #sockets = new Set<Socket>();
  readonly #attempts: number[] = [];
  #dropRemaining = 0;
  #dropped = 0;
  #port: number | null = null;

  constructor(private readonly upstreamPort: number) {
    this.#server = createServer((client) => this.#accept(client));
  }

  async listen(): Promise<number> {
    await new Promise<void>((resolveListen, rejectListen) => {
      this.#server.once('error', rejectListen);
      this.#server.listen(0, '127.0.0.1', () => {
        this.#server.off('error', rejectListen);
        resolveListen();
      });
    });
    const address = this.#server.address();
    if (!address || typeof address === 'string') throw new Error('observer_proxy_bind_failed');
    this.#port = (address as AddressInfo).port;
    return this.#port;
  }

  get port(): number {
    if (this.#port === null) throw new Error('observer_proxy_not_listening');
    return this.#port;
  }

  dropNextConnections(count: number): void {
    this.#attempts.length = 0;
    this.#dropped = 0;
    this.#dropRemaining = count;
  }

  attemptTimes(): readonly number[] { return [...this.#attempts]; }
  droppedCount(): number { return this.#dropped; }

  async close(): Promise<void> {
    for (const socket of this.#sockets) socket.destroy();
    await new Promise<void>((resolveClose) => this.#server.close(() => resolveClose()));
  }

  #accept(client: Socket): void {
    this.#sockets.add(client);
    client.once('close', () => this.#sockets.delete(client));
    client.on('error', () => undefined);
    this.#attempts.push(performance.now());

    if (this.#dropRemaining > 0) {
      this.#dropRemaining -= 1;
      this.#dropped += 1;
      // RST makes the postgres.js connection attempt observe an error and exercise its retry path.
      client.resetAndDestroy();
      return;
    }

    const upstream = createConnection({ host: 'host.docker.internal', port: this.upstreamPort });
    this.#sockets.add(upstream);
    upstream.once('close', () => this.#sockets.delete(upstream));
    upstream.on('error', () => client.destroy());
    client.on('close', () => upstream.destroy());
    client.pipe(upstream);
    upstream.pipe(client);
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    promise,
    new Promise<T>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('observer_reconnect_deadline_exceeded')), timeoutMs);
    }),
  ]).finally(() => { if (timer) clearTimeout(timer); });
}

async function readObserverSessionWithTransientReconnects(
  ports: Awaited<ReturnType<typeof createBefObservationPorts>>,
): Promise<unknown> {
  const deadline = performance.now() + CONNECT_TIMEOUT_MS;
  while (true) {
    try {
      return await ports.postgresByEnvironment[ENVIRONMENT_ID]!.withRepeatableRead(async (query) =>
        query(`SELECT current_user AS current_user,current_database() AS database_name,
            current_setting('transaction_read_only') AS transaction_read_only,
            current_setting('transaction_isolation') AS transaction_isolation`));
    } catch (error) {
      const code = error instanceof Error ? error.message : '';
      if (!['bef_observer_connection_unavailable', 'bef_observer_transaction_unavailable'].includes(code) ||
          performance.now() >= deadline) throw error;
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
    }
  }
}

test('observer PostgreSQL pool reconnects promptly after repeated real TCP resets', {
  skip: TEST_ENABLED ? false : 'set BEF_OBSERVER_RECONNECT_PG_TEST=1 in the pinned runtime to use the local BEF observer database',
  timeout: CONNECT_TIMEOUT_MS * 2 + 10_000,
}, async (t) => {
  assert.ok(Number.isSafeInteger(OBSERVER_PORT) && OBSERVER_PORT >= 1 && OBSERVER_PORT <= 65535,
    'BEF_DATABASE_OBSERVER_HOST_PORT must be a valid TCP port');

  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
  const passwordPath = resolve(repositoryRoot,
    'infrastructure/benchmark-environment/.local/secrets/database-observer-password');
  const password = (await readFile(passwordPath, 'utf8')).trim();
  assert.ok(password.length >= 16, 'BEF observer password file must be present in the pinned runtime');

  const proxy = new ObserverReconnectProxy(OBSERVER_PORT);
  await proxy.listen();
  try {
    for (let cycle = 0; cycle < 2; cycle += 1) {
      proxy.dropNextConnections(DROPPED_CONNECTIONS_PER_CYCLE);
      const ports = await createBefObservationPorts({
        repositoryRoot,
        database: { host: '127.0.0.1', port: proxy.port, database: 'bef', password },
        environments: [{ envId: ENVIRONMENT_ID, observerRpcUrl: 'http://127.0.0.1:1' }],
      });
      try {
        const rows = await withTimeout(readObserverSessionWithTransientReconnects(ports), CONNECT_TIMEOUT_MS);
        assert.ok(Array.isArray(rows));
        const session = (rows as Record<string, unknown>[])[0];
        assert.equal(session?.current_user, 'bef_observer');
        assert.equal(session?.database_name, 'bef');
        assert.equal(session?.transaction_read_only, 'on');
        assert.equal(session?.transaction_isolation, 'repeatable read');

        const attempts = proxy.attemptTimes();
        assert.equal(proxy.droppedCount(), DROPPED_CONNECTIONS_PER_CYCLE);
        assert.ok(attempts.length >= DROPPED_CONNECTIONS_PER_CYCLE + 1,
          `expected ${DROPPED_CONNECTIONS_PER_CYCLE} reset connections followed by a real PostgreSQL connection`);
        const retryGaps = attempts.slice(1, DROPPED_CONNECTIONS_PER_CYCLE + 1)
          .map((attempt, index) => attempt - attempts[index]!);
        t.diagnostic(`cycle=${cycle + 1} dropped=${proxy.droppedCount()} observedMaxReconnectGapMs=${Math.max(...retryGaps).toFixed(1)}`);
        assert.ok(retryGaps.every((gap) => gap <= MAX_RECONNECT_GAP_MS),
          `postgres.js reconnect gap exceeded ${MAX_RECONNECT_GAP_MS}ms`);
      } finally {
        await ports.close();
      }
    }
  } finally {
    await proxy.close();
  }
});

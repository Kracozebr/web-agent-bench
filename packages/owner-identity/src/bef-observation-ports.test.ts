import { makeChainCaptureFixture } from './task-chain-capture-packet.fixture.js';
import { validPaidDataCapturePacket } from './task-paid-data-capture-packet.fixture.js';
import { createS3CapturePacketFixture } from './task-s3-capture-packet.fixture.js';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  createBefObservationPorts,
  type BefObserverDatabaseConfig,
  type BefObservationPortsOptions,
} from './bef-observation-ports.js';
import { validM1CapturePacket } from './task-m1-capture-packet.fixture.js';

const ENV_ID = 'bef-env-a';
const OBSERVATION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/observation';
const PREPARATION_ID = 'd6512e1f-6f8d-4f2c-a854-9e558d57b260';
const GENERATION_ID = '66ba7f12-7d45-4d4f-9466-83415449b487';
const DB_PASSWORD = 'synthetic-observer-password-0123456789';

function database(): BefObserverDatabaseConfig {
  return { host: 'host.docker.internal', port: 55432, database: 'bef', password: DB_PASSWORD };
}

type TestPacket = {
  schemaVersion: string;
  classification: string;
  binding: { ownerId: string; agentId: string; runId: string; environmentId: string; releaseIdentity: string;
    manifestHash: string; caseId: string; caseHash: string; rubricHash: string; taskId: string };
  closure: { closureId: string; actionCutoffSequence: number; reconciledActionSequence: number };
  execution: { preparationId: string; leaseId: string; generationId: string; environmentId: string };
  ownerActions: Array<Record<string, unknown>>;
  [key: string]: unknown;
};

function validPacket(runId: string = randomUUID(), taskId: 'S1' | 'S2' | 'S4' = 'S1'): TestPacket {
  return {
    schemaVersion: `bts-${taskId.toLowerCase()}-run-observation-capture/v1`,
    classification: 'run_bound_observations_candidate_not_grade',
    binding: { ownerId: randomUUID(), agentId: randomUUID(), runId, environmentId: ENV_ID,
      releaseIdentity: 'synthetic-release', manifestHash: 'a'.repeat(64), caseId: `${taskId}.training.fixture`,
      caseHash: 'b'.repeat(64), rubricHash: 'c'.repeat(64), taskId },
    closure: { closureId: randomUUID(), actionCutoffSequence: 1, reconciledActionSequence: 1 },
    execution: { preparationId: PREPARATION_ID, leaseId: randomUUID(), generationId: GENERATION_ID,
      environmentId: ENV_ID },
    ownerActions: [],
  };
}

function sessionRow(overrides: Record<string, unknown> = {}) {
  return [{ current_user: 'bef_observer', session_user: 'bef_observer', database_name: 'bef',
    transaction_read_only: 'on', transaction_isolation: 'repeatable read', superuser: false, bypass_rls: false,
    ...overrides }];
}

function fakePool(options: { session?: Record<string, unknown>; queryRows?: Record<string, unknown>[] } = {}) {
  const statements: Array<{ statement: string; parameters: readonly unknown[] }> = [];
  let releases = 0;
  let ended = 0;
  const pool = {
    async reserve() {
      return {
        async unsafe(statement: string, parameters: readonly unknown[] = []): Promise<unknown> {
          statements.push({ statement, parameters });
          if (statement.includes('current_user AS current_user')) return sessionRow(options.session);
          if (statement.includes('FROM public.bef_generation')) return options.queryRows ?? [];
          return [{ value: parameters[0] ?? null }];
        },
        release() { releases += 1; },
      };
    },
    async end() { ended += 1; },
  };
  return { pool, statements, get releases() { return releases; }, get ended() { return ended; } };
}

async function makePorts(root: string, overrides: Partial<BefObservationPortsOptions> = {}) {
  const connection = fakePool();
  const ports = await createBefObservationPorts({
    repositoryRoot: root,
    database: database(),
    environments: [{ envId: ENV_ID, observerRpcUrl: 'http://host.docker.internal:18545' }],
    poolFactory: () => connection.pool,
    ...overrides,
  });
  return { ports, connection };
}

test('BEF observer queries run in verified repeatable-read read-only transactions', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bef-observation-ports-'));
  try {
    const { ports, connection } = await makePorts(root);
    const result = await ports.postgresByEnvironment[ENV_ID]!.withRepeatableRead(async (query) => {
      const rows = await query('SELECT $1 AS value', ['public']);
      assert.deepEqual(rows, [{ value: 'public' }]);
      return 'read';
    });
    assert.equal(result, 'read');
    assert.equal(connection.statements[0]?.statement, 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    assert.ok(connection.statements.some(({ statement }) => statement.startsWith('COMMIT')));
    assert.equal(connection.releases, 1);
    await ports.close();
    assert.equal(connection.ended, 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('observer role rejects superuser, bypass-RLS, wrong-role, and DML connections', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bef-observation-ports-'));
  try {
    const wrongRole = fakePool({ session: { ...sessionRow()[0], current_user: 'oid_owner', session_user: 'oid_owner' } });
    const wrongRolePorts = await createBefObservationPorts({ repositoryRoot: root, database: database(),
      environments: [{ envId: ENV_ID, observerRpcUrl: 'http://localhost:18545' }], poolFactory: () => wrongRole.pool });
    await assert.rejects(wrongRolePorts.postgresByEnvironment[ENV_ID]!.withRepeatableRead(async () => 'must not run'),
      (error: Error) => error.message === 'bef_observer_role_invalid');
    await wrongRolePorts.close();

    const superuser = fakePool({ session: { ...sessionRow()[0], superuser: true } });
    const ports = await createBefObservationPorts({ repositoryRoot: root, database: database(),
      environments: [{ envId: ENV_ID, observerRpcUrl: 'http://localhost:18545' }], poolFactory: () => superuser.pool });
    await assert.rejects(ports.postgresByEnvironment[ENV_ID]!.withRepeatableRead(async () => 'must not run'),
      (error: Error) => error.message === 'bef_observer_role_invalid');
    assert.ok(superuser.statements.some(({ statement }) => statement === 'ROLLBACK'));
    assert.equal(superuser.releases, 1);
    await ports.close();

    const bypass = fakePool({ session: { ...sessionRow()[0], bypass_rls: true } });
    const bypassPorts = await createBefObservationPorts({ repositoryRoot: root, database: database(),
      environments: [{ envId: ENV_ID, observerRpcUrl: 'http://localhost:18545' }], poolFactory: () => bypass.pool });
    await assert.rejects(bypassPorts.postgresByEnvironment[ENV_ID]!.withRepeatableRead(async () => 'must not run'),
      (error: Error) => error.message === 'bef_observer_role_invalid');
    await bypassPorts.close();

    const readOnly = fakePool();
    const readOnlyPorts = await createBefObservationPorts({ repositoryRoot: root, database: database(),
      environments: [{ envId: ENV_ID, observerRpcUrl: 'http://localhost:18545' }], poolFactory: () => readOnly.pool });
    await assert.rejects(readOnlyPorts.postgresByEnvironment[ENV_ID]!.withRepeatableRead(async (query) =>
      query('UPDATE public.bef_operation SET status=$1', ['settled'])),
    (error: Error) => error.message === 'bef_observer_query_not_read_only');
    assert.ok(readOnly.statements.some(({ statement }) => statement === 'ROLLBACK'));
    await readOnlyPorts.close();
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('fence proof is read through the same verified observer transaction and exact IDs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bef-observation-ports-'));
  try {
    const row = { generation_id: GENERATION_ID, env_id: ENV_ID, generation_status: 'fenced', fenced_at: '2026-10-28T00:00:00Z',
      preparation_id: PREPARATION_ID, preparation_status: 'fenced', fence_confirmed_at: '2026-10-28T00:00:01Z',
      preparation_generation_id: GENERATION_ID, public_pins_sha256: 'a'.repeat(64), manifest_sha256: 'b'.repeat(64),
      environment_manifest_hash: 'c'.repeat(64) };
    const connection = fakePool({ queryRows: [row] });
    const ports = await createBefObservationPorts({ repositoryRoot: root, database: database(),
      environments: [{ envId: ENV_ID, observerRpcUrl: 'http://localhost:18545' }], poolFactory: () => connection.pool });
    assert.deepEqual(await ports.postgresByEnvironment[ENV_ID]!.readFenceProof({ preparationId: PREPARATION_ID, generationId: GENERATION_ID }), {
      generation: { generation_id: GENERATION_ID, env_id: ENV_ID, status: 'fenced', fenced_at: '2026-10-28T00:00:00Z' },
      preparation: { preparation_id: PREPARATION_ID, status: 'fenced', fence_confirmed_at: '2026-10-28T00:00:01Z',
        preparation_generation_id: GENERATION_ID, public_pins_sha256: 'a'.repeat(64), manifest_sha256: 'b'.repeat(64),
        environment_manifest_hash: 'c'.repeat(64) },
    });
    assert.ok(connection.statements.some(({ statement }) => statement.includes('JOIN public.bef_preparation')));
    await assert.rejects(ports.postgresByEnvironment[ENV_ID]!.readFenceProof({ preparationId: 'bad', generationId: GENERATION_ID }),
      (error: Error) => error.message === 'bef_observer_fence_target_invalid');
    await ports.close();
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('RPC adapter allows bounded read methods and rejects signing methods and unsafe response envelopes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bef-observation-ports-'));
  try {
    const received: Array<{ url: string; init: RequestInit }> = [];
    const { ports } = await makePorts(root, { fetchImpl: async (input, init) => {
      received.push({ url: String(input), init: init ?? {} });
      const body = JSON.parse(String(init?.body)) as { id: number };
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: '0x1' }),
        { status: 200, headers: { 'content-type': 'application/json' } });
    } });
    assert.equal(await ports.rpcByEnvironment[ENV_ID]!.request('eth_blockNumber', []), '0x1');
    assert.equal(received[0]?.url, 'http://host.docker.internal:18545');
    assert.equal(received[0]?.init.redirect, 'error');
    assert.ok(received[0]?.init.signal);
    await assert.rejects(ports.rpcByEnvironment[ENV_ID]!.request('eth_sendRawTransaction', ['0xdead']),
      (error: Error) => error.message === 'bef_observer_rpc_method_not_allowed');
    assert.equal(received.length, 1);
    await ports.close();

    const badId = await makePorts(root, { fetchImpl: async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { id: number };
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id + 1, result: '0x1' }), { status: 200 });
    } });
    await assert.rejects(badId.ports.rpcByEnvironment[ENV_ID]!.request('eth_chainId', []),
      (error: Error) => error.message === 'bef_observer_rpc_result_unavailable');
    await badId.ports.close();

    const oversized = await makePorts(root, { fetchImpl: async () => new Response('{}', {
      status: 200, headers: { 'content-length': String(4 * 1024 * 1024 + 1) },
    }) });
    await assert.rejects(oversized.ports.rpcByEnvironment[ENV_ID]!.request('eth_chainId', []),
      (error: Error) => error.message === 'bef_observer_rpc_response_oversized');
    await oversized.ports.close();
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('RPC config and upstream errors are bounded and never disclose credentials', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bef-observation-ports-'));
  try {
    await assert.rejects(createBefObservationPorts({ repositoryRoot: root, database: database(),
      environments: [{ envId: ENV_ID, observerRpcUrl: 'https://public.example/rpc' }] }),
    (error: Error) => error.message === 'bef_observer_rpc_url_invalid');
    const { ports } = await makePorts(root, { fetchImpl: async () => { throw new Error(DB_PASSWORD); } });
    await assert.rejects(ports.rpcByEnvironment[ENV_ID]!.request('eth_call', [{ to: '0x1' }, 'latest']),
      (error: Error) => error.message === 'bef_observer_rpc_transport_unavailable' && !error.message.includes(DB_PASSWORD));
    await ports.close();
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('observation writer is content-addressed, idempotent, bounded, and allows only a public S1 token address', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bef-observation-ports-'));
  try {
    const { ports } = await makePorts(root);
    const packet = validPacket();
    packet.ownerActions = [{ participantToolResponse: { selectedAction: { token: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913' } } }];
    const first = await ports.evidenceSink.write(packet);
    const replay = await ports.evidenceSink.write(packet);
    assert.deepEqual(replay, first);
    assert.match(first.path, new RegExp(`^${OBSERVATION_ROOT.replaceAll('/', '\\/')}\\/${packet.binding.runId}\\/S1\\/[0-9a-f]{64}\\.json$`));
    const bytes = await readFile(join(root, first.path));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), first.sha256);

    const addition = { ...packet, closure: { ...packet.closure, actionCutoffSequence: 2 } };
    const second = await ports.evidenceSink.write(addition);
    assert.notEqual(second.sha256, first.sha256);
    assert.notEqual(second.path, first.path);
    assert.equal(createHash('sha256').update(await readFile(join(root, first.path))).digest('hex'), first.sha256);

    const s2 = await ports.evidenceSink.write(validPacket(randomUUID(), 'S2'));
    const s4 = await ports.evidenceSink.write(validPacket(randomUUID(), 'S4'));
    assert.match(s2.path, /\/S2\/[0-9a-f]{64}\.json$/);
    assert.match(s4.path, /\/S4\/[0-9a-f]{64}\.json$/);

    const credential = validPacket();
    credential.ownerActions = [{ participantToolResponse: { selectedAction: { token: 'bearer_secret_value' } } }];
    await assert.rejects(ports.evidenceSink.write(credential),
      (error: Error) => error.message === 'bef_observer_packet_secret_or_oversized');
    const disguised = validPacket();
    disguised.authorization = 'Bearer abc';
    await assert.rejects(ports.evidenceSink.write(disguised),
      (error: Error) => error.message === 'bef_observer_packet_secret_or_oversized');
    const wrongShape = validPacket();
    wrongShape.ownerActions = [{ participantToolResponse: { selectedAction: { token: '0x1234' } } }];
    await assert.rejects(ports.evidenceSink.write(wrongShape),
      (error: Error) => error.message === 'bef_observer_packet_secret_or_oversized');
    const oversized = validPacket();
    oversized.publicDiagnostic = 'x'.repeat(8 * 1024 * 1024);
    await assert.rejects(ports.evidenceSink.write(oversized),
      (error: Error) => error.message === 'bef_observer_packet_secret_or_oversized');
    await ports.close();
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('M1 sink accepts only the strict sanitized packet and never retains signed x402 or raw transaction bytes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bef-observation-ports-m1-'));
  try {
    const { ports } = await makePorts(root);
    const packet = validM1CapturePacket();
    const first = await ports.evidenceSink.write(packet);
    const replay = await ports.evidenceSink.write(packet);
    assert.deepEqual(replay, first);
    assert.match(first.path, new RegExp(`^${OBSERVATION_ROOT.replaceAll('/', '\\/')}\\/${packet.binding.runId}\\/M1\\/[0-9a-f]{64}\\.json$`));
    const bytes = await readFile(join(root, first.path));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), first.sha256);
    assert.equal(bytes.includes(Buffer.from('payment-signature')), false);
    assert.equal(bytes.includes(Buffer.from('rawSignedTransaction')), false);

    const signedHeader = structuredClone(packet);
    signedHeader.bef.before.generation['x-payment'] = 'signed-authorization-bytes';
    signedHeader.bef.after.generation['x-payment'] = 'signed-authorization-bytes';
    await assert.rejects(ports.evidenceSink.write(signedHeader),
      (error: Error) => error.message === 'bef_observer_packet_invalid');

    const signedTx = structuredClone(packet);
    signedTx.rpc.paymentProofs = [{ operationId: '10000000-0000-4000-8000-000000000009',
      paymentId: '10000000-0000-4000-8000-000000000010', transactionHash: `0x${'a'.repeat(64)}`,
      transaction: { hash: `0x${'a'.repeat(64)}`, from: `0x${'1'.repeat(40)}`, to: null, value: '0', nonce: '0',
        blockNumber: '100', blockHash: `0x${'b'.repeat(64)}`, inputSha256: 'c'.repeat(64), input: `0x${'d'.repeat(128)}` },
      receipt: { transactionHash: `0x${'a'.repeat(64)}`, transactionIndex: '0', blockNumber: '100',
        blockHash: `0x${'b'.repeat(64)}`, from: `0x${'1'.repeat(40)}`, to: null, status: 'success', gasUsed: '1',
        effectiveGasPrice: '1', logsSha256: 'e'.repeat(64) } }];
    await assert.rejects(ports.evidenceSink.write(signedTx),
      (error: Error) => error.message === 'bef_observer_packet_invalid');
    await ports.close();
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('observation writer rejects invalid envelopes and symlinked evidence directories', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bef-observation-ports-'));
  const outside = await mkdtemp(join(tmpdir(), 'bef-observation-outside-'));
  try {
    const { ports } = await makePorts(root);
    const invalid = validPacket('not-a-run-id');
    await assert.rejects(ports.evidenceSink.write(invalid), (error: Error) => error.message === 'bef_observer_packet_invalid');
    await ports.close();

    const symlinkRoot = join(outside, 'symlink-root');
    await mkdir(symlinkRoot);
    await symlink(outside, join(symlinkRoot, 'artifacts'), 'dir');
    const linked = await makePorts(symlinkRoot);
    await assert.rejects(linked.ports.evidenceSink.write(validPacket()),
      (error: Error) => error.message === 'bef_observer_evidence_path_invalid');
    await linked.ports.close();
    assert.deepEqual(await readdir(outside), ['symlink-root']);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('observation writer accepts retained positive S1/S2/S4 packet shapes without touching their files', {
  skip: process.env.OID_BEF_OBSERVATION_PACKET_SMOKE !== '1',
}, async () => {
  const repositoryRoot = fileURLToPath(new URL('../../../', import.meta.url));
  const packetPaths = [
    'artifacts/runs/owner-identity-bef-task-coordinator/observation/200e82e5-0616-48dd-813c-5f7271aa42d5-s1-0-observer-packet.json',
    'artifacts/runs/owner-identity-bef-task-coordinator/observation/200e82e5-0616-48dd-813c-5f7271aa42d5-s2-1-observer-packet.json',
    'artifacts/runs/owner-identity-bef-task-coordinator/observation/49f9a88e-5d8d-4796-b2b2-aa630100cf18-s4-observer-packet.json',
  ];
  const originalHashes = new Map<string, string>();
  for (const path of packetPaths) originalHashes.set(path, createHash('sha256').update(await readFile(join(repositoryRoot, path))).digest('hex'));
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'bef-observation-retained-smoke-'));
  try {
    const { ports } = await makePorts(temporaryRoot);
    for (const path of packetPaths) {
      const bytes = await readFile(join(repositoryRoot, path));
      const packet = JSON.parse(bytes.toString('utf8')) as unknown;
      const first = await ports.evidenceSink.write(packet);
      const replay = await ports.evidenceSink.write(packet);
      assert.deepEqual(replay, first);
      assert.equal(createHash('sha256').update(await readFile(join(temporaryRoot, first.path))).digest('hex'), first.sha256);
      assert.equal(createHash('sha256').update(await readFile(join(repositoryRoot, path))).digest('hex'), originalHashes.get(path));
    }
    await ports.close();
  } finally { await rm(temporaryRoot, { recursive: true, force: true }); }
});

test('observation sink accepts strict chain, paid-data and S3 packets and rejects unknown variants',async()=>{
 const root=await mkdtemp(join(tmpdir(),'bef-new-observation-packets-'));
 try{const {ports}=await makePorts(root);
  for(const packet of [makeChainCaptureFixture('M3').packet,validPaidDataCapturePacket(),createS3CapturePacketFixture().packet]){
   let retained!: Awaited<ReturnType<typeof ports.evidenceSink.write>>; await assert.doesNotReject(async()=>{retained=await ports.evidenceSink.write(packet);},packet.schemaVersion);assert.match(retained.sha256,/^[0-9a-f]{64}$/);
   assert.deepEqual(await ports.evidenceSink.write(packet),retained);
   await assert.rejects(ports.evidenceSink.write({...packet,schemaVersion:'bts-unreviewed-capture/v1'}),/bef_observer_packet_invalid/);
   await assert.rejects(ports.evidenceSink.write({...packet,signature:'must-not-be-retained'}));
  }
 }finally{await rm(root,{recursive:true,force:true});}
});
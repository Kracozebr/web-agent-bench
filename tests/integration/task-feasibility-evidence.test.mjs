import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyRetainedTaskFeasibility } from '../../packages/owner-identity/src/task-feasibility-evidence.ts';

const root = fileURLToPath(new URL('../..', import.meta.url));
const witnessPath = 'artifacts/runs/bts-release-feasibility-witness/9a306c79-614b-4027-9129-33f68ffa3a75/witness.json';
const witnessHash = '39c7340d7e438c6da232dcb39e6130ee56d4de0ae3507d533851f2844e148ded';
const candidatePath = 'artifacts/runs/bts-task-case-candidates/182275ce-2c74-4bee-a0eb-96f6094f8196/candidate-cases.json';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const candidate = JSON.parse(await readFile(join(root, candidatePath), 'utf8')).assembly;
const base = { executionIdentity: candidate.executionIdentity, expectedIdentityHash: candidate.executionIdentityHash };
base.profilePolicy = { path: 'infrastructure/owner-identity/task-release-local-policy.json',
  sha256: '3f2e59f1b5992ed69ecea443953dd2f96c8e74fd4bc77ff0386f1039000cb0ed' };
const reference = { path: witnessPath, sha256: witnessHash, boundary: 'actual_tool_http_x402_local_evm_application_store' };

test('retained local feasibility independently binds raw RPC, schema ledger and candidate identity', async () => {
  assert.deepEqual(await verifyRetainedTaskFeasibility({ ...base, repositoryRoot: root, evidence: reference }),
    { status: 'verified', executionIdentityHash: base.expectedIdentityHash, actualBoundary: true });
});

test('a split-payment release cannot reuse feasibility for the legacy tool protocol', async () => {
  assert.deepEqual(await verifyRetainedTaskFeasibility({ ...base, repositoryRoot: root, evidence: reference,
    participantToolProtocol: 'separate_payment_delivery_v2' }),
  { status: 'mismatch', reason: 'feasibility_tool_protocol_mismatch' });
});

async function mutatedWitness(mutate, run) {
  const temporary = await mkdtemp(join(tmpdir(), 'bts-feasibility-'));
  try {
    const witness = JSON.parse(await readFile(join(root, witnessPath), 'utf8'));
    await mkdir(dirname(join(temporary, base.profilePolicy.path)), { recursive: true });
    await copyFile(join(root, base.profilePolicy.path), join(temporary, base.profilePolicy.path));
    for (const artifact of witness.artifacts) {
      const target = join(temporary, artifact.path);
      await mkdir(dirname(target), { recursive: true });
      await copyFile(join(root, artifact.path), target);
    }
    const db = JSON.parse(await readFile(join(temporary, dirname(witnessPath), 'observer-database.raw.json'), 'utf8'));
    for (const migration of db.migrations) {
      const relative = `infrastructure/benchmark-environment/migrations/${migration.filename}`;
      await mkdir(dirname(join(temporary, relative)), { recursive: true });
      await copyFile(join(root, relative), join(temporary, relative));
    }
    await mutate({ witness, temporary, async replaceRaw(name, edit) {
      const row = witness.artifacts.find((item) => item.path.endsWith(`/${name}`));
      const raw = JSON.parse(await readFile(join(temporary, row.path), 'utf8'));
      edit(raw);
      const bytes = Buffer.from(JSON.stringify(raw));
      await writeFile(join(temporary, row.path), bytes);
      row.sha256 = sha(bytes); row.byteLength = bytes.length;
    } });
    const bytes = Buffer.from(JSON.stringify(witness));
    await writeFile(join(temporary, witnessPath), bytes);
    await run(await verifyRetainedTaskFeasibility({ ...base, repositoryRoot: temporary,
      evidence: { ...reference, sha256: sha(bytes) } }));
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

test('a rehashed wrong-chain RPC response cannot inherit true summary booleans', async () => {
  await mutatedWitness(async ({ replaceRaw }) => replaceRaw('bef-env-b-rpc-chain-id.raw.json',
    (raw) => { raw.result = '0x1'; }), (result) => {
    assert.deepEqual(result, { status: 'mismatch', reason: 'feasibility_chain_mismatch' });
  });
});

test('rehashed observer write privilege invalidates feasibility even with passing summary', async () => {
  await mutatedWitness(async ({ replaceRaw }) => replaceRaw('observer-database.raw.json',
    (raw) => { raw.tablePrivileges[0].can_update = true; }), (result) => {
    assert.deepEqual(result, { status: 'mismatch', reason: 'feasibility_observer_table_privileges_invalid' });
  });
});

test('a rehashed fabricated applied migration cannot establish checked-in schema lineage', async () => {
  await mutatedWitness(async ({ replaceRaw }) => replaceRaw('observer-database.raw.json',
    (raw) => { raw.migrations[0].sha256 = '0'.repeat(64); }), (result) => {
    assert.deepEqual(result, { status: 'mismatch', reason: 'feasibility_migration_hash_mismatch' });
  });
});

test('hashed witness cannot redirect an artifact outside its capture directory', async () => {
  await mutatedWitness(async ({ witness }) => { witness.artifacts[0].path = '../manifest.json'; }, (result) => {
    assert.deepEqual(result, { status: 'mismatch', reason: 'feasibility_artifact_path_conflict' });
  });
});

test('rehashed proxy identity and active generation cannot inherit summary success', async () => {
  await mutatedWitness(async ({ replaceRaw }) => replaceRaw('bef-env-a-proxy-health.raw.json',
    (raw) => { raw.envId = 'bef-env-b'; }), (result) => {
    assert.deepEqual(result, { status: 'mismatch', reason: 'feasibility_proxy_identity_mismatch' });
  });
  await mutatedWitness(async ({ replaceRaw }) => replaceRaw('observer-database.raw.json',
    (raw) => { raw.generations[0].status = 'active'; }), (result) => {
    assert.deepEqual(result, { status: 'mismatch', reason: 'feasibility_generation_fence_unverified' });
  });
});

test('an unrelated artifact cannot replace a required response while retaining count 29', async () => {
  await mutatedWitness(async ({ witness, temporary }) => {
    const row = witness.artifacts.find((item) => item.path.endsWith('/bef-env-a-proxy-health.raw.json'));
    const replacement = `${dirname(row.path)}/unrelated.raw.json`;
    await copyFile(join(temporary, row.path), join(temporary, replacement));
    row.path = replacement;
  }, (result) => assert.deepEqual(result,
    { status: 'mismatch', reason: 'feasibility_artifact_missing:bef-env-a-proxy-health.raw.json' }));
});

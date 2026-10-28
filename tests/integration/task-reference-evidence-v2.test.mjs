// Opt-in retained-capture integration checks. These never contact BEF or modify originals.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile, rm, realpath } from 'node:fs/promises';
import { dirname, resolve, relative, isAbsolute } from 'node:path';
import { loadV2ReferenceContext } from '../../packages/owner-identity/src/task-reference-evidence-v2.ts';
import { canonicalTaskJson, sha256CanonicalTaskJson } from '../../packages/owner-identity/src/task-release.ts';

const index = 'artifacts/runs/bts-difficulty-v2-case-candidates/8f478f5f-edda-47f8-85b2-35fa2f455a4c/candidate-cases.json';
const indexSha = 'b50836aa76611fe826e4c31e3fcc20f3cedb6e2e05485c0c59d11c79c0462156';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const bytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const json = async (path) => JSON.parse(await readFile(path, 'utf8'));
const clone = (value) => structuredClone(value);
const policyPath = 'infrastructure/owner-identity/task-release-local-policy.json';

test('retained reader rejects rehashed semantic corruption and reconstructs raw amounts', async (t) => {
  assert.equal(process.platform, 'linux', 'Run in the approved owner Docker runtime');
  const root = await realpath(process.cwd());
  const source = await readFile(index);
  assert.equal(sha(source), indexSha);
  const candidate = JSON.parse(source);
  const originalCase = candidate.cases.find((row) => row.taskId === 'M1' && row.mode === 'ranked');
  const reference = await json(originalCase.referencePath.evidence.path);
  const baseline = await json(originalCase.initialStateEvidence.path);
  const probe = await json(reference.probe.path);
  const originalRoot = dirname(reference.probe.path);
  const originalBytes = new Map(await Promise.all(probe.artifacts.map(async (row) =>
    [row.path, await readFile(`${originalRoot}/${row.path}`)])));
  const originals = probe.artifacts.map((row) => ({ ...row,
    value: JSON.parse(originalBytes.get(row.path)) }));
  const policyHash = sha(await readFile(policyPath));
  const input = (taskCase) => ({ repositoryRoot: root, identity: candidate.executionIdentity,
    executionIdentityHash: candidate.executionIdentityHash, profilePolicy: { path: policyPath, sha256: policyHash },
    taskCase, evidence: taskCase.referencePath.evidence });
  const originalContext = await loadV2ReferenceContext(input(originalCase));
  const initialCheckpoint = originalContext.rpc('eth_getBlockByNumber').map((row) => row.result)
    .find((block) => {
      try {
        const state = originalContext.stateAt(originalCase.initialState, { number: block.number, hash: block.hash });
        return canonicalTaskJson(state.balances) === canonicalTaskJson(originalCase.initialState.balances)
          && canonicalTaskJson(state.allowances) === canonicalTaskJson(originalCase.initialState.allowances);
      } catch { return false; }
    });
  assert.ok(initialCheckpoint, 'Original initial numeric state has raw block-tagged reads');
  const fixtureParent = 'artifacts/runs/bts-v2-reference-reader-tests';
  await mkdir(fixtureParent, { recursive: true });

  async function withFixture(mutate, verify) {
    const prefix = `${fixtureParent}/${randomUUID()}`;
    await mkdir(`${prefix}/capture`, { recursive: true });
    try {
      const documents = clone(originals), nextProbe = clone(probe), nextCase = clone(originalCase);
      const changed = mutate(documents);
      assert.ok(changed > 0, 'Mutation must change at least one raw observation');
      const replacementHashes = new Map();
      for (const doc of documents) {
        const original = originals.find((row) => row.path === doc.path);
        const content = canonicalTaskJson(doc.value) === canonicalTaskJson(original.value)
          ? originalBytes.get(doc.path) : bytes(doc.value);
        const path = `${prefix}/capture/${doc.path}`;
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, content, { flag: 'wx' });
        replacementHashes.set(doc.path, sha(content));
      }
      nextProbe.artifacts.forEach((row) => { row.sha256 = replacementHashes.get(row.path); });
      nextProbe.captureReferences.participantActions.forEach((row) => {
        row.rawResponseSha256 = replacementHashes.get(row.rawResponsePath);
      });
      const probeBytes = bytes(nextProbe), probePath = `${prefix}/capture/probe.json`;
      await writeFile(probePath, probeBytes, { flag: 'wx' });
      const refs = reference.rawReferences.map((row) => {
        const local = row.path.slice(originalRoot.length + 1);
        return { ...row, path: `${prefix}/capture/${local}`, sha256: replacementHashes.get(local) };
      });
      const writeEnvelope = async (original, name) => {
        const next = clone(original);
        next.probe = { ...next.probe, path: probePath, sha256: sha(probeBytes) };
        next.rawReferences = refs;
        if (next.participantActions) next.participantActions = clone(nextProbe.captureReferences.participantActions);
        const content = bytes(next), path = `${prefix}/${name}.json`;
        await writeFile(path, content, { flag: 'wx' });
        return { path, sha256: sha(content) };
      };
      Object.assign(nextCase.referencePath.evidence, await writeEnvelope(reference, 'reference'));
      Object.assign(nextCase.initialStateEvidence, await writeEnvelope(baseline, 'initial'));
      const { caseHash: _oldHash, ...fields } = nextCase;
      nextCase.caseHash = sha256CanonicalTaskJson(fields);
      await verify(input(nextCase));
    } finally {
      // AICODE-NOTE: delete only the newly created UUID fixture, after containment checks.
      const actual = await realpath(prefix), parent = await realpath(fixtureParent);
      const child = relative(parent, actual);
      assert.ok(child && !isAbsolute(child) && !child.includes('/') && !child.includes('\\') && child !== '..');
      await rm(actual, { recursive: true, force: false });
    }
  }

  await t.test('rehashed observer privilege escalation is rejected', async () => {
    await withFixture((docs) => {
      const row = docs.find((doc) => doc.value.queryName === 'observer-role-effective-privileges');
      row.value.role.is_superuser = true;
      return 1;
    }, async (next) => assert.rejects(loadV2ReferenceContext(next),
      (error) => error.code === 'v2_reference_observer_privileges_mismatch'));
  });
  await t.test('rehashed cross-generation HTTP witness is rejected', async () => {
    await withFixture((docs) => {
      let changed = 0;
      for (const doc of docs) {
        if (doc.value.boundary !== 'actual-tool-http' || !doc.value.request?.headers) continue;
        for (const key of Object.keys(doc.value.request.headers)) {
          if (key.toLowerCase() === 'x-bef-generation') {
            doc.value.request.headers[key] = randomUUID(); changed++;
          }
        }
      }
      return changed;
    }, async (next) => assert.rejects(loadV2ReferenceContext(next),
      (error) => error.code === 'v2_reference_action_http_witness_missing'));
  });
  await t.test('rehashed independent fence for another generation is rejected', async () => {
    await withFixture((docs) => {
      let changed = 0;
      for (const doc of docs) {
        if (doc.value.queryName === 'generation-by-id' && doc.value.rows?.[0]?.status === 'fenced') {
          doc.value.rows[0].generation_id = randomUUID(); changed++;
        }
      }
      return changed;
    }, async (next) => assert.rejects(loadV2ReferenceContext(next),
      (error) => error.code === 'v2_reference_independent_fence_missing'));
  });
  await t.test('raw ERC20 amount overrides the unchanged claimed state', async () => {
    const payer = originalContext.generation.payerAddress.toLowerCase().slice(2).padStart(64, '0');
    const usdc = candidate.executionIdentity.assets.find((row) => row.assetId === 'USDC').address.toLowerCase();
    await withFixture((docs) => {
      let changed = 0;
      for (const doc of docs) {
        const value = doc.value;
        if (value.schemaVersion === 'bef-rpc-observation/v1' && value.method === 'eth_call'
          && value.params?.[0]?.to?.toLowerCase() === usdc
          && value.params?.[0]?.data?.toLowerCase() === `0x70a08231${payer}`
          && BigInt(value.params[1]) === BigInt(initialCheckpoint.number)) {
          value.result = `0x${(BigInt(value.result) + 1n).toString(16).padStart(64, '0')}`; changed++;
        }
      }
      return changed;
    }, async (next) => {
      const context = await loadV2ReferenceContext(next);
      const observed = context.stateAt(next.taskCase.initialState,
        { number: initialCheckpoint.number, hash: initialCheckpoint.hash });
      assert.notEqual(sha256CanonicalTaskJson(observed), next.taskCase.initialState.stateSha256);
      const before = next.taskCase.initialState.balances.find((row) => row.account === 'participant' && row.assetId === 'USDC');
      const after = observed.balances.find((row) => row.account === 'participant' && row.assetId === 'USDC');
      assert.equal(BigInt(after.amountUnits), BigInt(before.amountUnits) + 1n);
    });
  });
});

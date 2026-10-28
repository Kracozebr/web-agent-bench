import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFile, mkdtemp, readFile, rm, mkdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { readS1TransferPrimitiveCapture } from '../../packages/owner-identity/src/task-observer.ts';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const captureDirectory = process.env.BTS_S1_CAPTURE_DIR ?? resolve(
  repoRoot, 'artifacts/runs/bts-transfer-primitive/ea5c8e80-8653-4e52-969c-3a4925b7dc59',
);
const probeSha256 = 'b42729a6f98018de685947d74fa40e775cdfd67f039af350eac01255b49ee7f9';
const identity = {
  envId: 'bef-env-a',
  generationId: '46611eeb-3696-440e-b55e-e80a878c5974',
  operationId: 'd7dd747f-5ac6-4c91-8db5-dc5d39b6c6d2',
  participantId: 'probe-bef-sc-007-eef45a61-e456-4b68-9b83-00eafc0510ff',
};
const captureAvailable = existsSync(join(captureDirectory, 'probe.json'));

async function copyCapture(sourceDirectory, destinationDirectory) {
  const probe = JSON.parse(await readFile(join(sourceDirectory, 'probe.json'), 'utf8'));
  await mkdir(destinationDirectory, { recursive: true });
  await copyFile(join(sourceDirectory, 'probe.json'), join(destinationDirectory, 'probe.json'));
  for (const artifact of probe.artifacts) {
    const from = join(sourceDirectory, ...artifact.path.split('/'));
    const to = join(destinationDirectory, ...artifact.path.split('/'));
    await mkdir(dirname(to), { recursive: true });
    await copyFile(from, to);
  }
}

test('retained real BEF S1 primitive reconciles hashed PostgreSQL, receipt, transfer and balance evidence', {
  skip: !captureAvailable ? `Retained capture unavailable at ${captureDirectory}` : false,
}, async () => {
  const result = await readS1TransferPrimitiveCapture({ captureDirectory, expectedProbeSha256: probeSha256, trustedIdentity: identity });
  assert.equal(result.status, 'verified_primitive_only');
  assert.equal(result.classification, 'selected_executor_primitive_capture_not_bts_acceptance');
  assert.deepEqual(result.transfer, {
    fromAddress: '0x4c49d14cfdd9ab941ecdce4688a8b118d1491b64',
    recipientAddress: '0x2f46a8a284b7ddd32a9d8c9dd33235f698b5a743',
    assetAddress: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    amountUnits: '100000',
    receiptStatus: 'success',
  });
  assert.deepEqual(result.finalState, {
    blockNumber: '52982198',
    blockHash: '0xa031d74d63eec00851925c3982e741d9147b0973c26c775c4c8eca037e06430d',
    participantNativeWei: '9999999665883253995',
    participantUsdcUnits: '99900000',
    recipientUsdcUnits: '100000',
  });
  assert.deepEqual(result.receiptCost, {
    gasUsed: '62159',
    effectiveGasPriceWei: '5375195',
    gasCostWei: '334116746005',
    modeledGasFeeUsdcUnits: '799',
    transactionCostRow: 'unavailable_in_capture',
  });
  assert.deepEqual(result.relatedRows, { paymentRows: 0, deliveryRows: 0, transactionCostRows: 'not_captured' });
  assert.equal(result.taskActionBinding, 'unavailable');
  assert.deepEqual(result.unavailableReasons, ['task_action_binding_unavailable', 'authoritative_run_cutoff_unavailable']);
  assert.equal(result.evaluatorObservations, null);
  assert.ok(result.evidence.some((item) => item.boundary === 'readonly-database'));
  assert.ok(result.evidence.filter((item) => item.boundary === 'local-chain-readonly-proxy').length >= 8);
});

test('tampered retained RPC evidence fails its raw artifact hash before normalization', {
  skip: !captureAvailable ? `Retained capture unavailable at ${captureDirectory}` : false,
}, async () => {
  const copyDirectory = await mkdtemp(join(tmpdir(), 'bts-task-observer-'));
  try {
    await copyCapture(captureDirectory, copyDirectory);
    const receiptPath = join(copyDirectory, 'rpc', '0011-task-transfer-receipt.json');
    const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
    receipt.result.status = '0x0';
    await writeFile(receiptPath, JSON.stringify(receipt));
    await assert.rejects(
      () => readS1TransferPrimitiveCapture({ captureDirectory: copyDirectory, expectedProbeSha256: probeSha256, trustedIdentity: identity }),
      /task_observer_artifact_hash_mismatch:rpc\/0011-task-transfer-receipt\.json/,
    );
  } finally {
    await rm(copyDirectory, { recursive: true, force: true });
  }
});

test('capture identity must match the trusted environment and generation scope', {
  skip: !captureAvailable ? `Retained capture unavailable at ${captureDirectory}` : false,
}, async () => {
  await assert.rejects(
    () => readS1TransferPrimitiveCapture({
      captureDirectory,
      expectedProbeSha256: probeSha256,
      trustedIdentity: { ...identity, generationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
    }),
    /task_observer_trusted_identity_mismatch/,
  );
});

test('artifact paths cannot escape the retained capture root', {
  skip: !captureAvailable ? `Retained capture unavailable at ${captureDirectory}` : false,
}, async () => {
  const copyDirectory = await mkdtemp(join(tmpdir(), 'bts-task-observer-path-'));
  try {
    await copyCapture(captureDirectory, copyDirectory);
    const probePath = join(copyDirectory, 'probe.json');
    const probe = JSON.parse(await readFile(probePath, 'utf8'));
    probe.artifacts[0].path = '../outside.json';
    const changedProbe = Buffer.from(JSON.stringify(probe));
    await writeFile(probePath, changedProbe);
    const changedProbeSha256 = createHash('sha256').update(changedProbe).digest('hex');
    await assert.rejects(
      () => readS1TransferPrimitiveCapture({ captureDirectory: copyDirectory, expectedProbeSha256: changedProbeSha256, trustedIdentity: identity }),
      /task_observer_artifact_path_invalid/,
    );
  } finally {
    await rm(copyDirectory, { recursive: true, force: true });
  }
});

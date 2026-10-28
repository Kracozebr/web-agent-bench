import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { createBoundedEvidenceStoreView } from './ranked-bdd-cases.mjs';

const RUN_ID = '11111111-1111-4111-8111-111111111111';
const OBSERVATION = 'artifacts/runs/owner-identity-bef-task-coordinator/observation';
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function writeSource(root, path, bytes) {
  const absolute = resolve(root, ...path.split('/'));
  await mkdir(dirname(absolute), { recursive: true });
  await writeFile(absolute, bytes, { flag: 'wx', mode: 0o600 });
}

test('bounded evidence view omits one pinned U1 packet, copies reachable bytes, and restores exactly', async (t) => {
  const sourceRoot = await mkdtemp(resolve(tmpdir(), 'bts-sc009-source-'));
  t.after(() => rm(sourceRoot, { recursive: true, force: true }));

  const childBytes = Buffer.from('{"boundary":"fixture-only"}\n');
  const childPath = `${OBSERVATION}/${RUN_ID}/U1/${sha256(childBytes)}.json`;
  const childRef = { path: childPath, sha256: sha256(childBytes), boundary: BOUNDARY };
  const actionBytes = Buffer.from(`${JSON.stringify({ runId: RUN_ID, taskIndex: 11, actionId: 'fixture-action' })}\n`);
  const actionPath = 'artifacts/runs/owner-identity-bef-task-coordinator/action/33333333-3333-4333-8333-333333333333-44444444-4444-4444-8444-444444444444.json';
  const actionRef = { path: actionPath, sha256: sha256(actionBytes), boundary: BOUNDARY };
  const rootBytes = Buffer.from(`${JSON.stringify({ schemaVersion: 'fixture-capture', preparation: { evidence: childRef }, actionEvidence: actionRef })}\n`);
  const rootPath = `${OBSERVATION}/${RUN_ID}/U1/${sha256(rootBytes)}.json`;
  const rootRef = { path: rootPath, sha256: sha256(rootBytes), boundary: BOUNDARY };
  await writeSource(sourceRoot, childPath, childBytes);
  await writeSource(sourceRoot, actionPath, actionBytes);
  await writeSource(sourceRoot, rootPath, rootBytes);

  const view = await createBoundedEvidenceStoreView({ evidenceRoot: sourceRoot, runId: RUN_ID,
    evidenceReferencesByTask: [{ taskIndex: 11, references: [rootRef] }], omittedReference: rootRef });
  try {
    assert.equal(view.summary.fileCount, 3);
    assert.equal(view.summary.bytes, childBytes.length + actionBytes.length + rootBytes.length);
    await assert.rejects(readFile(resolve(view.viewRoot, ...rootPath.split('/'))), { code: 'ENOENT' });
    assert.deepEqual(await readFile(resolve(view.viewRoot, ...childPath.split('/'))), childBytes);
    assert.deepEqual(await readFile(resolve(view.viewRoot, ...actionPath.split('/'))), actionBytes);
    const restored = await view.restoreOmitted();
    assert.equal(restored.sha256, rootRef.sha256);
    assert.deepEqual(await readFile(resolve(view.viewRoot, ...rootPath.split('/'))), rootBytes);
    assert.equal(await view.verifyOriginalOmitted(), true);
  } finally {
    const viewRoot = view.viewRoot;
    await view.dispose();
    await assert.rejects(stat(viewRoot), { code: 'ENOENT' });
  }
});

test('bounded evidence view rejects a cross-run reference and altered retained bytes', async (t) => {
  const sourceRoot = await mkdtemp(resolve(tmpdir(), 'bts-sc009-source-'));
  t.after(() => rm(sourceRoot, { recursive: true, force: true }));

  const bytes = Buffer.from('{"runId":"11111111-1111-4111-8111-111111111111","taskIndex":11}\n');
  const validPath = `${OBSERVATION}/${RUN_ID}/U1/${sha256(bytes)}.json`;
  await writeSource(sourceRoot, validPath, bytes);
  const wrongRunPath = `${OBSERVATION}/22222222-2222-4222-8222-222222222222/U1/${sha256(bytes)}.json`;
  const wrongRunRef = { path: wrongRunPath, sha256: sha256(bytes), boundary: BOUNDARY };
  await assert.rejects(createBoundedEvidenceStoreView({ evidenceRoot: sourceRoot, runId: RUN_ID,
    evidenceReferencesByTask: [{ taskIndex: 11, references: [wrongRunRef] }], omittedReference: wrongRunRef }),
  { code: 'ranked_bdd_evidence_view_cross_run_reference' });

  const wrongHashRef = { path: validPath, sha256: '0'.repeat(64), boundary: BOUNDARY };
  await assert.rejects(createBoundedEvidenceStoreView({ evidenceRoot: sourceRoot, runId: RUN_ID,
    evidenceReferencesByTask: [{ taskIndex: 11, references: [wrongHashRef] }], omittedReference: wrongHashRef }),
  { code: 'ranked_bdd_evidence_view_source_hash_mismatch' });
});

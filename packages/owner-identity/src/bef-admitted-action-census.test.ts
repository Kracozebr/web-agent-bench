import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { TaskActionCommandSchema } from './task-action-service.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import { assertAdmittedActionCoverage, readAdmittedActionEvidenceFile, validateAdmittedActionCensus,
  type AdmittedActionRow, type AdmittedActionProof } from './bef-admitted-action-census.js';

const uuid = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const hash = (c: string) => c.repeat(64);
const binding = { ownerId: uuid(1), agentId: uuid(2), runId: uuid(3), environmentId: 'test-isolated-env',
  releaseIdentity: 'test-release', manifestHash: hash('a'), caseId: 'test-s1-case', caseHash: hash('b'),
  rubricHash: hash('c'), taskId: 'S1' as const };
const execution = { preparationId: uuid(4), leaseId: uuid(5), generationId: uuid(6),
  environmentId: binding.environmentId, environmentManifestHash: hash('d'), applicationSourceHash: hash('e'),
  executionIdentityHash: hash('f'), initialStateSha256: hash('0') };
const commands = [
  { kind: 'inspect_catalog' },
  { kind: 'inspect_offer', resourceId: 'scoped-nonobjective-resource', offerId: 'other-valid-offer' },
  { kind: 'pay', resourceId: 'scoped-nonobjective-resource', offerId: 'other-valid-offer', offerReadActionId: uuid(102) },
  { kind: 'retrieve', payActionId: uuid(103) },
  { kind: 'approve', tokenAssetId: 'USDC', amountUnits: '99999', gasLimit: '100000' },
  { kind: 'transfer', amountUnits: '7', recipient: '0x0000000000000000000000000000000000000009', gasLimit: '100000' },
  { kind: 'wrap', amountWei: '1', gasLimit: '100000' },
  { kind: 'unwrap', amountWei: '1', gasLimit: '100000' },
  { kind: 'swap', inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: '3', amountOutMinimumUnits: '1',
    recipient: '0x0000000000000000000000000000000000000009', gasLimit: '100000' },
];

function fixture(rawCommands = commands) {
  const bytes = new Map<string, Buffer>();
  const rows: AdmittedActionRow[] = rawCommands.map((rawCommand, index) => {
    const command = TaskActionCommandSchema.parse(rawCommand), sequence = index + 1;
    const id = uuid(100 + sequence), operationId = `test_operation_${sequence}`;
    const payloadHash = sha256CanonicalTaskJson({ runId: binding.runId, taskIndex: 0, command });
    const payment = { scheme: 'exact', network: 'eip155:8453', asset: 'USDC', amount: '1',
      payTo: '0x0000000000000000000000000000000000000009', transferMethod: 'transfer' };
    const resource = { resourceId: 'scoped-nonobjective-resource', resourceSha256: hash('3'), contentType: 'application/json',
      offers: [{ id: 'other-valid-offer', payment }] };
    const response = command.kind === 'inspect_catalog' ? { operationId: uuid(500 + sequence), freeInspection: true,
      deliveryState: 'not_delivered', catalog: [resource] } : command.kind === 'inspect_offer' ?
      { ...resource, payment, operationId: uuid(500 + sequence), freeInspection: true, deliveryState: 'not_delivered' } :
      { operationId: uuid(500 + sequence) };
    const document = { schema: 'bef-task-action-observation-v1', actionId: id, runId: binding.runId,
      taskIndex: 0, actionSequence: String(sequence), ownerOperationId: operationId,
      actionKind: command.kind, commandSha256: payloadHash, environmentId: binding.environmentId,
      generationId: execution.generationId, manifestSha256: execution.environmentManifestHash,
      applicationSourceSha256: execution.applicationSourceHash, idempotencyKey: 'task-action-' + id,
      status: 'observed', httpStatus: 200, rawResponseSha256: hash('4'), participantToolResponse: response };
    const content = Buffer.from(JSON.stringify(document)), evidenceHash = createHash('sha256').update(content).digest('hex');
    const path = `artifacts/runs/owner-identity-bef-task-coordinator/action/${id}.json`;
    bytes.set(path, content);
    return { id, run_id: binding.runId, task_index: 0, owner_id: binding.ownerId, agent_id: binding.agentId,
      task_id: binding.taskId, environment_id: binding.environmentId, action_sequence: sequence,
      operation_id: operationId, payload_hash: payloadHash, action_kind: command.kind, command_json: command,
      receipt_revision: 1, receipt_status: 'observed', evidence_hash: evidenceHash, evidence_path: path,
      transaction_hash: null, history_revision: 1, history_status: 'observed', history_evidence_hash: evidenceHash,
      history_evidence_path: path, history_transaction_hash: null,
      tool_response_json: response, tool_response_hash: sha256CanonicalTaskJson(response),
      history_tool_response_json: response, history_tool_response_hash: sha256CanonicalTaskJson(response) };
  });
  const input = { binding: structuredClone(binding), execution: structuredClone(execution), taskIndex: 0,
    closure: { closureId: uuid(7), operationId: 'test_finish_operation', payloadHash: hash('1'),
      reason: 'agent_finish' as const, actionCutoffSequence: rows.length, reconciledActionSequence: rows.length },
    rows, readActionEvidence: async (ref: { path: string }): Promise<Uint8Array> => bytes.get(ref.path)! };
  return { input, bytes };
}
function proofs(census: Awaited<ReturnType<typeof validateAdmittedActionCensus>>): AdmittedActionProof[] {
  return census.entries.map(({ actionId, actionSequence, ownerOperationId, actionKind, commandSha256,
    receiptStatus, transactionHash, actionEvidence }) => ({ actionId, actionSequence, ownerOperationId,
    actionKind, commandSha256, receiptStatus, transactionHash, actionEvidence }));
}
function replaceDocument(f: ReturnType<typeof fixture>, index: number, modify: (document: Record<string, unknown>) => void) {
  const row = f.input.rows[index]!, document = JSON.parse(f.bytes.get(row.evidence_path!)!.toString()) as Record<string, unknown>;
  modify(document);
  const content = Buffer.from(JSON.stringify(document));
  row.evidence_hash = row.history_evidence_hash = createHash('sha256').update(content).digest('hex');
  f.bytes.set(row.evidence_path!, content);
}

test('S1 census accounts for all nine admitted families including off-goal read/pay without asserting effects or grade', async () => {
  const { input } = fixture();
  const result = await validateAdmittedActionCensus(input);
  assert.equal(result.classification, 'identity_and_evidence_census_not_effect_proof');
  assert.deepEqual(result.entries.map(e => e.family), ['read', 'read', 'payment', 'payment', 'chain', 'chain', 'chain', 'chain', 'chain']);
  assert.deepEqual(result.entries.map(e => e.command), commands);
  assert.equal('coverage' in result, false);
  assert.equal('credit' in result, false);
  assertAdmittedActionCoverage(result, proofs(result));
});

for (const [name, change] of [
  ['missing row', (f: ReturnType<typeof fixture>) => { f.input.rows.pop(); }],
  ['wrong sequence', (f: ReturnType<typeof fixture>) => { f.input.rows[1]!.action_sequence = 3; }],
  ['unreconciled cutoff', (f: ReturnType<typeof fixture>) => { f.input.closure.reconciledActionSequence--; }],
  ['foreign owner', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.owner_id = uuid(999); }],
  ['foreign environment', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.environment_id = 'foreign'; }],
  ['history receipt revision mismatch', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.history_revision = 2; }],
  ['history evidence mismatch', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.history_evidence_hash = hash('9'); }],
  ['history response mismatch', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.history_tool_response_json = { forged: true }; }],
  ['receipt response hash mismatch', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.tool_response_json = f.input.rows[2]!.history_tool_response_json = { forged: true };
    f.input.rows[2]!.tool_response_hash = f.input.rows[2]!.history_tool_response_hash = hash('9'); }],
  ['rehashed document response unlike durable receipt', (f: ReturnType<typeof fixture>) => { replaceDocument(f, 2, d => { d.participantToolResponse = { forged: true }; }); }],
  ['unresolved action', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.receipt_status = f.input.rows[2]!.history_status = 'unknown'; }],
  ['duplicate owner operation', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.operation_id = f.input.rows[1]!.operation_id; }],
  ['command changed after admission', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.command_json = { kind: 'inspect_catalog' }; }],
  ['changed evidence bytes', (f: ReturnType<typeof fixture>) => { f.bytes.set(f.input.rows[2]!.evidence_path!, Buffer.from('{}')); }],
  ['foreign generation with matching file hash', (f: ReturnType<typeof fixture>) => { replaceDocument(f, 2, d => { d.generationId = uuid(999); }); }],
  ['wrong source hash with matching file hash', (f: ReturnType<typeof fixture>) => { replaceDocument(f, 2, d => { d.applicationSourceSha256 = hash('9'); }); }],
  ['foreign action with matching file hash', (f: ReturnType<typeof fixture>) => { replaceDocument(f, 2, d => { d.actionId = uuid(999); }); }],
  ['extra top-level evidence authority', (f: ReturnType<typeof fixture>) => { replaceDocument(f, 2, d => { d.adminOverride = true; }); }],
  ['out-of-scope evidence path', (f: ReturnType<typeof fixture>) => { f.input.rows[2]!.evidence_path = '../outside.json'; }],
] as const) {
  test(`census refuses ${name} instead of omitting the admitted action`, async () => {
    const f = fixture(); change(f);
    await assert.rejects(validateAdmittedActionCensus(f.input), /owner_cutoff_mismatch|action_evidence_unavailable/);
  });
}

test('census retains one immutable owner snapshot across asynchronous evidence reads', async () => {
  const f = fixture();
  const read = f.input.readActionEvidence;
  f.input.readActionEvidence = async ref => {
    f.input.binding.ownerId = uuid(999);
    f.input.execution.generationId = uuid(999);
    f.input.rows[1]!.owner_id = uuid(999);
    return read(ref);
  };
  const result = await validateAdmittedActionCensus(f.input);
  assert.equal(result.binding.ownerId, binding.ownerId);
  assert.equal(result.execution.generationId, execution.generationId);
});

test('a paid-only packet cannot claim complete census while skipping an admitted chain action', async () => {
  const { input } = fixture();
  const census = await validateAdmittedActionCensus(input);
  const partial = proofs(census).filter(p => ['inspect_catalog', 'inspect_offer', 'pay', 'retrieve'].includes(p.actionKind));
  assert.throws(() => assertAdmittedActionCoverage(census, partial), /action_coverage_incomplete/);
  const duplicate = proofs(census); duplicate[2] = duplicate[1]!;
  assert.throws(() => assertAdmittedActionCoverage(census, duplicate), /action_coverage_incomplete/);
  const forged = proofs(census); forged[2] = { ...forged[2]!, commandSha256: hash('9') };
  assert.throws(() => assertAdmittedActionCoverage(census, forged), /action_coverage_incomplete/);
});

test('aggregate action evidence accepts the exact existing budget and rejects one byte over before retaining a document', async () => {
  const f = fixture();
  const total = [...f.bytes.values()].reduce((sum, bytes) => sum + bytes.length, 0);
  assert.equal((await validateAdmittedActionCensus({ ...f.input, maximumTotalEvidenceBytes: total })).entries.length, 9);
  await assert.rejects(validateAdmittedActionCensus({ ...f.input, maximumTotalEvidenceBytes: total - 1 }), /action_evidence_unavailable/);
  await assert.rejects(validateAdmittedActionCensus({ ...f.input, maximumTotalEvidenceBytes: 32 * 1024 * 1024 + 1 }), /action_evidence_unavailable/);
});

test('safe file reader verifies actual bytes and rejects changed or unbounded files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bts-census-'));
  try {
    const f = fixture([commands[0]!]);
    const row = f.input.rows[0]!;
    const path = join(root, row.evidence_path!);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, f.bytes.get(row.evidence_path!)!);
    f.input.readActionEvidence = ref => readAdmittedActionEvidenceFile(root, { ...ref,
      sha256: row.evidence_hash!, boundary: 'actual_tool_http_x402_local_evm_application_store' });
    assert.equal((await validateAdmittedActionCensus(f.input)).entries.length, 1);
    await writeFile(path, '{}');
    await assert.rejects(validateAdmittedActionCensus(f.input), /action_evidence_unavailable/);
    await assert.rejects(readAdmittedActionEvidenceFile(root, { path: row.evidence_path!, sha256: row.evidence_hash!,
      boundary: 'actual_tool_http_x402_local_evm_application_store' }, 1), /action_evidence_unavailable/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

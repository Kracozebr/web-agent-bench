import assert from 'node:assert/strict';
import test from 'node:test';
import { TaskActionCommandSchema } from './task-action-service.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import { validateAdmittedActionsCapturePacket, parseAdmittedActionsCapturePacket,
  validateAdmittedClosureAnswer, composeAdmittedActionObservationCandidates,
  admittedDeliveryAbsenceSources, assertAdmittedGoalEffectRepresentation,
  type AdmittedActionsCapturePacket } from './task-admitted-actions-capture-packet.js';
import { makeAdmittedActionsCaptureFixture } from './task-admitted-actions-capture-packet.fixture.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';
import type { TaskCase } from './task-release.js';

const uuid = (n: number) => '20000000-0000-4000-8000-' + String(n).padStart(12, '0');
const h = (v: string) => v.repeat(64);
const tasks = ['S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1'] as const;
function fixture(taskId: typeof tasks[number] = 'S1'): AdmittedActionsCapturePacket {
  const rawCommands = [
    { kind: 'inspect_catalog' }, { kind: 'inspect_offer', resourceId: 'valid-other-resource', offerId: 'other-offer' },
    { kind: 'pay', resourceId: 'valid-other-resource', offerId: 'other-offer', offerReadActionId: uuid(102) },
    { kind: 'retrieve', payActionId: uuid(103) },
    { kind: 'approve', tokenAssetId: 'USDC', amountUnits: '8', gasLimit: '100000' },
    { kind: 'transfer', amountUnits: '9', recipient: '0x0000000000000000000000000000000000000009', gasLimit: '100000' },
    { kind: 'wrap', amountWei: '1', gasLimit: '100000' }, { kind: 'unwrap', amountWei: '1', gasLimit: '100000' },
    { kind: 'swap', inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: '1', amountOutMinimumUnits: '0',
      recipient: '0x0000000000000000000000000000000000000009', gasLimit: '100000' },
  ];
  const binding = { ownerId: uuid(1), agentId: uuid(2), runId: uuid(3), environmentId: 'unit-env', releaseIdentity: 'unit-release',
    manifestHash: h('a'), caseId: 'unit-case', caseHash: h('b'), rubricHash: h('c'), taskId };
  const closure = { closureId: uuid(4), operationId: 'unit_finish_operation', payloadHash: sha256CanonicalTaskJson({
    action: 'task_finish', runId: binding.runId, taskIndex: 0, answer: null }), reason: 'agent_finish' as const,
    actionCutoffSequence: 9, reconciledActionSequence: 9 };
  const evidence = (kind: string, id: string) => ({ path: `artifacts/runs/owner-identity-bef-task-coordinator/${kind}/${id}.json`,
    sha256: h('d'), boundary: 'actual_tool_http_x402_local_evm_application_store' as const });
  const boundary = { actionCutoffSequence: 9, observationCutoffSequence: 10,
    baselineBlockNumber: '1', baselineBlockHash: '0x' + h('e'), finalBlockNumber: '2', finalBlockHash: '0x' + h('f') };
  return { schemaVersion: 'bts-admitted-actions-observation-capture/v1', classification: 'run_bound_observations_candidate_not_grade',
    binding, taskIndex: 0, closure, closureAnswer: null,
    execution: { preparationId: uuid(5), leaseId: uuid(6), generationId: uuid(7), environmentId: binding.environmentId,
      environmentManifestHash: h('8'), applicationSourceHash: h('9'), executionIdentityHash: h('0'), initialStateSha256: h('1') },
    census: { schemaVersion: 'bts-admitted-action-census-reference/v1', entries: rawCommands.map((raw, i) => {
      const command = TaskActionCommandSchema.parse(raw);
      return { actionId: uuid(101 + i), actionSequence: i + 1, ownerOperationId: 'unit_operation_' + i,
        actionKind: command.kind, command, commandSha256: sha256CanonicalTaskJson({ runId: binding.runId, taskIndex: 0, command }),
        receiptStatus: 'observed', receiptRevision: 1, transactionHash: null, actionEvidence: evidence('action', uuid(101 + i)),
        family: i < 2 ? 'read' : i < 4 ? 'payment' : 'chain' };
    }) }, children: { paid: { evidence: evidence('observation', uuid(8)), boundary },
      chain: { evidence: evidence('observation', uuid(9)), boundary: structuredClone(boundary) } } };
}

// Envelope-only fixtures do not attest child effects, chain execution or a passing task.
test('all actual task IDs retain the same nine-kind census without a task-goal command filter', () => {
  for (const task of tasks) {
    const value = fixture(task), parsed = parseAdmittedActionsCapturePacket(Buffer.from(JSON.stringify(value)));
    assert.equal(parsed.binding.taskId, task);
    assert.equal(parsed.census.entries.length, 9);
    assert.equal('credit' in parsed, false);
    assert.equal('coverage' in parsed, false);
    assert.equal('document' in parsed.census.entries[0]!, false);
  }
});

for (const [name, change] of [
  ['action skipped', (v: AdmittedActionsCapturePacket) => { v.census.entries.pop(); }],
  ['duplicate action', (v: AdmittedActionsCapturePacket) => { v.census.entries[2]!.actionId = v.census.entries[1]!.actionId; }],
  ['different command under old payload hash', (v: AdmittedActionsCapturePacket) => { v.census.entries[1]!.command = { kind: 'inspect_catalog' }; }],
  ['wrong family', (v: AdmittedActionsCapturePacket) => { v.census.entries[2]!.family = 'chain'; }],
  ['unknown receipt', (v: AdmittedActionsCapturePacket) => { Object.assign(v.census.entries[2]!, { receiptStatus: 'unknown' }); }],
  ['foreign generation shape', (v: AdmittedActionsCapturePacket) => { v.execution.generationId = 'not-a-uuid'; }],
  ['different child block', (v: AdmittedActionsCapturePacket) => { v.children.chain.boundary.finalBlockHash = '0x' + h('1'); }],
  ['different child cutoff', (v: AdmittedActionsCapturePacket) => { v.children.chain.boundary.actionCutoffSequence--; }],
  ['same child evidence file', (v: AdmittedActionsCapturePacket) => { v.children.chain.evidence = v.children.paid.evidence; }],
  ['extra grade field', (v: AdmittedActionsCapturePacket) => { Object.assign(v, { credit: '1' }); }],
  ['raw document in reference root', (v: AdmittedActionsCapturePacket) => { Object.assign(v.census.entries[0]!, { document: {} }); }],
] as const) {
  test(`reference root rejects ${name}`, () => {
    const value = fixture(); change(value);
    assert.throws(() => validateAdmittedActionsCapturePacket(value), /ADMITTED_ACTION_PACKET_INVALID/);
  });
}

test('S2 and S3 final answers must match immutable closure hashes; absent and wrong answers are not fabricated', () => {
  for (const taskId of ['S2', 'S3'] as const) {
    const value = fixture(taskId);
    const answer = taskId === 'S2' ? { amountUnits: 'wrong-but-valid-answer' } : { offerId: 'wrong-offer' };
    value.closureAnswer = answer;
    assert.throws(() => validateAdmittedActionsCapturePacket(value), /ADMITTED_ACTION_PACKET_INVALID/);
    value.closure.payloadHash = sha256CanonicalTaskJson({ action: 'task_finish', runId: value.binding.runId,
      taskIndex: 0, answer });
    const parsed = validateAdmittedActionsCapturePacket(value);
    assert.deepEqual(parsed.closureAnswer, answer);
    assert.equal('credit' in parsed, false);
    assert.throws(() => validateAdmittedClosureAnswer(value.binding, 0, value.closure, { hiddenGrade: 1 }), /ADMITTED_ACTION_PACKET_INVALID/);
  }
  const s1 = fixture();
  assert.throws(() => validateAdmittedClosureAnswer(s1.binding, 0, s1.closure, { offerId: 'wrong-offer' }), /ADMITTED_ACTION_PACKET_INVALID/);
});

test('deadline closure cannot import an answer or a forged agent finish', () => {
  const value = fixture('S2');
  value.closure.reason = 'task_deadline'; value.closure.operationId = null;
  value.closure.payloadHash = sha256CanonicalTaskJson({ runId: value.binding.runId, taskIndex: 0, reason: 'task_deadline' });
  assert.equal(validateAdmittedActionsCapturePacket(value).closureAnswer, null);
  value.closureAnswer = { amountUnits: '1' };
  assert.throws(() => validateAdmittedActionsCapturePacket(value), /ADMITTED_ACTION_PACKET_INVALID/);
});

test('generic composition independently reprojects both empty families without inventing action effects', async () => {
  const f = await makeAdmittedActionsCaptureFixture();
  const candidate = composeAdmittedActionObservationCandidates(f.packet, f.projected.paid, f.projected.chain, f.root, f.options);
  assert.equal(candidate.cutoffStatus, 'authoritative');
  assert.equal(candidate.observations!.finalStates.length, 1);
  for (const field of ['transfers', 'payments', 'stateMutations', 'deliveries', 'expenses'] as const)
    assert.deepEqual(candidate.observations![field], []);
  assert.equal('credit' in candidate, false);
  assert.equal(candidate.observations!.finalStates[0]!.sequence, candidate.observationCutoffSequence);
});

test('a forged child candidate or observed label cannot replace independently retained source effects', async () => {
  const f = await makeAdmittedActionsCaptureFixture();
  const candidate = structuredClone(f.projected.chain);
  candidate.observations!.finalStates[0]!.balances[0]!.amountUnits = '999';
  assert.throws(() => composeAdmittedActionObservationCandidates(f.packet, f.projected.paid, candidate, f.root, f.options),
    /ADMITTED_ACTION_PROJECTION_MISMATCH/);
  const paid = structuredClone(f.paid);
  (paid.bef.before.payments as unknown[]).push({ payment_id: uuid(999), operation_id: uuid(998) });
  paid.bef.after = structuredClone(paid.bef.before);
  paid.bef.censusSha256 = sha256CanonicalTaskJson(paid.bef.after);
  paid.coverage.befPaymentCount = 1;
  assert.throws(() => composeAdmittedActionObservationCandidates(f.packet, f.projected.paid, f.projected.chain, f.root,
    { ...f.options, paidPacket: paid }), /PAID_FAMILY_EFFECTS_UNVERIFIED|PAID_DATA_PACKET_INVALID/);
});

test('generic composition rejects missing per-transaction chain history despite complete coverage labels', async () => {
  const f = await makeAdmittedActionsCaptureFixture();
  const chain = structuredClone(f.chain);
  delete (chain.rpc as unknown as Record<string, unknown>).balanceHistory;
  assert.throws(() => composeAdmittedActionObservationCandidates(f.packet, f.projected.paid, f.projected.chain, f.root,
    { ...f.options, chainPacket: chain }));
});

test('delivery-absence authority handoff binds actual root census, payment identity and all closure pins', () => {
  // Synthetic trusted-candidate shape tests authority handoff only, not payment execution/proof.
  const packet = fixture();
  const pay = packet.census.entries[2]!;
  pay.transactionHash = '0x' + h('1');
  const replacement = { kind: 'inspect_catalog' as const };
  Object.assign(packet.census.entries[3]!, { actionKind: replacement.kind, family: 'read', command: replacement,
    commandSha256: sha256CanonicalTaskJson({ runId: packet.binding.runId, taskIndex: 0, command: replacement }) });
  const root = { ...packet.children.paid.evidence, path: 'artifacts/runs/owner-identity-bef-task-coordinator/observation/root.json' };
  const proof = { schemaVersion: 'bts-delivery-request-absence/v1' as const, status: 'not_admitted_at_cutoff' as const,
    paymentAttemptId: uuid(700), paymentActionSequence: 3, acceptedActionCutoffSequence: 9,
    authority: { closureId: packet.closure.closureId, preparationId: packet.execution.preparationId,
      leaseId: packet.execution.leaseId, generationId: packet.execution.generationId }, captureEvidence: packet.children.paid.evidence };
  const candidate: TaskObservationBundleCandidate = { schemaVersion: 'bts-task-observation-bundle-candidate/v1',
    cutoffStatus: 'authoritative', cutoffEvidence: root, observationCutoffSequence: 1, observations: {
      schemaVersion: 'bts-task-observations/v1', binding: packet.binding, captureEvidence: root, coveredThroughSequence: 1, coverage: {},
      transfers: [], payments: [{ kind: 'payment', observationId: 'unit-payment', sequence: 1, actionSequence: 3,
        source: 'persisted_observer', binding: packet.binding, evidence: packet.children.paid.evidence,
        paymentAttemptId: proof.paymentAttemptId, status: 'settled', gasPayer: 'facilitator', transactionHash: pay.transactionHash,
        requirements: { scheme: 'exact', resourceId: 'unit', offerId: 'unit', version: '2', amountUnits: '1',
          network: 'eip155:31337', assetId: 'USDC', recipient: '0x0000000000000000000000000000000000000009', authFields: [] },
        deliveryRequestAbsence: proof }], stateMutations: [], finalStates: [], allowanceChanges: [], allowanceUses: [],
      answers: [], selections: [], deliveries: [], trades: [], conversions: [], expenses: [] } };
  assert.deepEqual(admittedDeliveryAbsenceSources(packet, candidate, root), [packet.children.paid.evidence]);
  for (const key of ['closureId', 'preparationId', 'leaseId', 'generationId'] as const) {
    const changed = structuredClone(candidate);
    changed.observations!.payments[0]!.deliveryRequestAbsence!.authority[key] = uuid(999);
    assert.throws(() => admittedDeliveryAbsenceSources(packet, changed, root), /ADMITTED_ACTION_CHILD_MISMATCH/);
  }
  const changed = structuredClone(candidate);
  changed.observations!.payments[0]!.deliveryRequestAbsence!.paymentAttemptId = uuid(999);
  assert.throws(() => admittedDeliveryAbsenceSources(packet, changed, root), /ADMITTED_ACTION_CHILD_MISMATCH/);
  assert.throws(() => admittedDeliveryAbsenceSources(fixture(), candidate, root), /ADMITTED_ACTION_CHILD_MISMATCH/,
    'an admitted retrieval cannot be called request absence');
});

test('future stock-funded S4 unwrap cannot become false success through an unrepresented burn', async () => {
  const f = await makeAdmittedActionsCaptureFixture();
  const taskCase = { ...f.taskCase, taskId: 'S4', initialState: { ...f.taskCase.initialState,
    balances: [...f.taskCase.initialState.balances.filter(item => item.assetId !== 'WETH'),
      { account: 'participant', assetId: 'WETH', amountUnits: '5' }] },
    objective: { owner: 'participant', tokenAssetId: 'USDC', spender: '0x0000000000000000000000000000000000000009',
      initialAllowanceUnits: '1' } } as TaskCase;
  const observations = structuredClone(f.projected.chain.observations!);
  const meta = { observationId: 'unit-verified-unwrap', sequence: 1, actionSequence: 1, source: 'persisted_observer' as const,
    binding: observations.binding, evidence: f.packet.children.chain.evidence };
  observations.conversions = [{ ...meta, kind: 'conversion', conversion: 'unwrap', inputAssetId: 'WETH', inputAmountUnits: '1',
    outputAssetId: 'ETH', outputAmountUnits: '1', transactionHash: '0x' + h('1'), receiptStatus: 'success' }];
  assert.throws(() => assertAdmittedGoalEffectRepresentation(taskCase, observations, f.chain.rpc.participant),
    /ADMITTED_ACTION_GOAL_EFFECT_UNREPRESENTED/);
  assert.deepEqual(observations.transfers, [], 'guard must not manufacture a burn transfer or counterparty');
  const reverted = structuredClone(observations);
  reverted.conversions[0]!.receiptStatus = 'reverted';
  assert.doesNotThrow(() => assertAdmittedGoalEffectRepresentation(taskCase, reverted, f.chain.rpc.participant));
  const witnessed = structuredClone(observations);
  witnessed.transfers.push({ ...meta, observationId: 'unit-actual-outgoing', kind: 'transfer', from: 'participant',
    to: '0x0000000000000000000000000000000000000009', assetId: 'ETH', amountUnits: '1', receiptStatus: 'success',
    transactionHash: '0x' + h('2'), operation: 'principal' });
  assert.doesNotThrow(() => assertAdmittedGoalEffectRepresentation(taskCase, witnessed, f.chain.rpc.participant));
  assert.doesNotThrow(() => assertAdmittedGoalEffectRepresentation(f.taskCase, observations, f.chain.rpc.participant),
    'guard may not add a task-goal restriction to other task rubrics');
});

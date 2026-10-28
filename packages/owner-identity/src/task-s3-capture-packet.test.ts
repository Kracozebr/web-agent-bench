import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalTaskJson, sha256CanonicalTaskJson } from './task-release.js';
import { createS3CapturePacketFixture } from './task-s3-capture-packet.fixture.js';
import { parseS3CapturePacket, projectS3PacketObservations, validateS3CapturePacket } from './task-s3-capture-packet.js';

test('S3 packet validates, parses, and projects only the structured finish answer', () => {
  const { packet, binding, taskCase } = createS3CapturePacketFixture();
  validateS3CapturePacket(packet);
  assert.deepEqual(parseS3CapturePacket(JSON.stringify(packet)), packet);
  // The evidence sink serializes canonical JSON, which sorts nested catalog keys.
  // The original BEF response hash is verified against raw child evidence by the sealed reader.
  assert.deepEqual(parseS3CapturePacket(canonicalTaskJson(packet)), packet);
  const observations = projectS3PacketObservations(packet, { binding, taskCase,
    captureEvidence: { path: 'artifacts/runs/owner-identity-bef-task-coordinator/observation/s3.json',
      sha256: 'f'.repeat(64), boundary: 'actual_tool_http_x402_local_evm_application_store' } });
  assert.deepEqual(observations.answers.map((item) => item.answer), [{ offerId: 'selected' }]);
  assert.deepEqual(observations.selections.map((item) => item.offerId), ['selected']);
  assert.equal('eligible' in observations.selections[0]!, false);
  assert.equal(observations.coverage?.answers, 'complete');
  assert.equal(observations.coverage?.selections, 'complete');
  assert.equal(observations.captureEvidence.path.endsWith('/s3.json'), true);
});

test('S3 requires a well-formed durable BEF response hash without reconstructing wire JSON', () => {
  const { packet } = createS3CapturePacketFixture();
  const invalidHash = structuredClone(packet);
  invalidHash.bef.before.operations[0]!.response_sha256 = 'not-a-sha256';
  invalidHash.bef.after = structuredClone(invalidHash.bef.before);
  invalidHash.bef.censusSha256 = sha256CanonicalTaskJson(invalidHash.bef.before);
  assert.throws(() => validateS3CapturePacket(invalidHash));
});
test('S3 rejects unbound mode, altered finish data, and action/census contradictions', () => {
  const { packet } = createS3CapturePacketFixture();
  const wrongMode = structuredClone(packet);
  wrongMode.taskCase.mode = 'training';
  assert.throws(() => validateS3CapturePacket(wrongMode));

  const wrongAnswer = structuredClone(packet);
  wrongAnswer.closure.answer = { offerId: 'other' };
  assert.throws(() => validateS3CapturePacket(wrongAnswer));

  const paid = structuredClone(packet);
  paid.bef.before.payments.push({ payment_id: 'unexpected' });
  paid.bef.after = structuredClone(paid.bef.before);
  paid.bef.censusSha256 = sha256CanonicalTaskJson(paid.bef.before);
  assert.throws(() => validateS3CapturePacket(paid));

  const wrongOperation = structuredClone(packet);
  const handle = wrongOperation.ownerActions[0]!.response!.readHandle as Record<string, unknown>;
  handle.kind = 'offer';
  assert.throws(() => validateS3CapturePacket(wrongOperation));
});

test('S3 retains a locally rejected read action without inventing a BEF request', () => {
  const { packet } = createS3CapturePacketFixture();
  const rejected = structuredClone(packet);
  rejected.ownerActions[0] = { ...rejected.ownerActions[0]!, receiptStatus: 'rejected_before_execution',
    reasonCode: 'bef_environment_health_unavailable', befOperationId: null, response: null };
  rejected.bef.before.operations = [];
  rejected.bef.after = structuredClone(rejected.bef.before);
  rejected.bef.censusSha256 = sha256CanonicalTaskJson(rejected.bef.before);
  validateS3CapturePacket(rejected);
  assert.equal(rejected.ownerActions[0]!.reasonCode, 'bef_environment_health_unavailable');
  assert.deepEqual(rejected.bef.before.operations, []);
});

test('S3 preserves an out-of-catalog finish answer without deriving eligibility', () => {
  const { packet, binding, taskCase } = createS3CapturePacketFixture();
  const unlisted = structuredClone(packet);
  unlisted.closure.answer = { offerId: 'agent-supplied-unlisted-id' };
  unlisted.closure.payloadHash = sha256CanonicalTaskJson({ action: 'task_finish', runId: binding.runId, taskIndex: 0,
    answer: unlisted.closure.answer });
  validateS3CapturePacket(unlisted);
  const observations = projectS3PacketObservations(unlisted, { binding, taskCase });
  assert.deepEqual(observations.selections.map((item) => item.offerId), ['agent-supplied-unlisted-id']);
  assert.equal('eligible' in observations.selections[0]!, false);
});

test('S3 rejects incomplete block intervals even when the endpoint state is unchanged', () => {
  const { packet } = createS3CapturePacketFixture();
  const incomplete = structuredClone(packet);
  incomplete.rpc.final.blockNumber = '101';
  incomplete.rpc.final.parentHash = incomplete.rpc.baseline.blockHash;
  assert.throws(() => validateS3CapturePacket(incomplete));
});

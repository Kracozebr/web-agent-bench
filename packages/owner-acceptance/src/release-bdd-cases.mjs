import { createHash } from 'node:crypto';

const SNAPSHOT_TABLES = Object.freeze([
  'oid_task_release',
  'oid_task_release_active',
  'oid_task_release_activation_journal',
  'oid_benchmark_run',
  'oid_run_launch_intent',
  'oid_run_task',
  'oid_run_event',
  'oid_ledger_entry',
  'oid_run_reservation',
  'oid_run_budget_hold',
  'oid_run_dispatch_claim',
  'oid_run_execution_slot',
]);

const hashBytes = (bytes) => createHash('sha256').update(bytes).digest('hex');

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function clone(value) {
  return structuredClone(value);
}

function findCase(manifest, mode, taskId) {
  const taskCase = manifest?.cases?.[mode]?.find((entry) => entry.taskId === taskId);
  if (!taskCase) throw new Error('release_probe_required_case_missing');
  return taskCase;
}

function caseSubject(taskCase) {
  return `${taskCase.mode}/${taskCase.taskId}/${taskCase.caseId}`;
}

function replaceStateProjection(taskCase, changes, sha256CanonicalTaskJson) {
  const balances = changes.balances ?? taskCase.initialState.balances;
  const allowances = changes.allowances ?? taskCase.initialState.allowances;
  const deliveredComponentIds = changes.deliveredComponentIds ?? taskCase.initialState.deliveredComponentIds;
  const fulfilledObligationIds = changes.fulfilledObligationIds ?? taskCase.initialState.fulfilledObligationIds;
  const projection = {
    balances: [...balances].sort((left, right) => {
      const leftKey = `${left.account.toLowerCase()}|${left.assetId}`;
      const rightKey = `${right.account.toLowerCase()}|${right.assetId}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    }),
    allowances: [...allowances].sort((left, right) => {
      const leftKey = `${left.owner.toLowerCase()}|${left.tokenAssetId}|${left.spender.toLowerCase()}`;
      const rightKey = `${right.owner.toLowerCase()}|${right.tokenAssetId}|${right.spender.toLowerCase()}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    }),
    deliveredComponentIds: [...deliveredComponentIds].sort(),
    fulfilledObligationIds: [...fulfilledObligationIds].sort(),
  };
  taskCase.initialState = { stateSha256: sha256CanonicalTaskJson(projection), ...projection };
  taskCase.referencePath.initialStateSha256 = taskCase.initialState.stateSha256;
}

function rebindHashes(manifest, releaseApi, { identityChanged = false } = {}) {
  if (identityChanged) {
    manifest.executionIdentityHash = releaseApi.sha256CanonicalTaskJson(manifest.executionIdentity);
    for (const taskCase of [...manifest.cases.training, ...manifest.cases.ranked]) {
      taskCase.executionIdentityHash = manifest.executionIdentityHash;
    }
  }
  for (const taskCase of [...manifest.cases.training, ...manifest.cases.ranked]) {
    const { caseHash: _oldHash, ...withoutCaseHash } = taskCase;
    taskCase.caseHash = releaseApi.sha256CanonicalTaskJson(withoutCaseHash);
  }
  manifest.policyHash = releaseApi.taskPolicyHash(manifest);
  manifest.benchmarkHash = releaseApi.taskBenchmarkHash(manifest);
  const { manifestHash: _oldManifestHash, ...withoutManifestHash } = manifest;
  manifest.manifestHash = releaseApi.sha256CanonicalTaskJson(withoutManifestHash);
  return manifest;
}

function schemaPathExpected(path) {
  return (blocker) => blocker.code === 'manifest_schema_invalid' && blocker.subject === path;
}

export function createReleaseNegativeCandidates(sourceManifest, releaseApi) {
  const rankedU1 = findCase(sourceManifest, 'ranked', 'U1');
  const rankedM1 = findCase(sourceManifest, 'ranked', 'M1');
  const rankedS3 = findCase(sourceManifest, 'ranked', 'S3');
  const rankedH2 = findCase(sourceManifest, 'ranked', 'H2');
  const trainingS1 = findCase(sourceManifest, 'training', 'S1');
  const u1Index = sourceManifest.cases.ranked.findIndex((entry) => entry.taskId === 'U1');
  const u1Subject = caseSubject(rankedU1);
  const componentPath = `cases.ranked.${u1Index}.objective.requiredComponents`;
  const allocationPath = `cases.ranked.${u1Index}.objective.allocationAssets`;
  const payoutPath = `cases.ranked.${u1Index}.objective.payoutObligations`;
  const spenderPath = `cases.ranked.${u1Index}.objective.temporarySpenderScope`;
  const cases = [];

  const add = (id, mutate, expected, mutationPath) => {
    const candidate = clone(sourceManifest);
    try {
      mutate(candidate);
      rebindHashes(candidate, releaseApi);
      cases.push({ id, candidate, expected, mutationPath });
    } catch (error) {
      cases.push({ id, candidate: null, expected, mutationPath, generationErrorCode: safeErrorCode(error) });
    }
  };

  add('placeholder', (candidate) => {
    const target = findCase(candidate, 'ranked', 'M1');
    target.caseId = `${target.caseId.slice(0, 96)}-placeholder`;
  }, {
    any: [(blocker) => blocker.code === 'placeholder_or_latest_value' &&
      blocker.subject.startsWith('ranked/M1/') && blocker.subject.includes('placeholder')],
  }, `cases.ranked.M1.caseId`);

  add('wrong_block_identity', (candidate) => {
    const identity = candidate.executionIdentity;
    const shiftedBlock = (BigInt(identity.sourceBlockNumber) + 1n).toString();
    identity.sourceBlockNumber = shiftedBlock;
    identity.localForkBlockNumber = shiftedBlock;
    for (const contract of identity.contracts) contract.blockNumber = shiftedBlock;
    rebindHashes(candidate, releaseApi, { identityChanged: true });
  }, { all: [{ code: 'missing_feasibility_evidence', subject: 'feasibilityEvidence' }] }, 'executionIdentity.sourceBlockNumber');

  add('wrong_contract_code_identity', (candidate) => {
    const contract = candidate.executionIdentity.contracts.find((entry) => entry.contractId === 'pool');
    if (!contract) throw new Error('release_probe_pool_contract_missing');
    contract.codeHash = `${contract.codeHash[0] === '0' ? '1' : '0'}${contract.codeHash.slice(1)}`;
    rebindHashes(candidate, releaseApi, { identityChanged: true });
  }, { all: [{ code: 'missing_feasibility_evidence', subject: 'feasibilityEvidence' }] }, 'executionIdentity.contracts[pool].codeHash');

  add('initially_satisfied_paid_case', (candidate) => {
    const target = findCase(candidate, 'ranked', 'M1');
    replaceStateProjection(target, {
      deliveredComponentIds: [...target.initialState.deliveredComponentIds, target.objective.component.componentId],
    }, releaseApi.sha256CanonicalTaskJson);
  }, { all: [{ code: 'unsolvable_or_initially_solved_case', subject: caseSubject(rankedM1) }] },
  'cases.ranked.M1.initialState.deliveredComponentIds');

  add('initially_fulfilled_payout_obligation', (candidate) => {
    const target = findCase(candidate, 'ranked', 'H2');
    replaceStateProjection(target, {
      fulfilledObligationIds: [...target.initialState.fulfilledObligationIds, target.objective.obligations[0].obligationId],
    }, releaseApi.sha256CanonicalTaskJson);
  }, { all: [{ code: 'invalid_task_reference', subject: caseSubject(rankedH2) }] },
  'cases.ranked.H2.initialState.fulfilledObligationIds');

  add('missing_reference_evidence', (candidate) => {
    const target = findCase(candidate, 'training', 'S1');
    target.referencePath.evidence.path = `${target.referencePath.evidence.path}.missing-bts-reference`;
  }, { all: [{ code: 'reference_path_evidence_unavailable', subject: caseSubject(trainingS1) }] },
  'cases.training.S1.referencePath.evidence.path');

  add('no_qualifying_catalog_offer', (candidate) => {
    findCase(candidate, 'ranked', 'S3').objective.required.requiredDataType = 'bts-no-qualifying-data-type';
  }, { all: [{ code: 'invalid_catalog_predicates', subject: caseSubject(rankedS3) }] },
  'cases.ranked.S3.objective.required.requiredDataType');

  add('empty_u1_component_set', (candidate) => {
    findCase(candidate, 'ranked', 'U1').objective.requiredComponents = [];
  }, { all: [schemaPathExpected(componentPath)] }, componentPath);

  add('duplicate_u1_component', (candidate) => {
    const target = findCase(candidate, 'ranked', 'U1');
    target.objective.requiredComponents = [target.objective.requiredComponents[0], target.objective.requiredComponents[0]];
  }, { all: [{ code: 'invalid_u1_fixed_sets', subject: u1Subject }] }, 'cases.ranked.U1.objective.requiredComponents');

  add('incomplete_u1_component_validator', (candidate) => {
    const component = findCase(candidate, 'ranked', 'U1').objective.requiredComponents[0];
    const predicateField = component.validator.predicates[0]?.field;
    const remaining = component.validator.requiredFields.filter((field) => field.name !== predicateField);
    if (!predicateField || remaining.length === 0) throw new Error('release_probe_u1_validator_not_mutable_without_schema_failure');
    component.validator.requiredFields = remaining;
  }, { all: [
    { code: 'missing_component_validator_field', subject: u1Subject },
    { code: 'invalid_u1_fixed_sets', subject: u1Subject },
  ] }, 'cases.ranked.U1.objective.requiredComponents[0].validator.requiredFields');

  add('empty_u1_allocation_asset_set', (candidate) => {
    findCase(candidate, 'ranked', 'U1').objective.allocationAssets = [];
  }, { all: [schemaPathExpected(allocationPath)] }, allocationPath);

  add('duplicate_u1_allocation_asset', (candidate) => {
    const target = findCase(candidate, 'ranked', 'U1');
    target.objective.allocationAssets = [target.objective.allocationAssets[0], target.objective.allocationAssets[0]];
  }, { all: [{ code: 'invalid_u1_fixed_sets', subject: u1Subject }] }, 'cases.ranked.U1.objective.allocationAssets');

  add('fewer_than_two_u1_payout_obligations', (candidate) => {
    findCase(candidate, 'ranked', 'U1').objective.payoutObligations =
      findCase(candidate, 'ranked', 'U1').objective.payoutObligations.slice(0, 1);
  }, { all: [schemaPathExpected(payoutPath)] }, payoutPath);

  add('duplicate_u1_payout_obligation', (candidate) => {
    const target = findCase(candidate, 'ranked', 'U1');
    target.objective.payoutObligations[1] = clone(target.objective.payoutObligations[0]);
  }, { all: [{ code: 'invalid_u1_fixed_sets', subject: u1Subject }] }, 'cases.ranked.U1.objective.payoutObligations');

  add('empty_u1_temporary_spender_set', (candidate) => {
    findCase(candidate, 'ranked', 'U1').objective.temporarySpenderScope = [];
  }, { all: [schemaPathExpected(spenderPath)] }, spenderPath);

  add('duplicate_u1_temporary_spender', (candidate) => {
    const target = findCase(candidate, 'ranked', 'U1');
    target.objective.temporarySpenderScope = [target.objective.temporarySpenderScope[0], target.objective.temporarySpenderScope[0]];
  }, { all: [{ code: 'invalid_u1_fixed_sets', subject: u1Subject }] }, 'cases.ranked.U1.objective.temporarySpenderScope');

  add('initially_satisfied_u1_allocation', (candidate) => {
    const target = findCase(candidate, 'ranked', 'U1');
    const assets = target.objective.allocationAssets;
    const totalUsdcValue = 100_000_000n;
    const targetBalances = new Map(assets.map((item) => {
      const numerator = BigInt(item.usdcBaseUnitsPerAssetBaseUnit.numerator);
      const denominator = BigInt(item.usdcBaseUnitsPerAssetBaseUnit.denominator);
      const targetValue = totalUsdcValue * BigInt(item.targetShareBps) / 10_000n;
      const amount = targetValue * denominator / numerator;
      if (amount < 0n || (BigInt(item.targetShareBps) > 0n && amount === 0n) || amount.toString().length > 78) {
        throw new Error('release_probe_allocation_amount_out_of_range');
      }
      return [item.assetId, amount.toString()];
    }));
    const balances = target.initialState.balances.filter((entry) => !(entry.account === 'participant' && targetBalances.has(entry.assetId)));
    for (const [assetId, amountUnits] of targetBalances) balances.push({ account: 'participant', assetId, amountUnits });
    replaceStateProjection(target, { balances }, releaseApi.sha256CanonicalTaskJson);
    if (!u1AllocationSatisfied(target)) throw new Error('release_probe_allocation_rounding_outside_tolerance');
  }, { all: [{ code: 'invalid_u1_fixed_sets', subject: u1Subject }] }, 'cases.ranked.U1.initialState.balances');

  return cases;
}

function gcd(left, right) {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a === 0n ? 1n : a;
}

function u1AllocationSatisfied(taskCase) {
  const values = taskCase.objective.allocationAssets.map((target) => {
    const amount = taskCase.initialState.balances
      .filter((balance) => balance.account === 'participant' && balance.assetId === target.assetId)
      .reduce((sum, balance) => sum + BigInt(balance.amountUnits), 0n);
    return {
      target,
      numerator: amount * BigInt(target.usdcBaseUnitsPerAssetBaseUnit.numerator),
      denominator: BigInt(target.usdcBaseUnitsPerAssetBaseUnit.denominator),
    };
  });
  if (values.every((value) => value.numerator === 0n)) return false;
  let totalNumerator = 0n;
  let totalDenominator = 1n;
  for (const value of values) {
    totalNumerator = totalNumerator * value.denominator + value.numerator * totalDenominator;
    totalDenominator *= value.denominator;
    const divisor = gcd(totalNumerator, totalDenominator);
    totalNumerator /= divisor;
    totalDenominator /= divisor;
  }
  if (totalNumerator === 0n) return false;
  return values.every(({ target, numerator, denominator }) => {
    const absoluteNumerator = numerator * totalDenominator * 10_000n;
    const assetDenominator = denominator * totalNumerator;
    const targetNumerator = BigInt(target.targetShareBps) * assetDenominator;
    const delta = absoluteNumerator >= targetNumerator ? absoluteNumerator - targetNumerator : targetNumerator - absoluteNumerator;
    return delta <= BigInt(target.toleranceBps) * assetDenominator;
  });
}

function summarizeRelease(manifest, referenceResults, difficultyEvidence) {
  const allCases = [...manifest.cases.training, ...manifest.cases.ranked];
  const u1 = findCase(manifest, 'ranked', 'U1');
  return {
    // BTS evidence is private, local acceptance output. Retain the exact
    // admitted candidate so the Python BDD adapter can independently recompute
    // its identity, case hashes, fixed inventory, and evidence references.
    manifest: clone(manifest),
    releaseIdentity: manifest.releaseIdentity,
    manifestHash: manifest.manifestHash,
    benchmarkVersion: manifest.benchmarkVersion,
    benchmarkHash: manifest.benchmarkHash,
    policyHash: manifest.policyHash,
    executionIdentityHash: manifest.executionIdentityHash,
    sourceEnvironmentHash: manifest.executionIdentity.environmentManifestSha256,
    sourceChainId: manifest.executionIdentity.sourceChainId,
    sourceBlockNumber: manifest.executionIdentity.sourceBlockNumber,
    sourceBlockHash: manifest.executionIdentity.sourceBlockHash,
    localChainId: manifest.executionIdentity.localChainId,
    localForkBlockNumber: manifest.executionIdentity.localForkBlockNumber,
    participantToolProtocol: manifest.participantToolProtocol ?? 'combined_purchase_v1',
    rawPathsHashes: [
      { kind: 'feasibility', path: manifest.feasibilityEvidence.path, sha256: manifest.feasibilityEvidence.sha256 },
      { kind: 'difficulty_review', path: manifest.difficultyReviewEvidence.path, sha256: manifest.difficultyReviewEvidence.sha256 },
      ...allCases.flatMap((taskCase) => [
        { kind: 'initial_state', taskId: taskCase.taskId, mode: taskCase.mode,
          path: taskCase.initialStateEvidence.path, sha256: taskCase.initialStateEvidence.sha256 },
        { kind: 'reference_path', taskId: taskCase.taskId, mode: taskCase.mode,
          path: taskCase.referencePath.evidence.path, sha256: taskCase.referencePath.evidence.sha256 },
      ]),
    ],
    caseHashes: allCases.map((taskCase) => ({
      mode: taskCase.mode,
      taskId: taskCase.taskId,
      caseId: taskCase.caseId,
      caseHash: taskCase.caseHash,
      rubricHash: taskCase.rubricHash,
      taskWeight: taskCase.taskWeight,
      referenceActionCount: taskCase.referencePath.actionCount,
      referenceEvidence: { path: taskCase.referencePath.evidence.path, sha256: taskCase.referencePath.evidence.sha256 },
    })),
    u1: {
      componentIds: u1.objective.requiredComponents.map((component) => component.componentId),
      componentValidatorSpecs: u1.objective.requiredComponents.map((component) => ({
        componentId: component.componentId,
        resourceId: component.resourceId,
        sourceIds: [...component.sourceIds],
        validator: clone(component.validator),
      })),
      allocationAssets: clone(u1.objective.allocationAssets),
      payoutObligations: clone(u1.objective.payoutObligations),
      temporarySpenderKeys: u1.objective.temporarySpenderScope.map((entry) => ({
        owner: entry.owner, tokenAssetId: entry.tokenAssetId, spender: entry.spender,
      })),
    },
    verifier: {
      referencePathCount: referenceResults.length,
      verifiedReferencePathCount: referenceResults.filter((entry) => entry?.result?.status === 'verified').length,
      difficultyStatus: difficultyEvidence?.status ?? 'unavailable',
    },
  };
}

async function readOnlyDatabaseSnapshot(observerPool) {
  if (!observerPool || typeof observerPool.connect !== 'function') throw new Error('release_probe_readonly_observer_unavailable');
  const client = await observerPool.connect();
  let inTransaction = false;
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    inTransaction = true;
    const session = (await client.query(`SELECT current_user AS role,current_setting('transaction_read_only') AS readonly`)).rows[0];
    if (!session || session.role !== 'oid_observer' || session.readonly !== 'on') {
      throw new Error('release_probe_readonly_observer_identity_invalid');
    }
    const tables = {};
    for (const table of SNAPSHOT_TABLES) {
      const exists = (await client.query('SELECT to_regclass($1) IS NOT NULL AS present', [`public.${table}`])).rows[0]?.present === true;
      if (!exists) {
        tables[table] = { present: false, rowCount: 0, rowsSha256: hashBytes(Buffer.alloc(0)) };
        continue;
      }
      const rows = (await client.query(`SELECT to_jsonb(row_value) AS row FROM ${table} AS row_value ORDER BY to_jsonb(row_value)::text`)).rows
        .map((entry) => entry.row);
      tables[table] = {
        present: true,
        rowCount: rows.length,
        rowsSha256: hashBytes(Buffer.from(canonicalJson(rows), 'utf8')),
        rows,
      };
    }
    const activePointer = (await client.query(`SELECT id,release_identity,manifest_hash,activated_at::text AS activated_at
      FROM oid_task_release_active ORDER BY id`)).rows;
    await client.query('COMMIT');
    inTransaction = false;
    const snapshot = { session: { role: session.role, readonly: session.readonly }, activePointer, tables };
    return { ...snapshot, stateSha256: hashBytes(Buffer.from(canonicalJson(snapshot), 'utf8')) };
  } catch (error) {
    if (inTransaction) await client.query('ROLLBACK').catch(() => {});
    const code = typeof error?.message === 'string' && /^release_probe_[a-z0-9_]+$/.test(error.message)
      ? error.message : 'release_probe_readonly_snapshot_failed';
    throw new Error(code);
  } finally {
    client.release();
  }
}

function expectedMatches(blockers, expected) {
  const matches = (matcher) => typeof matcher === 'function'
    ? blockers.some(matcher)
    : blockers.some((blocker) => blocker.code === matcher.code && blocker.subject === matcher.subject);
  if (expected.all && !expected.all.every(matches)) return false;
  if (expected.any && !expected.any.some(matches)) return false;
  return true;
}

function safeBlockerRows(result) {
  return Array.isArray(result?.blockers) ? result.blockers.map((blocker) => ({
    code: String(blocker.code ?? 'unknown'), subject: String(blocker.subject ?? 'unknown'),
  })) : [];
}

function safeErrorCode(error) {
  const message = typeof error?.message === 'string' ? error.message : '';
  return /^[A-Za-z0-9_:-]{1,128}$/.test(message) ? message : 'release_probe_activation_failed';
}

/**
 * Run BTS-SC-001/002 release-candidate negatives with the same production
 * verifier and PostgreSQL activation service that admitted the positive release.
 * AICODE-NOTE: Retain the real release identity for each mutated candidate. If
 * a negative unexpectedly validates, the immutable release row forces the
 * production transaction to roll back instead of switching the active pointer.
 * Candidate identity stays equal to the already sealed release identity, so an
 * unexpectedly validated mutated candidate collides with immutable content and
 * rolls back instead of moving the active pointer. No run/admission/charge API is
 * called by this probe.
 */
export async function runReleaseBddCases({ db, observerPool, manifest, verifier, positiveActivation, referenceResults, difficultyEvidence }) {
  const activation = positiveActivation;
  const verifiedManifest = activation?.release?.manifest;
  const referenceRows = Array.isArray(referenceResults) ? referenceResults : [];
  const releaseApi = await import('../../owner-identity/dist/task-release.js');
  const storeApi = await import('../../owner-identity/dist/task-store.js');
  const base = {
    schemaVersion: 'bts-release-negative-activation-probe/v1',
    classification: 'actual_production_release_validation_and_postgres_activation_no_run_or_charge',
  };
  if (!db || typeof db.transaction !== 'function' || typeof storeApi.activatePostgresTaskReleaseCandidate !== 'function' ||
      activation?.status !== 'validated' || !verifiedManifest || !manifest ||
      manifest.releaseIdentity !== verifiedManifest.releaseIdentity || manifest.manifestHash !== verifiedManifest.manifestHash ||
      typeof verifier?.verifyFeasibility !== 'function' || typeof verifier?.verifyReferencePath !== 'function' ||
      typeof verifier?.verifyDifficultyReview !== 'function' || referenceRows.length !== 20 ||
      referenceRows.some((entry) => entry?.result?.status !== 'verified') || difficultyEvidence?.status !== 'approved') {
    return { ...base, status: 'not_run', reasonCode: 'actual_positive_release_verification_not_complete', variants: [] };
  }

  let before;
  try {
    before = await readOnlyDatabaseSnapshot(observerPool);
  } catch (error) {
    return { ...base, status: 'not_run', reasonCode: safeErrorCode(error), variants: [] };
  }
  const databaseSnapshots = new Map([[before.stateSha256, before]]);
  const activeMatch = before.activePointer.length === 1 &&
    before.activePointer[0].release_identity === verifiedManifest.releaseIdentity &&
    before.activePointer[0].manifest_hash === verifiedManifest.manifestHash;
  if (!activeMatch) {
    return { ...base, status: 'not_run', reasonCode: 'active_release_database_binding_mismatch',
      release: summarizeRelease(verifiedManifest, referenceRows, difficultyEvidence),
      database: { before, unchanged: null, snapshots: [before] }, variants: [] };
  }

  const variants = [];
  let stateUnchanged = true;
  for (const probe of createReleaseNegativeCandidates(verifiedManifest, releaseApi)) {
    if (!probe.candidate) {
      variants.push({ id: probe.id, status: 'not_run', mutationPath: probe.mutationPath,
        expected: 'expected_production_blocker', observedBlockers: [], reasonCode: probe.generationErrorCode ?? 'negative_candidate_generation_failed' });
      continue;
    }
    const candidateHash = probe.candidate.manifestHash;
    let activationResult = null;
    let activationErrorCode = null;
    try {
      activationResult = await storeApi.activatePostgresTaskReleaseCandidate(db, probe.candidate, verifier);
    } catch (error) {
      activationErrorCode = safeErrorCode(error);
    }
    let after;
    try {
      after = await readOnlyDatabaseSnapshot(observerPool);
    } catch (error) {
      variants.push({ id: probe.id, status: 'failed', candidateHash, mutationPath: probe.mutationPath,
        expected: 'expected_production_blocker', observedBlockers: safeBlockerRows(activationResult),
        activationErrorCode, reasonCode: safeErrorCode(error) });
      stateUnchanged = false;
      break;
    }
    databaseSnapshots.set(after.stateSha256, after);
    const unchanged = before.stateSha256 === after.stateSha256;
    stateUnchanged &&= unchanged;
    const blockers = safeBlockerRows(activationResult);
    const blockedByExpected = activationResult?.status === 'blocked' && expectedMatches(blockers, probe.expected);
    const status = !unchanged ? 'failed' : blockedByExpected ? 'verified'
      : activationResult?.status === 'validated' || activationErrorCode ? 'failed' : 'not_run';
    variants.push({
      id: probe.id,
      status,
      candidateHash,
      candidateManifest: clone(probe.candidate),
      mutationPath: probe.mutationPath,
      expected: 'expected_production_blocker',
      observedBlockers: blockers,
      activationErrorCode,
      databaseStateSha256Before: before.stateSha256,
      databaseStateSha256After: after.stateSha256,
      databaseUnchanged: unchanged,
      ...(blockedByExpected ? {} : { reasonCode: !unchanged ? 'durable_database_state_changed'
        : activationResult?.status === 'validated' ? 'invalid_candidate_unexpectedly_validated'
          : activationErrorCode ? 'activation_rejected_with_error' : 'expected_predicate_not_observed' }),
    });
    if (!unchanged) break;
  }

  const verifiedCount = variants.filter((entry) => entry.status === 'verified').length;
  const failedCount = variants.filter((entry) => entry.status === 'failed').length;
  const notRunCount = variants.filter((entry) => entry.status === 'not_run').length;
  return {
    ...base,
    status: failedCount ? 'failed' : notRunCount || variants.length !== 17 ? 'blocked' : 'verified',
    positiveActivation: {
      status: activation.status,
      manifestHash: activation.release.manifestHash,
      validationEvidenceCount: activation.validationEvidence.length,
    },
    release: summarizeRelease(verifiedManifest, referenceRows, difficultyEvidence),
    database: { before, unchanged: stateUnchanged, snapshots: [...databaseSnapshots.values()] },
    coverage: { requested: 17, observed: verifiedCount, notRun: notRunCount, failed: failedCount },
    variants,
  };
}

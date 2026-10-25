import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { ensureSchema, poolFor, verifySchema } from './db.js';
import {
  finalizeTransactionCost,
  insertUnknownTransactionCost,
  type CostIdentity,
  type FeePolicySnapshot,
  type FinalCostObservation,
} from './transaction-costs.js';

const migrationTestUrl = process.env.BEF_MIGRATION_TEST_DATABASE_URL;
const RATE_NUM = '2';
const RATE_DEN = '3';
const MANIFEST = 'a'.repeat(64);
const POLICY: FeePolicySnapshot = {
  baseFeeWei: '2', priorityFeeWei: '1', ethUsdcRateNumerator: RATE_NUM,
  ethUsdcRateDenominator: RATE_DEN, rounding: 'floor-to-6-decimal-usdc-units',
  baseL1Fee: 'unmodelled', principalSeparateFromExpense: true,
};
const PAYER = '0x1111111111111111111111111111111111111111';
const BLOCK_HASH = `0x${'b'.repeat(64)}`;
const PARENT_HASH = `0x${'d'.repeat(64)}`;
const FINAL_EVIDENCE_SHA256 = 'c'.repeat(64);
const POLICY_CHECK_CONSTRAINTS = new Set([
  'bef_transaction_cost_fee_policy_snapshot_check',
  'bef_transaction_cost_rate_snapshot_ck',
]);

function isPolicyCheckViolation(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const postgresError = error as { code?: unknown; constraint?: unknown };
  return postgresError.code === '23514' && typeof postgresError.constraint === 'string' &&
    POLICY_CHECK_CONSTRAINTS.has(postgresError.constraint);
}

test('PostgreSQL transaction costs preserve unknown markers, exact final rows, and immutability', {
  skip: !migrationTestUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to a dedicated local migration-test database.' : false,
}, async () => {
  assert.ok(migrationTestUrl);
  const url = new URL(migrationTestUrl);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname.toLowerCase()),
    'the test URL must target loopback only');
  assert.match(url.pathname, /^\/bef_migration_test(?:_[a-z0-9]+)*$/i,
    'the test URL must target a dedicated bef_migration_test database');
  const requestedDatabaseName = decodeURIComponent(url.pathname.slice(1));

  const pool = poolFor(migrationTestUrl);
  const client = await pool.connect();
  const nonce = randomUUID().replaceAll('-', '');
  const envId = `bef-cost-${nonce.slice(0, 20)}`;
  const generationId = randomUUID();
  const operations = [randomUUID(), randomUUID(), randomUUID(), randomUUID(), randomUUID()];
  const hashes = [`0x${'1'.repeat(64)}`, `0x${'2'.repeat(64)}`, `0x${'3'.repeat(64)}`, `0x${'4'.repeat(64)}`, `0x${'5'.repeat(64)}`];

  const createOperation = async (operationId: string, transactionHash: string): Promise<void> => {
    await client.query(
      `INSERT INTO bef_operation(
         operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,request_sha256,
         operation_kind,status,transaction_hash,receipt_status
       ) VALUES($1,$2,$3,'cost-test',$4,$5,'selected-execution','settling',$6,'unknown')`,
      [operationId, envId, generationId, operationId.replaceAll('-', '').repeat(2), 'e'.repeat(64), transactionHash],
    );
  };

  const insertUnknown = async (index: number, asset: 'ETH' | 'WETH', amount: string, policy = POLICY): Promise<void> => {
    await client.query(
      `INSERT INTO bef_transaction_cost(
         operation_id,env_id,generation_id,transaction_hash,payer_address,payer_role,receipt_status,
         fee_rate_numerator,fee_rate_denominator,fee_policy_snapshot,manifest_sha256,
         selected_principal_asset,selected_principal_units,observed_principal_units,base_l1_fee_status
       ) VALUES($1,$2,$3,$4,$5,'participant','unknown',$6,$7,$8::jsonb,$9,$10,$11,NULL,'unmodelled')`,
      [operations[index], envId, generationId, hashes[index], PAYER, RATE_NUM, RATE_DEN,
        JSON.stringify(policy), MANIFEST, asset, amount],
    );
  };

  const makeParticipantEvidence = (index: number, status: 'success' | 'reverted') => {
    const selectedAsset = index === 0 ? 'ETH' : 'WETH';
    const selectedUnits = index === 0 ? '10' : index === 1 ? '20' : '5';
    const transactionValue = selectedAsset === 'ETH' ? selectedUnits : '0';
    return {
      transaction: {
        hash: hashes[index], from: PAYER, blockHash: BLOCK_HASH, blockNumber: '100',
        valueWei: transactionValue, maxFeePerGasWei: '3', maxPriorityFeePerGasWei: '1',
      },
      receipt: {
        transactionHash: hashes[index], from: PAYER, status, blockHash: BLOCK_HASH,
        blockNumber: '100', gasUsed: '2', effectiveGasPriceWei: '3', blockBaseFeePerGasWei: '2',
      },
      payerBlock: {
        hash: BLOCK_HASH, number: '100', parentHash: PARENT_HASH,
        transactions: [{ hash: hashes[index], from: PAYER }],
      },
      payerNativeBalanceBefore: { blockHash: null, blockNumber: null, balanceWei: null },
      payerNativeBalanceAfter: { blockHash: null, blockNumber: null, balanceWei: null },
    };
  };

  const finalizeWithEvidence = async (index: number, status: 'success' | 'reverted', observed: string, evidence: unknown): Promise<void> => {
    await client.query(
      `UPDATE bef_transaction_cost
          SET receipt_status=$3,transaction_from=$4,receipt_from=$4,receipt_block_number=100,
              receipt_block_hash=$5,receipt_block_parent_hash=$6,block_transaction_senders=$7::jsonb,
              gas_used=2,effective_gas_price_wei=3,gas_cost_wei=6,
              modeled_gas_fee_usdc_units=4,observed_principal_units=$8,
              receipt_evidence_json=$9::jsonb,receipt_evidence_sha256=$10
        WHERE operation_id=$1 AND transaction_hash=$2`,
      [operations[index], hashes[index], status, PAYER, BLOCK_HASH, PARENT_HASH,
        JSON.stringify([{ hash: hashes[index], from: PAYER }]), observed, JSON.stringify(evidence), FINAL_EVIDENCE_SHA256],
    );
  };

  const finalizeParticipant = async (index: number, status: 'success' | 'reverted', observed: string): Promise<void> =>
    finalizeWithEvidence(index, status, observed, makeParticipantEvidence(index, status));

  const costIdentity = (index: number): CostIdentity => ({
    operationId: operations[index]!, envId, generationId, transactionHash: hashes[index]!, payerAddress: PAYER,
    payerRole: 'participant', manifestSha256: MANIFEST, feePolicy: POLICY,
    selectedPrincipalAsset: 'WETH', selectedPrincipalUnits: '20',
  });

  const decliningBaseFeeObservation = (index: number, effectiveGasPrice: string): FinalCostObservation => ({
    transaction: {
      hash: hashes[index]!, from: PAYER, blockHash: BLOCK_HASH, blockNumber: '101', value: '0',
      maxFeePerGas: '3', maxPriorityFeePerGas: '1',
    },
    receipt: {
      transactionHash: hashes[index]!, from: PAYER, status: 'reverted', blockHash: BLOCK_HASH,
      blockNumber: '101', gasUsed: '2', effectiveGasPrice,
    },
    receiptBlockBaseFeePerGas: '1',
    payerBlock: {
      hash: BLOCK_HASH, number: '101', parentHash: PARENT_HASH, baseFeePerGas: '1',
      transactions: [{ hash: hashes[index]!, from: PAYER }],
    },
  });

  try {
    await ensureSchema(pool);
    await verifySchema(pool);
    await client.query('BEGIN');
    const databaseName = await client.query<{ current_database: string }>('SELECT current_database()');
    assert.equal(databaseName.rows[0]?.current_database, requestedDatabaseName);
    await client.query(
      `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
       VALUES($1,8453,'private-anvil-fork',$2)`, [envId, MANIFEST],
    );
    await client.query(
      `INSERT INTO bef_generation(
         generation_id,env_id,participant_id,run_token_sha256,payer_address,resource_variant,
         manifest_sha256,status,expires_at
       ) VALUES($1,$2,'cost-test',$3,$4,'canonical',$5,'active',clock_timestamp()+interval '1 hour')`,
      [generationId, envId, 'f'.repeat(64), PAYER, MANIFEST],
    );
    for (let index = 0; index < operations.length; index += 1) {
      await createOperation(operations[index]!, hashes[index]!);
    }

    const malformedPolicies: Record<string, unknown>[] = [];
    for (const key of Object.keys(POLICY)) {
      const missing = { ...POLICY } as Record<string, unknown>;
      delete missing[key];
      malformedPolicies.push(missing);
    }
    malformedPolicies.push(
      { ...POLICY, extra: 'must-not-be-accepted' },
      { ...POLICY, baseFeeWei: 2 },
      { ...POLICY, priorityFeeWei: null },
      { ...POLICY, ethUsdcRateNumerator: 2 },
      { ...POLICY, ethUsdcRateDenominator: null },
      { ...POLICY, rounding: 1 },
      { ...POLICY, baseL1Fee: null },
      { ...POLICY, principalSeparateFromExpense: 'true' },
      [] as unknown as Record<string, unknown>,
    );
    for (const malformedPolicy of malformedPolicies) {
      await client.query('SAVEPOINT reject_malformed_fee_snapshot');
      await assert.rejects(() => client.query(
        `INSERT INTO bef_transaction_cost(
           operation_id,env_id,generation_id,transaction_hash,payer_address,payer_role,receipt_status,
           fee_rate_numerator,fee_rate_denominator,fee_policy_snapshot,manifest_sha256,
           selected_principal_asset,selected_principal_units
         ) VALUES($1,$2,$3,$4,$5,'participant','unknown',$6,$7,$8::jsonb,$9,'WETH',5)`,
        [operations[2], envId, generationId, hashes[2], PAYER, RATE_NUM, RATE_DEN,
          JSON.stringify(malformedPolicy), MANIFEST],
      ), isPolicyCheckViolation);
      await client.query('ROLLBACK TO SAVEPOINT reject_malformed_fee_snapshot');
      await client.query('RELEASE SAVEPOINT reject_malformed_fee_snapshot');
    }

    await insertUnknown(0, 'ETH', '10');
    const unknown = await client.query<{ receipt_status: string; gas_cost_wei: string | null; observed_principal_units: string | null }>(
      `SELECT receipt_status,gas_cost_wei::text,observed_principal_units::text
         FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2`,
      [operations[0], hashes[0]],
    );
    assert.deepEqual(unknown.rows[0], { receipt_status: 'unknown', gas_cost_wei: null, observed_principal_units: null });

    await client.query('SAVEPOINT reject_invalid_final_cost');
    await assert.rejects(() => client.query(
      `UPDATE bef_transaction_cost SET receipt_status='success',transaction_from=$3,receipt_from=$3,
          receipt_block_number=100,receipt_block_hash=$4,gas_used=0,effective_gas_price_wei=3,
          gas_cost_wei=0,modeled_gas_fee_usdc_units=0,observed_principal_units=10,
          receipt_evidence_json='{}'::jsonb,receipt_evidence_sha256=$5
        WHERE operation_id=$1 AND transaction_hash=$2`,
      [operations[0], hashes[0], PAYER, BLOCK_HASH, FINAL_EVIDENCE_SHA256],
    ), /bef_transaction_cost_receipt_shape_ck/);
    await client.query('ROLLBACK TO SAVEPOINT reject_invalid_final_cost');
    await client.query('RELEASE SAVEPOINT reject_invalid_final_cost');
    const afterRejectedFinalize = await client.query<{ receipt_status: string }>(
      'SELECT receipt_status FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2',
      [operations[0], hashes[0]],
    );
    assert.equal(afterRejectedFinalize.rows[0]?.receipt_status, 'unknown');

    await finalizeParticipant(0, 'success', '10');
    const finalizedSuccess = await client.query<{
      receipt_status: string; gas_used: string; effective_gas_price_wei: string;
      gas_cost_wei: string; modeled_gas_fee_usdc_units: string; observed_principal_units: string;
    }>(
      `SELECT receipt_status,gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,
              modeled_gas_fee_usdc_units::text,observed_principal_units::text
         FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2`,
      [operations[0], hashes[0]],
    );
    assert.deepEqual(finalizedSuccess.rows[0], {
      receipt_status: 'success', gas_used: '2', effective_gas_price_wei: '3',
      gas_cost_wei: '6', modeled_gas_fee_usdc_units: '4', observed_principal_units: '10',
    });

    await client.query('SAVEPOINT reject_final_cost_mutation');
    await assert.rejects(() => client.query(
      `UPDATE bef_transaction_cost SET gas_cost_wei=7 WHERE operation_id=$1 AND transaction_hash=$2`,
      [operations[0], hashes[0]],
    ), /final transaction cost is immutable/);
    await client.query('ROLLBACK TO SAVEPOINT reject_final_cost_mutation');
    await client.query('RELEASE SAVEPOINT reject_final_cost_mutation');
    await client.query('SAVEPOINT reject_final_cost_delete');
    await assert.rejects(() => client.query(
      'DELETE FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2',
      [operations[0], hashes[0]],
    ), /cannot be deleted/);
    await client.query('ROLLBACK TO SAVEPOINT reject_final_cost_delete');
    await client.query('RELEASE SAVEPOINT reject_final_cost_delete');

    await insertUnknown(1, 'WETH', '20');
    await finalizeParticipant(1, 'reverted', '0');
    const finalizedRevert = await client.query<{ receipt_status: string; selected_principal_units: string; observed_principal_units: string }>(
      `SELECT receipt_status,selected_principal_units::text,observed_principal_units::text
         FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2`,
      [operations[1], hashes[1]],
    );
    assert.deepEqual(finalizedRevert.rows[0], {
      receipt_status: 'reverted', selected_principal_units: '20', observed_principal_units: '0',
    });

    await insertUnknown(2, 'WETH', '5');
    const validEvidence = makeParticipantEvidence(2, 'success');
    const cloneEvidence = (): Record<string, unknown> => JSON.parse(JSON.stringify(validEvidence)) as Record<string, unknown>;
    const rejectEvidence = async (evidence: unknown): Promise<void> => {
      await client.query('SAVEPOINT reject_malformed_receipt_evidence');
      await assert.rejects(
        () => finalizeWithEvidence(2, 'success', '5', evidence),
        /bef_transaction_cost_receipt_shape_ck/,
      );
      await client.query('ROLLBACK TO SAVEPOINT reject_malformed_receipt_evidence');
      await client.query('RELEASE SAVEPOINT reject_malformed_receipt_evidence');
    };
    const evidenceGroups: Record<string, string[]> = {
      transaction: ['hash', 'from', 'blockHash', 'blockNumber', 'valueWei', 'maxFeePerGasWei', 'maxPriorityFeePerGasWei'],
      receipt: ['transactionHash', 'from', 'status', 'blockHash', 'blockNumber', 'gasUsed', 'effectiveGasPriceWei', 'blockBaseFeePerGasWei'],
      payerBlock: ['hash', 'number', 'parentHash', 'transactions'],
      payerNativeBalanceBefore: ['blockHash', 'blockNumber', 'balanceWei'],
      payerNativeBalanceAfter: ['blockHash', 'blockNumber', 'balanceWei'],
    };
    const topLevelFields = ['transaction', 'receipt', 'payerBlock', 'payerNativeBalanceBefore', 'payerNativeBalanceAfter'];
    for (const field of topLevelFields) {
      const malformed = cloneEvidence();
      delete malformed[field];
      await rejectEvidence(malformed);
    }
    await rejectEvidence([]);
    for (const [group, fields] of Object.entries(evidenceGroups)) {
      for (const field of fields) {
        const malformed = cloneEvidence();
        delete (malformed[group] as Record<string, unknown>)[field];
        await rejectEvidence(malformed);
      }
      const wrongObjectType = cloneEvidence();
      wrongObjectType[group] = [];
      await rejectEvidence(wrongObjectType);
      const withExtraField = cloneEvidence();
      (withExtraField[group] as Record<string, unknown>).unexpected = 'must-not-be-accepted';
      await rejectEvidence(withExtraField);
    }
    const extraTopLevelField = cloneEvidence();
    extraTopLevelField.unexpected = 'must-not-be-accepted';
    await rejectEvidence(extraTopLevelField);
    const wrongTransactionType = cloneEvidence();
    ((wrongTransactionType.transaction as Record<string, unknown>).maxFeePerGasWei) = 3;
    await rejectEvidence(wrongTransactionType);
    const wrongReceiptType = cloneEvidence();
    ((wrongReceiptType.receipt as Record<string, unknown>).blockBaseFeePerGasWei) = null;
    await rejectEvidence(wrongReceiptType);
    const wrongBlockType = cloneEvidence();
    ((wrongBlockType.payerBlock as Record<string, unknown>).transactions) = {};
    await rejectEvidence(wrongBlockType);
    const wrongBalanceType = cloneEvidence();
    ((wrongBalanceType.payerNativeBalanceBefore as Record<string, unknown>).balanceWei) = '0';
    await rejectEvidence(wrongBalanceType);
    for (const [group, fields] of Object.entries({
      transaction: evidenceGroups.transaction!,
      receipt: evidenceGroups.receipt!,
      payerBlock: ['hash', 'number', 'parentHash'],
    })) {
      for (const field of fields) {
        const wrongFieldType = cloneEvidence();
        (wrongFieldType[group] as Record<string, unknown>)[field] = null;
        await rejectEvidence(wrongFieldType);
      }
    }
    const wrongMaximumFee = cloneEvidence();
    (wrongMaximumFee.transaction as Record<string, unknown>).maxFeePerGasWei = '4';
    await rejectEvidence(wrongMaximumFee);
    const wrongPriorityFee = cloneEvidence();
    (wrongPriorityFee.transaction as Record<string, unknown>).maxPriorityFeePerGasWei = '2';
    await rejectEvidence(wrongPriorityFee);
    const wrongReceiptBaseFee = cloneEvidence();
    (wrongReceiptBaseFee.receipt as Record<string, unknown>).blockBaseFeePerGasWei = '1';
    await rejectEvidence(wrongReceiptBaseFee);
    const stillUnknown = await client.query<{ receipt_status: string }>(
      'SELECT receipt_status FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2',
      [operations[2], hashes[2]],
    );
    assert.equal(stillUnknown.rows[0]?.receipt_status, 'unknown');

    const decliningFeeIdentity = costIdentity(3);
    await insertUnknownTransactionCost(client, decliningFeeIdentity);
    await finalizeTransactionCost(client, decliningFeeIdentity, decliningBaseFeeObservation(3, '2'));
    const finalizedDecliningFee = await client.query<{
      receipt_status: string; effective_gas_price_wei: string; gas_cost_wei: string;
      observed_principal_units: string; receipt_base_fee: string;
    }>(
      `SELECT receipt_status,effective_gas_price_wei::text,gas_cost_wei::text,observed_principal_units::text,
              receipt_evidence_json #>> '{receipt,blockBaseFeePerGasWei}' AS receipt_base_fee
         FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2`,
      [operations[3], hashes[3]],
    );
    assert.deepEqual(finalizedDecliningFee.rows[0], {
      receipt_status: 'reverted', effective_gas_price_wei: '2', gas_cost_wei: '4',
      observed_principal_units: '0', receipt_base_fee: '1',
    });

    const tamperedFeeIdentity = costIdentity(4);
    await insertUnknownTransactionCost(client, tamperedFeeIdentity);
    await assert.rejects(
      () => finalizeTransactionCost(client, tamperedFeeIdentity, decliningBaseFeeObservation(4, '3')),
      /transaction_cost_fee_policy_receipt_conflict/,
    );
    const tamperedFeeRemainsUnknown = await client.query<{
      receipt_status: string; gas_cost_wei: string | null; observed_principal_units: string | null;
    }>(
      `SELECT receipt_status,gas_cost_wei::text,observed_principal_units::text
         FROM bef_transaction_cost WHERE operation_id=$1 AND transaction_hash=$2`,
      [operations[4], hashes[4]],
    );
    assert.deepEqual(tamperedFeeRemainsUnknown.rows[0], {
      receipt_status: 'unknown', gas_cost_wei: null, observed_principal_units: null,
    });

    await client.query('SAVEPOINT reject_final_insert');
    await assert.rejects(() => client.query(
      `INSERT INTO bef_transaction_cost(
         operation_id,env_id,generation_id,transaction_hash,payer_address,payer_role,receipt_status,
         fee_rate_numerator,fee_rate_denominator,fee_policy_snapshot,manifest_sha256,
         selected_principal_asset,selected_principal_units
       ) VALUES($1,$2,$3,$4,$5,'participant','success',$6,$7,$8::jsonb,$9,'ETH',1)`,
      [operations[0], envId, generationId, `0x${'3'.repeat(64)}`, PAYER, RATE_NUM, RATE_DEN,
        JSON.stringify(POLICY), MANIFEST],
    ), /must begin with an unknown receipt marker/);
    await client.query('ROLLBACK TO SAVEPOINT reject_final_insert');
    await client.query('RELEASE SAVEPOINT reject_final_insert');
  } finally {
    await client.query('ROLLBACK').catch(() => undefined);
    client.release();
    await pool.end();
  }
});

BEGIN;

-- Candidate for review only. One row records gas paid by one actual sender for
-- one operation/hash. Service principal remains in bef_payment.amount_units.
CREATE TABLE IF NOT EXISTS bef_transaction_cost (
  operation_id uuid NOT NULL,
  env_id text NOT NULL,
  generation_id uuid NOT NULL,
  transaction_hash text NOT NULL CHECK (transaction_hash ~ '^0x[0-9a-fA-F]{64}$'),
  payer_address text NOT NULL CHECK (payer_address ~ '^0x[0-9a-fA-F]{40}$'),
  payer_role text NOT NULL CHECK (payer_role IN ('participant', 'facilitator')),
  receipt_status text NOT NULL CHECK (receipt_status IN ('unknown', 'success', 'reverted')),
  transaction_from text CHECK (transaction_from IS NULL OR transaction_from ~ '^0x[0-9a-fA-F]{40}$'),
  receipt_from text CHECK (receipt_from IS NULL OR receipt_from ~ '^0x[0-9a-fA-F]{40}$'),
  receipt_block_number numeric(78,0),
  receipt_block_hash text CHECK (receipt_block_hash IS NULL OR receipt_block_hash ~ '^0x[0-9a-fA-F]{64}$'),
  receipt_block_parent_hash text CHECK (receipt_block_parent_hash IS NULL OR receipt_block_parent_hash ~ '^0x[0-9a-fA-F]{64}$'),
  block_transaction_senders jsonb,
  gas_used numeric(78,0),
  effective_gas_price_wei numeric(78,0),
  gas_cost_wei numeric(78,0),
  modeled_gas_fee_usdc_units numeric(78,0),
  fee_rate_numerator numeric(78,0) NOT NULL CHECK (fee_rate_numerator > 0),
  fee_rate_denominator numeric(78,0) NOT NULL CHECK (fee_rate_denominator > 0),
  fee_policy_snapshot jsonb NOT NULL CHECK (jsonb_typeof(fee_policy_snapshot) = 'object'),
  manifest_sha256 char(64) NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  selected_principal_asset text CHECK (selected_principal_asset IS NULL OR selected_principal_asset IN ('ETH', 'WETH')),
  selected_principal_units numeric(78,0),
  observed_principal_units numeric(78,0),
  payer_native_balance_before_wei numeric(78,0),
  payer_native_balance_before_block_number numeric(78,0),
  payer_native_balance_before_block_hash text CHECK (payer_native_balance_before_block_hash IS NULL OR payer_native_balance_before_block_hash ~ '^0x[0-9a-fA-F]{64}$'),
  payer_native_balance_after_wei numeric(78,0),
  payer_native_balance_after_block_number numeric(78,0),
  payer_native_balance_after_block_hash text CHECK (payer_native_balance_after_block_hash IS NULL OR payer_native_balance_after_block_hash ~ '^0x[0-9a-fA-F]{64}$'),
  receipt_evidence_json jsonb,
  receipt_evidence_sha256 char(64) CHECK (receipt_evidence_sha256 IS NULL OR receipt_evidence_sha256 ~ '^[0-9a-f]{64}$'),
  base_l1_fee_status text NOT NULL DEFAULT 'unmodelled' CHECK (base_l1_fee_status = 'unmodelled'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (operation_id, transaction_hash),
  CONSTRAINT bef_transaction_cost_operation_scope_fk
    FOREIGN KEY (operation_id, env_id, generation_id)
    REFERENCES bef_operation(operation_id, env_id, generation_id),
  CONSTRAINT bef_transaction_cost_rate_snapshot_ck CHECK (
    (
      jsonb_typeof(fee_policy_snapshot) = 'object'
      AND CASE WHEN jsonb_typeof(fee_policy_snapshot) = 'object' THEN
        (fee_policy_snapshot - ARRAY[
          'baseFeeWei', 'priorityFeeWei', 'ethUsdcRateNumerator', 'ethUsdcRateDenominator',
          'rounding', 'baseL1Fee', 'principalSeparateFromExpense'
        ]) = '{}'::jsonb ELSE false END
      AND (fee_policy_snapshot ?& ARRAY[
        'baseFeeWei', 'priorityFeeWei', 'ethUsdcRateNumerator', 'ethUsdcRateDenominator',
        'rounding', 'baseL1Fee', 'principalSeparateFromExpense'
      ]) IS TRUE
      AND jsonb_typeof(fee_policy_snapshot->'baseFeeWei') = 'string'
      AND jsonb_typeof(fee_policy_snapshot->'priorityFeeWei') = 'string'
      AND jsonb_typeof(fee_policy_snapshot->'ethUsdcRateNumerator') = 'string'
      AND jsonb_typeof(fee_policy_snapshot->'ethUsdcRateDenominator') = 'string'
      AND jsonb_typeof(fee_policy_snapshot->'rounding') = 'string'
      AND jsonb_typeof(fee_policy_snapshot->'baseL1Fee') = 'string'
      AND jsonb_typeof(fee_policy_snapshot->'principalSeparateFromExpense') = 'boolean'
      AND (fee_policy_snapshot->>'baseFeeWei' ~ '^(0|[1-9][0-9]*)$') IS TRUE
      AND (fee_policy_snapshot->>'priorityFeeWei' ~ '^(0|[1-9][0-9]*)$') IS TRUE
      AND fee_policy_snapshot->>'ethUsdcRateNumerator' = fee_rate_numerator::text
      AND fee_policy_snapshot->>'ethUsdcRateDenominator' = fee_rate_denominator::text
      AND fee_policy_snapshot->>'baseL1Fee' = 'unmodelled'
      AND fee_policy_snapshot->>'rounding' = 'floor-to-6-decimal-usdc-units'
      AND fee_policy_snapshot->>'principalSeparateFromExpense' = 'true'
    ) IS TRUE
  ),
  CONSTRAINT bef_transaction_cost_receipt_shape_ck CHECK ((
    (receipt_status = 'unknown'
      AND transaction_from IS NULL AND receipt_from IS NULL
      AND receipt_block_number IS NULL AND receipt_block_hash IS NULL
      AND receipt_block_parent_hash IS NULL AND block_transaction_senders IS NULL
      AND gas_used IS NULL AND effective_gas_price_wei IS NULL
      AND gas_cost_wei IS NULL AND modeled_gas_fee_usdc_units IS NULL
      AND payer_native_balance_before_wei IS NULL AND payer_native_balance_before_block_number IS NULL
      AND payer_native_balance_before_block_hash IS NULL AND payer_native_balance_after_wei IS NULL
      AND payer_native_balance_after_block_number IS NULL AND payer_native_balance_after_block_hash IS NULL
      AND receipt_evidence_json IS NULL AND receipt_evidence_sha256 IS NULL)
    OR
    (receipt_status IN ('success', 'reverted')
      AND transaction_from IS NOT NULL AND lower(transaction_from) = lower(payer_address)
      AND receipt_from IS NOT NULL AND lower(receipt_from) = lower(payer_address)
      AND receipt_block_number IS NOT NULL AND receipt_block_number >= 0
      AND receipt_block_hash IS NOT NULL
      AND gas_used IS NOT NULL AND gas_used > 0
      AND effective_gas_price_wei IS NOT NULL AND effective_gas_price_wei > 0
      AND gas_cost_wei IS NOT NULL AND gas_cost_wei = gas_used * effective_gas_price_wei
      AND modeled_gas_fee_usdc_units IS NOT NULL
      AND modeled_gas_fee_usdc_units = floor(gas_cost_wei * fee_rate_numerator / fee_rate_denominator)
      AND receipt_evidence_json IS NOT NULL AND jsonb_typeof(receipt_evidence_json) = 'object'
      AND CASE WHEN jsonb_typeof(receipt_evidence_json) = 'object' THEN
        (receipt_evidence_json - ARRAY[
          'transaction', 'receipt', 'payerBlock', 'payerNativeBalanceBefore', 'payerNativeBalanceAfter'
        ]) = '{}'::jsonb ELSE false END
      AND (receipt_evidence_json ?& ARRAY[
        'transaction', 'receipt', 'payerBlock', 'payerNativeBalanceBefore', 'payerNativeBalanceAfter'
      ]) IS TRUE
      AND jsonb_typeof(receipt_evidence_json->'transaction') = 'object'
      AND CASE WHEN jsonb_typeof(receipt_evidence_json->'transaction') = 'object' THEN
        ((receipt_evidence_json->'transaction') - ARRAY[
          'hash', 'from', 'blockHash', 'blockNumber', 'valueWei', 'maxFeePerGasWei', 'maxPriorityFeePerGasWei'
        ]) = '{}'::jsonb ELSE false END
      AND ((receipt_evidence_json->'transaction') ?& ARRAY[
        'hash', 'from', 'blockHash', 'blockNumber', 'valueWei', 'maxFeePerGasWei', 'maxPriorityFeePerGasWei'
      ]) IS TRUE
      AND jsonb_typeof(receipt_evidence_json->'receipt') = 'object'
      AND CASE WHEN jsonb_typeof(receipt_evidence_json->'receipt') = 'object' THEN
        ((receipt_evidence_json->'receipt') - ARRAY[
          'transactionHash', 'from', 'status', 'blockHash', 'blockNumber', 'gasUsed',
          'effectiveGasPriceWei', 'blockBaseFeePerGasWei'
        ]) = '{}'::jsonb ELSE false END
      AND ((receipt_evidence_json->'receipt') ?& ARRAY[
        'transactionHash', 'from', 'status', 'blockHash', 'blockNumber', 'gasUsed',
        'effectiveGasPriceWei', 'blockBaseFeePerGasWei'
      ]) IS TRUE
      AND jsonb_typeof(receipt_evidence_json->'payerBlock') = 'object'
      AND CASE WHEN jsonb_typeof(receipt_evidence_json->'payerBlock') = 'object' THEN
        ((receipt_evidence_json->'payerBlock') - ARRAY['hash', 'number', 'parentHash', 'transactions']) = '{}'::jsonb ELSE false END
      AND ((receipt_evidence_json->'payerBlock') ?& ARRAY['hash', 'number', 'parentHash', 'transactions']) IS TRUE
      AND jsonb_typeof(receipt_evidence_json->'payerNativeBalanceBefore') = 'object'
      AND CASE WHEN jsonb_typeof(receipt_evidence_json->'payerNativeBalanceBefore') = 'object' THEN
        ((receipt_evidence_json->'payerNativeBalanceBefore') - ARRAY['blockHash', 'blockNumber', 'balanceWei']) = '{}'::jsonb ELSE false END
      AND ((receipt_evidence_json->'payerNativeBalanceBefore') ?& ARRAY['blockHash', 'blockNumber', 'balanceWei']) IS TRUE
      AND jsonb_typeof(receipt_evidence_json->'payerNativeBalanceAfter') = 'object'
      AND CASE WHEN jsonb_typeof(receipt_evidence_json->'payerNativeBalanceAfter') = 'object' THEN
        ((receipt_evidence_json->'payerNativeBalanceAfter') - ARRAY['blockHash', 'blockNumber', 'balanceWei']) = '{}'::jsonb ELSE false END
      AND ((receipt_evidence_json->'payerNativeBalanceAfter') ?& ARRAY['blockHash', 'blockNumber', 'balanceWei']) IS TRUE
      AND jsonb_typeof(receipt_evidence_json #> '{transaction,hash}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{transaction,from}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{transaction,blockHash}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{transaction,blockNumber}') = 'string'
      AND receipt_evidence_sha256 IS NOT NULL
      AND jsonb_typeof(receipt_evidence_json #> '{transaction,maxFeePerGasWei}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{transaction,maxPriorityFeePerGasWei}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{transaction,valueWei}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{receipt,blockBaseFeePerGasWei}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{receipt,transactionHash}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{receipt,from}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{receipt,status}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{receipt,blockHash}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{receipt,blockNumber}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{receipt,gasUsed}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{receipt,effectiveGasPriceWei}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{payerBlock,hash}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{payerBlock,number}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{payerBlock,parentHash}') = 'string'
      AND jsonb_typeof(receipt_evidence_json #> '{payerBlock,transactions}') = 'array'
      AND ((payer_role = 'facilitator'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceBefore,blockHash}') = 'string'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceBefore,blockNumber}') = 'string'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceBefore,balanceWei}') = 'string'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceAfter,blockHash}') = 'string'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceAfter,blockNumber}') = 'string'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceAfter,balanceWei}') = 'string')
        OR (payer_role = 'participant'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceBefore,blockHash}') = 'null'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceBefore,blockNumber}') = 'null'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceBefore,balanceWei}') = 'null'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceAfter,blockHash}') = 'null'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceAfter,blockNumber}') = 'null'
        AND jsonb_typeof(receipt_evidence_json #> '{payerNativeBalanceAfter,balanceWei}') = 'null')) IS TRUE
      AND (receipt_evidence_json #>> '{transaction,hash}' = lower(transaction_hash)) IS TRUE
      AND (receipt_evidence_json #>> '{transaction,from}' = lower(payer_address)) IS TRUE
      AND (receipt_evidence_json #>> '{transaction,blockHash}' = lower(receipt_block_hash)) IS TRUE
      AND (receipt_evidence_json #>> '{transaction,blockNumber}' = receipt_block_number::text) IS TRUE
      AND (receipt_evidence_json #>> '{receipt,transactionHash}' = lower(transaction_hash)) IS TRUE
      AND (receipt_evidence_json #>> '{receipt,from}' = lower(payer_address)) IS TRUE
      AND (receipt_evidence_json #>> '{receipt,status}' = receipt_status) IS TRUE
      AND (receipt_evidence_json #>> '{receipt,blockHash}' = lower(receipt_block_hash)) IS TRUE
      AND (receipt_evidence_json #>> '{receipt,blockNumber}' = receipt_block_number::text) IS TRUE
      AND (receipt_evidence_json #>> '{receipt,gasUsed}' = gas_used::text) IS TRUE
      AND (receipt_evidence_json #>> '{receipt,effectiveGasPriceWei}' = effective_gas_price_wei::text) IS TRUE
      AND (receipt_evidence_json #>> '{payerBlock,hash}' = lower(receipt_block_hash)) IS TRUE
      AND (receipt_evidence_json #>> '{payerBlock,number}' = receipt_block_number::text) IS TRUE
      AND (receipt_evidence_json #>> '{payerBlock,parentHash}' = lower(receipt_block_parent_hash)) IS TRUE
      AND ((receipt_evidence_json #> '{payerBlock,transactions}' = block_transaction_senders) IS TRUE)
      AND ((payer_role = 'facilitator'
        AND (receipt_evidence_json #>> '{payerNativeBalanceBefore,blockHash}' = lower(payer_native_balance_before_block_hash)) IS TRUE
        AND (receipt_evidence_json #>> '{payerNativeBalanceBefore,blockNumber}' = payer_native_balance_before_block_number::text) IS TRUE
        AND (receipt_evidence_json #>> '{payerNativeBalanceBefore,balanceWei}' = payer_native_balance_before_wei::text) IS TRUE
        AND (receipt_evidence_json #>> '{payerNativeBalanceAfter,blockHash}' = lower(payer_native_balance_after_block_hash)) IS TRUE
        AND (receipt_evidence_json #>> '{payerNativeBalanceAfter,blockNumber}' = payer_native_balance_after_block_number::text) IS TRUE
        AND (receipt_evidence_json #>> '{payerNativeBalanceAfter,balanceWei}' = payer_native_balance_after_wei::text) IS TRUE)
        OR (payer_role = 'participant'
        AND receipt_evidence_json #> '{payerNativeBalanceBefore,blockHash}' = 'null'::jsonb
        AND receipt_evidence_json #> '{payerNativeBalanceBefore,blockNumber}' = 'null'::jsonb
        AND receipt_evidence_json #> '{payerNativeBalanceBefore,balanceWei}' = 'null'::jsonb
        AND receipt_evidence_json #> '{payerNativeBalanceAfter,blockHash}' = 'null'::jsonb
        AND receipt_evidence_json #> '{payerNativeBalanceAfter,blockNumber}' = 'null'::jsonb
        AND receipt_evidence_json #> '{payerNativeBalanceAfter,balanceWei}' = 'null'::jsonb)) IS TRUE
      AND (receipt_evidence_json #>> '{transaction,maxFeePerGasWei}' ~ '^(0|[1-9][0-9]*)$') IS TRUE
      AND (receipt_evidence_json #>> '{transaction,maxPriorityFeePerGasWei}' ~ '^(0|[1-9][0-9]*)$') IS TRUE
      AND (receipt_evidence_json #>> '{transaction,valueWei}' ~ '^(0|[1-9][0-9]*)$') IS TRUE
      AND (receipt_evidence_json #>> '{receipt,blockBaseFeePerGasWei}' ~ '^(0|[1-9][0-9]*)$') IS TRUE
      AND (receipt_evidence_json #>> '{transaction,maxPriorityFeePerGasWei}')::numeric = (fee_policy_snapshot->>'priorityFeeWei')::numeric
      AND (receipt_evidence_json #>> '{receipt,blockBaseFeePerGasWei}')::numeric = (fee_policy_snapshot->>'baseFeeWei')::numeric
      AND (receipt_evidence_json #>> '{transaction,maxFeePerGasWei}')::numeric =
          (fee_policy_snapshot->>'baseFeeWei')::numeric + (fee_policy_snapshot->>'priorityFeeWei')::numeric
      AND (receipt_evidence_json #>> '{transaction,maxPriorityFeePerGasWei}')::numeric <=
          (receipt_evidence_json #>> '{transaction,maxFeePerGasWei}')::numeric
      AND effective_gas_price_wei = LEAST(
          (receipt_evidence_json #>> '{transaction,maxFeePerGasWei}')::numeric,
          (receipt_evidence_json #>> '{receipt,blockBaseFeePerGasWei}')::numeric +
            (receipt_evidence_json #>> '{transaction,maxPriorityFeePerGasWei}')::numeric)
      AND (payer_role = 'facilitator' AND receipt_evidence_json #>> '{transaction,valueWei}' = '0'
        OR payer_role = 'participant' AND (
          (selected_principal_asset = 'ETH' AND receipt_evidence_json #>> '{transaction,valueWei}' = selected_principal_units::text)
          OR (selected_principal_asset IS DISTINCT FROM 'ETH' AND receipt_evidence_json #>> '{transaction,valueWei}' = '0')))
      AND receipt_block_number >= 1 AND receipt_block_parent_hash IS NOT NULL
      AND block_transaction_senders IS NOT NULL AND jsonb_typeof(block_transaction_senders) = 'array'
      AND block_transaction_senders = jsonb_build_array(jsonb_build_object('hash',lower(transaction_hash),'from',lower(payer_address)))
      AND ((payer_role = 'facilitator'
        AND payer_native_balance_before_wei IS NOT NULL AND payer_native_balance_before_wei >= 0
        AND payer_native_balance_before_block_number = receipt_block_number - 1
        AND payer_native_balance_before_block_hash = receipt_block_parent_hash
        AND payer_native_balance_after_wei IS NOT NULL AND payer_native_balance_after_wei >= 0
        AND payer_native_balance_after_block_number = receipt_block_number
        AND payer_native_balance_after_block_hash = receipt_block_hash
        AND payer_native_balance_before_wei - payer_native_balance_after_wei = gas_cost_wei)
        OR (payer_role = 'participant'
          AND payer_native_balance_before_wei IS NULL AND payer_native_balance_before_block_number IS NULL
                AND payer_native_balance_before_block_hash IS NULL AND payer_native_balance_after_wei IS NULL
                AND payer_native_balance_after_block_number IS NULL AND payer_native_balance_after_block_hash IS NULL)))) IS TRUE
  ),
  CONSTRAINT bef_transaction_cost_principal_shape_ck CHECK (
    (payer_role = 'facilitator'
      AND selected_principal_asset IS NULL
      AND selected_principal_units IS NULL
      AND observed_principal_units IS NULL)
    OR
    (payer_role = 'participant'
      AND selected_principal_units IS NOT NULL AND selected_principal_units >= 0
      AND ((receipt_status = 'unknown' AND observed_principal_units IS NULL)
        OR (receipt_status = 'success' AND observed_principal_units = selected_principal_units)
        OR (receipt_status = 'reverted' AND observed_principal_units = 0)))
  )
);

CREATE INDEX IF NOT EXISTS bef_transaction_cost_payer_idx
  ON bef_transaction_cost(env_id, generation_id, payer_role, created_at);

CREATE OR REPLACE FUNCTION bef_require_unknown_transaction_cost()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.receipt_status <> 'unknown' THEN
    RAISE EXCEPTION 'transaction cost must begin with an unknown receipt marker';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS bef_transaction_cost_unknown_on_insert ON bef_transaction_cost;
CREATE TRIGGER bef_transaction_cost_unknown_on_insert
  BEFORE INSERT ON bef_transaction_cost
  FOR EACH ROW EXECUTE FUNCTION bef_require_unknown_transaction_cost();

CREATE OR REPLACE FUNCTION bef_protect_final_transaction_cost()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.receipt_status IN ('success', 'reverted') THEN
    IF NEW IS DISTINCT FROM OLD THEN
      RAISE EXCEPTION 'final transaction cost is immutable';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.receipt_status = 'unknown'
     AND NEW.receipt_status IN ('success', 'reverted')
     AND NEW.operation_id = OLD.operation_id
     AND NEW.env_id = OLD.env_id
     AND NEW.generation_id = OLD.generation_id
     AND NEW.transaction_hash = OLD.transaction_hash
     AND lower(NEW.payer_address) = lower(OLD.payer_address)
     AND NEW.payer_role = OLD.payer_role
     AND NEW.fee_rate_numerator = OLD.fee_rate_numerator
     AND NEW.fee_rate_denominator = OLD.fee_rate_denominator
     AND NEW.fee_policy_snapshot = OLD.fee_policy_snapshot
     AND NEW.manifest_sha256 = OLD.manifest_sha256
     AND NEW.selected_principal_asset IS NOT DISTINCT FROM OLD.selected_principal_asset
     AND NEW.selected_principal_units IS NOT DISTINCT FROM OLD.selected_principal_units
     AND NEW.base_l1_fee_status = OLD.base_l1_fee_status
     AND NEW.created_at = OLD.created_at THEN
    RETURN NEW;
  END IF;

  IF NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'transaction cost can only move from unknown to receipt-backed final';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS bef_transaction_cost_final_immutable ON bef_transaction_cost;
CREATE TRIGGER bef_transaction_cost_final_immutable
  BEFORE UPDATE ON bef_transaction_cost
  FOR EACH ROW EXECUTE FUNCTION bef_protect_final_transaction_cost();

CREATE OR REPLACE FUNCTION bef_reject_transaction_cost_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'transaction cost evidence cannot be deleted';
END;
$$;

DROP TRIGGER IF EXISTS bef_transaction_cost_no_delete ON bef_transaction_cost;
CREATE TRIGGER bef_transaction_cost_no_delete
  BEFORE DELETE ON bef_transaction_cost
  FOR EACH ROW EXECUTE FUNCTION bef_reject_transaction_cost_delete();

COMMIT;

BEGIN;

ALTER TABLE bef_transaction_cost DROP CONSTRAINT bef_transaction_cost_receipt_shape_ck;

ALTER TABLE bef_transaction_cost ADD   CONSTRAINT bef_transaction_cost_receipt_shape_ck CHECK ((
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
      AND (receipt_evidence_json #>> '{receipt,blockBaseFeePerGasWei}')::numeric <= (fee_policy_snapshot->>'baseFeeWei')::numeric
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
  );

COMMIT;

BEGIN;

-- Keep the primitive scoped to the pinned task token and isolated participant
-- wallet. The executor still controls the target address and stores the raw
-- receipt; no caller-supplied result or token contract is accepted.
ALTER TABLE bef_selected_execution
  DROP CONSTRAINT IF EXISTS bef_selected_execution_action_kind_check;
ALTER TABLE bef_selected_execution
  ADD CONSTRAINT bef_selected_execution_action_kind_check
  CHECK (action_kind IN ('approve', 'transfer', 'wrap', 'unwrap', 'swap'));

ALTER TABLE bef_transaction_cost
  DROP CONSTRAINT IF EXISTS bef_transaction_cost_selected_principal_asset_check;
ALTER TABLE bef_transaction_cost
  ADD CONSTRAINT bef_transaction_cost_selected_principal_asset_check
  CHECK (selected_principal_asset IS NULL OR selected_principal_asset IN ('ETH', 'WETH', 'USDC'));

COMMIT;

BEGIN;

ALTER TABLE bef_selected_execution_event
  DROP CONSTRAINT IF EXISTS bef_selected_execution_event_event_kind_check;

ALTER TABLE bef_selected_execution_event
  ADD CONSTRAINT bef_selected_execution_event_event_kind_check CHECK (event_kind IN (
    'selected_action_bound', 'prestate_observed', 'original_tx_hash_bound',
    'settlement_unknown', 'observer_reconciliation', 'receipt_finalized',
    'rejected_before_broadcast'
  ));

COMMIT;

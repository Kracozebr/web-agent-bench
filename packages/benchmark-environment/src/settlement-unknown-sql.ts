export const RECORD_UNKNOWN_SETTLEMENT_OPERATION_SQL = `UPDATE bef_operation SET status=$4,receipt_status='unknown',transaction_hash=COALESCE(transaction_hash,$3::text),completed_at=NULL
  WHERE operation_id=$1 AND env_id=$2 AND status='settling' AND receipt_status <> 'success'
    AND (transaction_hash IS NULL OR $3::text IS NULL OR transaction_hash=$3::text)`;

export const RECORD_UNKNOWN_SETTLEMENT_PAYMENT_SQL = `UPDATE bef_payment SET transaction_hash=COALESCE(transaction_hash,$2::text),receipt_status='unknown',observed_at=clock_timestamp()
  WHERE operation_id=$1 AND (transaction_hash IS NULL OR $2::text IS NULL OR transaction_hash=$2::text) AND receipt_status <> 'success'`;

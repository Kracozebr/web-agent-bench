BEGIN;
-- AICODE-NOTE: Old rows retain NULL and replay their original signer-as-payee
-- binding. A new public payee never requires retaining facilitator wallet keys.
ALTER TABLE bef_payment ADD COLUMN IF NOT EXISTS payment_recipient text
  CHECK (payment_recipient IS NULL OR (payment_recipient ~ '^0x[0-9a-f]{40}$' AND payment_recipient <> '0x0000000000000000000000000000000000000000'));
COMMIT;

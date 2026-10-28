BEGIN;

ALTER TABLE bef_operation
  ADD COLUMN payment_response_mode text NOT NULL DEFAULT 'combined';

ALTER TABLE bef_operation
  ADD CONSTRAINT bef_operation_payment_response_mode_ck
    CHECK (payment_response_mode IN ('combined', 'deferred_delivery'));

CREATE FUNCTION bef_prevent_payment_response_mode_change() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.payment_response_mode IS DISTINCT FROM OLD.payment_response_mode THEN
    RAISE EXCEPTION 'payment_response_mode is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER bef_operation_payment_response_mode_immutable
  BEFORE UPDATE OF payment_response_mode ON bef_operation
  FOR EACH ROW EXECUTE FUNCTION bef_prevent_payment_response_mode_change();

REVOKE ALL ON FUNCTION bef_prevent_payment_response_mode_change() FROM PUBLIC;

COMMIT;

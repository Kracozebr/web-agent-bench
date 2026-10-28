BEGIN;

-- A purchase fixes the pinned resource and offer before payment verification.
-- The nullable resource pair is retained only for rows selected by older BEF
-- versions; new choices are enforced by the immutable-choice trigger below.
ALTER TABLE bef_operation
  ADD COLUMN IF NOT EXISTS selected_resource_id text,
  ADD COLUMN IF NOT EXISTS selected_resource_sha256 char(64);

ALTER TABLE bef_operation
  DROP CONSTRAINT IF EXISTS bef_operation_selected_offer_pair_ck;
ALTER TABLE bef_operation
  ADD CONSTRAINT bef_operation_selected_offer_pair_ck CHECK (
    (
      (selected_offer_id IS NULL AND selected_amount_units IS NULL AND offer_selected_at IS NULL
        AND selected_resource_id IS NULL AND selected_resource_sha256 IS NULL)
      OR
      (selected_offer_id ~ '^[a-z][a-z0-9-]{2,63}$'
        AND selected_amount_units BETWEEN 1 AND 999999999999
        AND offer_selected_at IS NOT NULL
        AND ((selected_resource_id IS NULL AND selected_resource_sha256 IS NULL)
          OR (selected_resource_id ~ '^[a-z][a-z0-9-]{2,63}$'
            AND selected_resource_sha256 ~ '^[0-9a-f]{64}$')))
    ) IS TRUE
  );

CREATE OR REPLACE FUNCTION bef_preserve_selected_offer_choice() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF ROW(NEW.selected_offer_id, NEW.selected_amount_units, NEW.offer_selected_at,
         NEW.selected_resource_id, NEW.selected_resource_sha256)
       IS DISTINCT FROM ROW(OLD.selected_offer_id, OLD.selected_amount_units, OLD.offer_selected_at,
                            OLD.selected_resource_id, OLD.selected_resource_sha256) THEN
    IF OLD.selected_offer_id IS NOT NULL OR OLD.selected_amount_units IS NOT NULL OR OLD.offer_selected_at IS NOT NULL
       OR OLD.selected_resource_id IS NOT NULL OR OLD.selected_resource_sha256 IS NOT NULL
       OR OLD.offer_selection_eligible IS NOT TRUE OR NEW.offer_selection_eligible IS NOT FALSE
       OR OLD.status IS DISTINCT FROM 'awaiting_payment' OR NEW.status IS DISTINCT FROM 'awaiting_payment'
       OR NEW.selected_offer_id IS NULL OR NEW.selected_amount_units IS NULL OR NEW.offer_selected_at IS NULL
       OR NEW.selected_resource_id IS NULL OR NEW.selected_resource_sha256 IS NULL
       OR NEW.selected_resource_sha256 !~ '^[0-9a-f]{64}$'
       OR NEW.verification_started_at IS NOT NULL THEN
      RAISE EXCEPTION 'selected offer choice is immutable or not eligible';
    END IF;
  END IF;

  IF NEW.offer_selection_eligible IS DISTINCT FROM OLD.offer_selection_eligible THEN
    IF OLD.offer_selection_eligible IS NOT TRUE OR NEW.offer_selection_eligible IS NOT FALSE
       OR NEW.selected_offer_id IS NULL OR NEW.selected_amount_units IS NULL OR NEW.offer_selected_at IS NULL
       OR NEW.selected_resource_id IS NULL OR NEW.selected_resource_sha256 IS NULL THEN
      RAISE EXCEPTION 'offer selection eligibility is immutable';
    END IF;
  END IF;

  IF NEW.verification_started_at IS DISTINCT FROM OLD.verification_started_at THEN
    IF OLD.verification_started_at IS NOT NULL OR NEW.verification_started_at IS NULL
       OR NEW.selected_offer_id IS NULL OR NEW.selected_amount_units IS NULL OR NEW.offer_selected_at IS NULL
       OR NEW.verification_started_at < NEW.offer_selected_at THEN
      RAISE EXCEPTION 'verification must follow an immutable selected offer';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS bef_operation_selected_offer_immutable ON bef_operation;
CREATE TRIGGER bef_operation_selected_offer_immutable
  BEFORE UPDATE OF selected_offer_id, selected_amount_units, offer_selected_at,
                   selected_resource_id, selected_resource_sha256,
                   offer_selection_eligible, verification_started_at
  ON bef_operation FOR EACH ROW EXECUTE FUNCTION bef_preserve_selected_offer_choice();

COMMIT;

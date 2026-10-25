BEGIN;

-- SC002: only newly created purchase operations can establish an offer choice.
-- Old rows remain explicitly unknown and terminal replays cannot backfill them.
ALTER TABLE bef_operation
  ADD COLUMN IF NOT EXISTS selected_offer_id text,
  ADD COLUMN IF NOT EXISTS selected_amount_units numeric(78,0),
  ADD COLUMN IF NOT EXISTS offer_selected_at timestamptz,
  ADD COLUMN IF NOT EXISTS verification_started_at timestamptz,
  ADD COLUMN IF NOT EXISTS offer_selection_eligible boolean NOT NULL DEFAULT false;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'bef_operation_selected_offer_pair_ck' AND conrelid = 'bef_operation'::regclass) THEN
    ALTER TABLE bef_operation ADD CONSTRAINT bef_operation_selected_offer_pair_ck CHECK (
      (
        (selected_offer_id IS NULL AND selected_amount_units IS NULL AND offer_selected_at IS NULL)
        OR (selected_offer_id = 'canonical' AND selected_amount_units = 100000 AND offer_selected_at IS NOT NULL)
        OR (selected_offer_id = 'task-goal-exceeded' AND selected_amount_units = 3000000 AND offer_selected_at IS NOT NULL)
      ) IS TRUE
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'bef_operation_verification_after_offer_ck' AND conrelid = 'bef_operation'::regclass) THEN
    ALTER TABLE bef_operation ADD CONSTRAINT bef_operation_verification_after_offer_ck CHECK (
      (
        verification_started_at IS NULL
        OR (offer_selected_at IS NOT NULL AND verification_started_at >= offer_selected_at)
      ) IS TRUE
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'bef_operation_offer_selection_eligibility_ck' AND conrelid = 'bef_operation'::regclass) THEN
    ALTER TABLE bef_operation ADD CONSTRAINT bef_operation_offer_selection_eligibility_ck CHECK (
      (
        offer_selection_eligible = false
        OR (operation_kind = 'purchase' AND status = 'awaiting_payment'
            AND selected_offer_id IS NULL AND selected_amount_units IS NULL AND offer_selected_at IS NULL
            AND verification_started_at IS NULL)
      ) IS TRUE
    );
  END IF;
END $$;

CREATE OR REPLACE FUNCTION bef_preserve_selected_offer_choice() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF ROW(NEW.selected_offer_id, NEW.selected_amount_units, NEW.offer_selected_at)
       IS DISTINCT FROM ROW(OLD.selected_offer_id, OLD.selected_amount_units, OLD.offer_selected_at) THEN
    IF OLD.selected_offer_id IS NOT NULL OR OLD.selected_amount_units IS NOT NULL OR OLD.offer_selected_at IS NOT NULL
       OR OLD.offer_selection_eligible IS NOT TRUE OR NEW.offer_selection_eligible IS NOT FALSE
       OR OLD.status IS DISTINCT FROM 'awaiting_payment' OR NEW.status IS DISTINCT FROM 'awaiting_payment'
       OR NEW.selected_offer_id IS NULL OR NEW.selected_amount_units IS NULL OR NEW.offer_selected_at IS NULL
       OR NEW.verification_started_at IS NOT NULL THEN
      RAISE EXCEPTION 'selected offer choice is immutable or not eligible';
    END IF;
  END IF;

  IF NEW.offer_selection_eligible IS DISTINCT FROM OLD.offer_selection_eligible THEN
    IF OLD.offer_selection_eligible IS NOT TRUE OR NEW.offer_selection_eligible IS NOT FALSE
       OR NEW.selected_offer_id IS NULL OR NEW.selected_amount_units IS NULL OR NEW.offer_selected_at IS NULL THEN
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

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'bef_operation_selected_offer_immutable' AND tgrelid = 'bef_operation'::regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER bef_operation_selected_offer_immutable
      BEFORE UPDATE OF selected_offer_id, selected_amount_units, offer_selected_at,
                       offer_selection_eligible, verification_started_at
      ON bef_operation FOR EACH ROW EXECUTE FUNCTION bef_preserve_selected_offer_choice();
  END IF;
END $$;

COMMIT;

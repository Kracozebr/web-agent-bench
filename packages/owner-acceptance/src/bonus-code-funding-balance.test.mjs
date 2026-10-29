import assert from "node:assert/strict";
import test from "node:test";
import { computeBonusAvailableBalanceDelta } from "./bonus-code-cases.mjs";
import { verifyCodeDerivedBonusFunding, verifyRunFundingConservation } from "./genuine-s1-cases.mjs";

const owner = "11111111-1111-4111-8111-111111111111";
const snapshot = (bonusAvailableUnits, snapshotOwner = owner) => ({
  ownerBalances: bonusAvailableUnits === null ? [] : [{ owner_id: snapshotOwner, bonus_available_units: bonusAvailableUnits }],
});

test("worker funding verifies the exact new grant delta while retaining prior bonus", () => {
  assert.deepEqual(computeBonusAvailableBalanceDelta(snapshot("66666"), snapshot("166666"), owner, "100000"), {
    beforeUnits: "66666",
    afterUnits: "166666",
    deltaUnits: "100000",
    verified: true,
  });
});

test("worker funding rejects any shortfall or unrelated excess in the observed delta", () => {
  assert.equal(computeBonusAvailableBalanceDelta(snapshot("66666"), snapshot("166665"), owner, "100000").verified, false);
  assert.equal(computeBonusAvailableBalanceDelta(snapshot("66666"), snapshot("166667"), owner, "100000").verified, false);
});

test("missing prior owner balance is treated as zero and another owner's balance is ignored", () => {
  assert.equal(computeBonusAvailableBalanceDelta(snapshot(null), snapshot("100000"), owner, "100000").verified, true);
  assert.equal(computeBonusAvailableBalanceDelta(snapshot("200000", "other"), snapshot("100000"), owner, "100000").verified, true);
});

test("malformed and duplicate observer rows fail closed", () => {
  assert.throws(() => computeBonusAvailableBalanceDelta({ ownerBalances: [] }, { ownerBalances: [{ owner_id: owner }] }, owner, "100000"),
    /Bonus available balance is invalid/);
  assert.throws(() => computeBonusAvailableBalanceDelta({ ownerBalances: [] }, { ownerBalances: [
    { owner_id: owner, bonus_available_units: "100000" }, { owner_id: owner, bonus_available_units: "100000" },
  ] }, owner, "100000"), /duplicate owner rows/);
});

const runId = "11111111-1111-4111-8111-111111111111";
const issuer = "22222222-2222-4222-8222-222222222222";
const oldGrantId = "33333333-3333-4333-8333-333333333333";
const oldCodeId = "44444444-4444-4444-8444-444444444444";
const oldRedemptionId = "55555555-5555-4555-8555-555555555555";
const newestGrantId = "66666666-6666-4666-8666-666666666666";
const newestCodeId = "77777777-7777-4777-8777-777777777777";
const newestRedemptionId = "88888888-8888-4888-8888-888888888888";
const hash = "a".repeat(64);
const op = (prefix) => `${prefix}_0123456789abcdef`;

function reservation(grantId, amountUnits) {
  return { id: `reservation-${grantId}`, source_kind: "tester_bonus", bonus_grant_id: grantId,
    cash_provenance: null, amount_units: String(amountUnits), state: "debited" };
}

function ledgerFor(reservations) {
  const reserveOperationId = `runacc_${runId.replaceAll("-", "")}`;
  const debitOperationId = `rundeb_${runId.replaceAll("-", "")}`;
  return reservations.flatMap((row) => [
    { entry_type: "reserve", operation_id: reserveOperationId, source_kind: row.source_kind,
      bonus_grant_id: row.bonus_grant_id, cash_provenance: null, amount_units: row.amount_units,
      available_delta_units: `-${row.amount_units}`, reserved_delta_units: row.amount_units, expired_delta_units: "0" },
    { entry_type: "debit", operation_id: debitOperationId, source_kind: row.source_kind,
      bonus_grant_id: row.bonus_grant_id, cash_provenance: null, amount_units: row.amount_units,
      available_delta_units: "0", reserved_delta_units: `-${row.amount_units}`, expired_delta_units: "0" },
  ]);
}

function codeSource({ grantId, codeId, redemptionId, amountUnits, issueOperationId, grantOperationId,
  claimOperationId }) {
  return { grant_id: grantId, grant_owner_id: owner, grant_amount_units: String(amountUnits),
    grant_issuer_owner_id: issuer, grant_operation_id: grantOperationId,
    redemption_id: redemptionId, redemption_owner_id: owner, redemption_code_id: codeId,
    redemption_financial_operation_id: grantOperationId, code_id: codeId, code_issuer_owner_id: issuer,
    code_kind: "single_use", code_amount_units: String(amountUnits), code_maximum_uses: 1, code_used_count: 1,
    code_issue_operation_id: issueOperationId, claim_operation_ids: [claimOperationId],
    claim_payload_hashes: [hash], claim_operation_count: 1 };
}

function newlyIssuedGrant() {
  const issueOperationId = op("issue_new");
  const grantOperationId = op("grant_new");
  const redemptionOperationId = op("claim_new");
  return {
    grantId: newestGrantId, amountUnits: "100000", grantOperationId,
    issue: { status: 201, codeId: newestCodeId, operationId: issueOperationId },
    redemption: { redemptionId: newestRedemptionId, grantId: newestGrantId,
      operationId: redemptionOperationId },
    database: {
      ledgerConserved: true, cashEffectCount: 0,
      fundingBalanceDelta: { beforeUnits: "66666", afterUnits: "166666", deltaUnits: "100000", verified: true },
      code: { id: newestCodeId, kind: "single_use", maximum_uses: 1, used_count: 1,
        issue_operation_id: issueOperationId, amount_units: "100000", issuer_owner_id: issuer },
      redemption: { id: newestRedemptionId, owner_id: owner, code_id: newestCodeId,
        bonus_grant_id: newestGrantId, financial_operation_id: grantOperationId },
      grant: { id: newestGrantId, owner_id: owner, amount_units: "100000", operation_id: grantOperationId,
        issued_by_owner_id: issuer },
      grantEntry: { bonus_grant_id: newestGrantId, source_kind: "tester_bonus", available_delta_units: "100000" },
    },
  };
}

test("worker run conserves a quote across multiple FIFO bonus reservations and reserve/debit pairs", () => {
  const rows = [reservation(oldGrantId, "66666"), reservation(newestGrantId, "53334")];
  const proof = verifyRunFundingConservation({ runId, quoteUnits: "120000", reservations: rows, ledger: ledgerFor(rows) });
  assert.equal(proof.reservationUnits, "120000");
  assert.equal(proof.reservationCount, 2);
  assert.equal(proof.reserveEntryCount, 2);
  assert.equal(proof.debitEntryCount, 2);
  assert.equal(proof.cashReservationCount, 0);
  assert.equal(proof.allSourcesAreBonus, true);
});

test("FIFO funding proves every consumed code lot and truthfully records an unconsumed newest issue", () => {
  const rows = [reservation(oldGrantId, "66666")];
  const oldSource = codeSource({ grantId: oldGrantId, codeId: oldCodeId, redemptionId: oldRedemptionId,
    amountUnits: "66666", issueOperationId: op("issue_old"), grantOperationId: op("grant_old"),
    claimOperationId: op("claim_old") });
  const proof = verifyCodeDerivedBonusFunding({ ownerId: owner, reservations: rows, sourceGrants: [oldSource],
    issuedGrant: newlyIssuedGrant() });
  assert.equal(proof.consumedLatestIssuedGrant, false);
  assert.equal(proof.bonusGrantIdMatchesCodeReceipt, false);
  assert.equal(proof.newlyIssuedGrantConsumedUnits, "0");
  assert.equal(proof.newlyIssuedGrantAvailableDeltaUnits, "100000");
  assert.equal(proof.codeDerivedSourceGrants.length, 1);
  assert.equal(proof.codeDerivedSourceGrants[0].grantId, oldGrantId);
});

test("FIFO funding rejects missing grant and code issuer identities even when both are absent", () => {
  const rows = [reservation(oldGrantId, "66666")];
  const source = codeSource({ grantId: oldGrantId, codeId: oldCodeId, redemptionId: oldRedemptionId,
    amountUnits: "66666", issueOperationId: op("issue_old"), grantOperationId: op("grant_old"),
    claimOperationId: op("claim_old") });
  source.grant_issuer_owner_id = null;
  source.code_issuer_owner_id = null;
  assert.throws(() => verifyCodeDerivedBonusFunding({ ownerId: owner, reservations: rows, sourceGrants: [source],
    issuedGrant: newlyIssuedGrant() }), /worker_run_bonus_grant_code_binding_invalid/);
});

test("fresh worker funding binds the new code receipt when the new lot is actually consumed", () => {
  const rows = [reservation(newestGrantId, "100000")];
  const latest = newlyIssuedGrant();
  const source = codeSource({ grantId: newestGrantId, codeId: newestCodeId, redemptionId: newestRedemptionId,
    amountUnits: "100000", issueOperationId: latest.issue.operationId, grantOperationId: latest.grantOperationId,
    claimOperationId: latest.redemption.operationId });
  const proof = verifyCodeDerivedBonusFunding({ ownerId: owner, reservations: rows, sourceGrants: [source], issuedGrant: latest });
  assert.equal(proof.consumedLatestIssuedGrant, true);
  assert.equal(proof.bonusGrantIdMatchesCodeReceipt, true);
  assert.equal(proof.newlyIssuedGrantConsumedUnits, "100000");
});

test("multi-lot funding rejects cash, missing code lineage, extra ledger rows, and quote shortfall", () => {
  const rows = [reservation(oldGrantId, "66666"), reservation(newestGrantId, "53334")];
  const ledger = ledgerFor(rows);
  assert.throws(() => verifyRunFundingConservation({ runId, quoteUnits: "120000", reservations: rows,
    ledger: [...ledger, { ...ledger[0], id: "extra" }] }), /worker_run_reservation_ledger_binding_invalid/);
  assert.throws(() => verifyRunFundingConservation({ runId, quoteUnits: "120001", reservations: rows, ledger }),
    /worker_run_funding_quote_or_ledger_total_mismatch/);
  const cashRows = [{ ...rows[0], source_kind: "cash_usdc", bonus_grant_id: null, cash_provenance: "synthetic" }];
  assert.throws(() => verifyCodeDerivedBonusFunding({ ownerId: owner, reservations: cashRows,
    sourceGrants: [], issuedGrant: newlyIssuedGrant() }), /worker_run_bonus_code_funding_input_invalid/);
  assert.throws(() => verifyCodeDerivedBonusFunding({ ownerId: owner, reservations: [rows[0]], sourceGrants: [],
    issuedGrant: newlyIssuedGrant() }), /worker_run_bonus_grant_observation_incomplete/);
});

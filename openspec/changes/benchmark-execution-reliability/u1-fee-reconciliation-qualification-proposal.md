# U1 reference final-state gas reconciliation

Status: approved by the owner on 2026-11-01: “Да, точная сверка газа без
допуска и изменения правил задания.” This is a qualification-only change
for `restart_payment_identity`. Old profiles remain exactly unchanged.

## Retained evidence

Qualification `2d263beb-1156-4208-9ee2-ec3e55d47a57` captured fifteen physical
references and passed raw integrity. All twelve Ranked projections were written;
assembly stopped on the exact final-state comparison for U1. Its initial-state
hash is unchanged. The new projection is:
`artifacts/runs/bts-difficulty-v2-case-candidates/bad4a9c0-c090-4e4c-8c6e-d7371f8e4672/ranked/U1/reference_execution_trace.json`.

The approved reference has participant gas `1239106590293` wei and final native
balance `10000622949518845510` wei. The new reference has participant gas
`1239106245477` wei and balance `10000622949519190326` wei. The five transaction
gas-unit counts are identical: 61943, 61943, 55437, 135153, 30340. Each observed
effective gas price is one wei lower, accounting for exactly 344816 wei.
The swap output, USDC, pool balances, allowances, delivered resources and
fulfilled obligations are unchanged. Earlier sponsored gas differs; random
authorization calldata affecting base-fee rounding is a hypothesis, not a
proven signature-level cause.

## Proposed bounded rule

For U1 Ranked under this approved restart qualification profile only:

1. Keep every task goal, initial-state field/hash, action count, rubric,
   deadline, price, budget, route, reserve and allocation assertion exact.
2. Independently verify both retained reference evidence sets and their
   transaction/receipt gas observations. Require the same participant action
   sequence and the same non-gas economic effects. Missing, contradictory or
   unknown observations must reject admission.
3. Require exact integer equality:
   `newFinalNative + newVerifiedParticipantGas == oldFinalNative + oldVerifiedParticipantGas`.
   All other final-state fields remain exact. No epsilon, percentage or
   arbitrary numeric tolerance is permitted. Do not silently treat unknown
   fees as zero; this proof is for the declared local-fork fee model only.
4. Permit the derived U1 reference final-state hash to change only after that
   reconciliation succeeds, preserving the actual new raw balance and hash in
   published artifacts. Never rewrite old captures or reuse an old hash for a
   new state. Every other case and both old refresh profiles retain the exact
   existing semantic comparator.
5. Negative tests must reject unexplained native deltas, missing/forged gas
   receipts, changed token/swap/payout/allowance state, altered budgets/goals or
   initial state, another task/profile, and a substituted final-state hash.
   Independent candidate validation and runtime acceptance remain mandatory.

This changes a qualification assertion. `docs/task-design.md` requires renewed
approval for changed assertions. No implementation of this exception is
authorized by this proposal alone. Retrying references until an accidental
exact gas match appears is not a substitute for resolving this contract.

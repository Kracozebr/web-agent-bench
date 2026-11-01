# Exact native-gas reconciliation across the current task inventory

Status: approved by the owner on 2026-11-01: “Да, единое точное правило для
всех текущих заданий.” Extend the already approved U1 principle
through a separate explicit profile v4. Leave v1/v2/v3 unchanged.

## Why the U1-only rule is insufficient

The current physical capture campaign `f35fd9fc-6bd5-4931-a3e2-b9a9e7f787b3`
completed fifteen captures and raw integrity. Its assembly stopped at M3's
reference final-state equality. M3 itself passed the independent V2 verifier.
Initial state, swap output, USDC, WETH and allowances match the approved case.

Approved M3: final ETH `10000040530135731795`, participant gas
`1082439327231` wei. New M3: final ETH `10000040530193673171`, gas
`1082381385855` wei. The final balance increase and gas decrease are both
exactly **57941376 wei**. Gross swap output is identical:
`41612575059026` wei. No unverified outcome is being promoted to success.

The former U1-only boundary was too narrow: actual native gas is a separate
measurement in every applicable task, not only U1.

## Proposed v4 boundary

Apply the same exact receipt-backed rule to the existing finite fifteen-case
inventory: Ranked S1/S2/S3/S4/M1/M2/M3/M4/H1/H2/H3/U1 and Training S1/M1/H1.
An unchanged case still passes the existing strict comparator. A differing
reference final hash may use reconciliation only when both references pass
full independent verification and have a nonempty, complete, identically
scoped participant native-transaction set. The count must match the approved
reference; it is not fixed to U1's five transactions.

Derive every gas charge from matched authoritative transaction/receipt and
existing cost/event evidence. Preserve the identical normalized economic
action sequence, initial state, every non-native final-state field and every
goal/price/budget/deadline/rubric/route/reserve assertion. Require exact integer
`newFinalNative + newVerifiedGas == oldFinalNative + oldVerifiedGas`; no tolerance
is allowed. Require both actual final-state hashes to match their raw states.
Keep U1's additional final-cutoff checks where that capture format declares
them. A missing, extra, unknown, contradictory or wrong-payer fee observation
rejects admission. A task with no participant gas cannot use this exception.

The application grader and benchmark requirements do not change. Only the
reference qualification accounts for independently observed gas rather than
requiring an accidentally identical fee. The scope is the declared local-fork
fee model, not full mainnet cost accounting.

Protect M3's three-receipt and U1's five-receipt sets, all available task-format
boundaries, missing/extra/forged receipts, non-gas state changes, substituted
hashes, unknown/future tasks and attempts to apply the rule to v1/v2/v3.
After approval: unit/negative gates, real retained M3 and U1 replay, standard
full qualification, restart and user-facing E2E. Never retry for an accidental
exact fee match or rewrite existing captures.

Renewed approval is required by `docs/task-design.md`: “A new scenario or
changed assertion requires renewed approval.”

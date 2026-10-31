# S1 reference fixture pin: technical profile

Decision: root requested a narrow public fixture input pin rather than alpha-renaming
or relaxing the approved source-refresh comparison. This changes reference capture
tooling only; task objectives, amounts, grading rules and exact state/hash comparisons
remain unchanged. No participant-facing product decision or new acceptance scenario
is introduced by this option.

The one-task v2 reference wrapper and probe accept optional `--recipient` only for
S1 in Ranked or Training. The batch driver must read each mode's exact public
`objective.recipient` from the already pinned approved candidate `0b68e103` after
verifying its complete SHA-256. The option does not reconstruct, import or require
the old recipient's private key: receiving a USDC transfer requires only its public
address. Never print or persist payer signer keys.

Malformed, zero, non-S1 and invalid-mode pins are rejected before any reset or
generation request. Fixed manifest-contract and generated-payer collisions are
rejected before the first reset. Omission retains the existing fresh random
recipient behavior. Capture provenance distinguishes explicit public fixture
selection from ephemeral generation. Existing action amounts, transaction proof,
balance deltas, receipts, original state hashes and case hashes stay authoritative.

The strict six-path source metadata exclusion list and production semantic reader
are unchanged. Fresh captures still need exact semantic comparison, independent
raw integrity checks, fencing and all applicable runtime gates. Previous `8f1817`
proofs remain historical; they are not rewritten to the new application/probe pins.

Local tests cover both S1 modes, default behavior, malformed/zero addresses,
non-S1 scope, duplicate CLI flags, payer/contract collisions, zero transport calls
on invalid pins and absence of a recipient-key requirement for explicit pins.
These are tooling regressions, not actual reference-capture or native-agent proof.
Fresh probes remain subject to root's exclusive BEF slot and explicit source/witness
GO; no reset or generation is performed by the tests.

## Context

The S2 `answer` observation is already retained in the immutable evaluation input when a grade is recorded. `recordTaskEvaluation` stores the canonical input and hash, while the owner feedback projection returns only grade/reason. This leaves the owner unable to inspect the submitted value behind the 2/5 S2 result in run `3463ef71-f14c-4781-add2-469fa659e84c`.

For Training run `8a7b4fb4-3fe7-4caf-abd3-10579fc468ff`, H1 closure is recorded at cutoff, accepted, and reconciled sequence 9. The retained admitted-action census contains three observed payments and two observed retrieves; the last payment has no same-payment retrieve. The worker still reaches `paid_resource_delivery_unobserved` and eventually `coordinator_evaluation_unknown`. A replay inside the running `oid-google-local` container using the current mounted source produced one `deliveryRequestAbsence` proof for payment sequence 9; `admittedDeliveryAbsenceSources` accepted the paid-child reference. The evaluator then rejects that reference because it allows validated non-root sources only for H3/U1. This confirms the failing gate. The available evidence is local BEF evidence, not live-chain evidence.

## Goals / Non-Goals

**Goals:**

- Let an authenticated owner inspect the exact submitted final S2 answer after both the task and run are terminal and the retained evaluation input passes its hash check.
- Let H1 use a paid-child absence proof only when the admitted-action loader validates the child, payment identity, cutoff, and absence of a same-payment retrieve.
- Keep unknown when the census/proof is absent or contradictory, or when a retrieve for the same payment was admitted.
- Keep all existing task goals, rubric fractions, action/deadline limits, and durable historical records unchanged.

**Non-Goals:**

- Exposing reference answers, sealed case fields, task fixtures, raw tool responses, or a general action journal.
- Changing task prompts, the payment/withdrawal contracts, credit weights, timeouts, or coordinator retry policy.
- Automatically regrading or rewriting the supplied historical run, changing its terminal reason, or treating this local BEF evidence as mainnet proof.

## Decisions

1. **Project the answer from the retained evaluation input.** Use the existing hash-verified retained input reader and select only the final S2 `observations.answers` value. Do not add another database copy or derive answer content from task-case/reference data. Return it only to the authenticated run owner after the run and S2 task are terminal; omit it if no verified evaluation input exists.

2. **Accept only trusted paid-child references.** Keep the existing source-equality fast path. For a child capture, require its evidence reference to be present in the trusted `validatedDeliveryAbsenceSources` assembled by the admitted-action or composite replay validator. Remove the task-ID exception that currently limits this path to H3/U1. Do not accept a caller-supplied reference without loader validation.

3. **Keep the rubric and unknown behavior unchanged.** A verified H1 no-retrieve proof allows the existing rubric to grade the observed result as partial. Missing, foreign, hash-mismatched, incomplete, contradictory, or same-payment-retrieve evidence remains unknown. No fallback score or new deadline grace period is added.

4. **Keep answer rendering as plain structured data.** Render escaped JSON/text in the existing owner report/feedback surface. Do not render answer values as HTML or attach other fields from the evaluation input.

## Risks / Trade-offs

- **[Reference-answer leakage]** An overbroad projection could expose sealed case data → select only the submitted S2 answer from the verified input; add tests proving expected/reference fields and other observations are absent.
- **[Untrusted child proof]** A caller could claim a paid capture is authoritative → accept child references only from strict admitted-action/composite replay validation and bind them to the same payment and closure.
- **[Answer markup or size]** Submitted content could be malformed or unexpectedly large → enforce existing S2 schema/size bounds and render it as escaped text; do not add raw transcript storage.
- **[Historical status ambiguity]** Fixing the evaluator may make a new run gradeable but does not authorize rewriting old run state → preserve existing historical rows and verify the new path with a fresh bounded run.

## Migration Plan

No database migration or backfill is required. The S2 report field is a read-only projection from an already retained, hash-verified evaluation input. The H1 evaluator consumes the already captured child proof only after loader validation. Rollback can remove the answer projection and restore the previous child-source check without changing stored inputs or task observations.

## Open Questions

None. The H1 replay confirmed that the proof is minted and trusted-loader validated before the evaluator rejects its child source. The S2 value is shown in the existing owner result/report view only after the entire run is terminal.

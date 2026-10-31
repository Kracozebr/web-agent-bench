## Context

The dedicated Training M1 collector mints absence proof. Ranked M1/M2/H1 use paid_data; H3/U1 combine paid_data and chain children. Complete settled payments without admitted retrieval currently become ambiguous in those paths.

## Goals / Non-Goals

Use one per-payment safety contract across all applicable paths. Preserve the seven non-purchase task rubrics, unknown safety, deadlines, pricing and history. Reporting tools exist but are filtered by current client configuration; automatic reporting activation is outside this grading correction.

## Decisions

Mint optional absence only from a complete immutable closed admission census, independently matching before/after source census, observed settled deferred payment, matching transfer/receipt and exact generation authority. Match retrievals to the same payment operation; unrelated resource retrievals do not exclude valid absence. Any admitted same-payment retrieval, pending/unknown/rejected action, incomplete census or contradictory identity stays outside this exemption.

Composite paid-child evidence must be verified against root, owner, run, task, closure, execution and child hashes before the trusted evaluator context admits its reference. A proof cannot authorize its own child reference. Candidate preflight and sealed replay derive the same trusted context without changing old input shapes. Old bundles without optional facts reproject byte-for-byte without new absence facts.

Ordinary rubric logic computes known failed or partial credit. No global unknown-to-zero conversion. Full Ranked admission remains twelve tasks. Physical negative actors use disclosed MCP tools and existing public reference actions, never injected grades or rewritten task clocks.

## Risks / Trade-offs

- False absence from partial child census: validate exact owner and source census and retain unknown for ambiguity.
- Retroactive grade drift: explicit legacy suppression and exact input-hash tests.
- Synthetic success mistaken for runtime proof: separate unit/PG reports from actual browser/MCP/worker/BEF captures.

## Migration Plan

Add optional projection/context fields only. Freeze production source before actual captures, preserve historical user-run fingerprints, restore the original local stand after isolated runs. Rollback code without rewriting runs or financial history.

## Open Questions

No economic-policy decision is pending. Live gates remain not_run until independently verified.

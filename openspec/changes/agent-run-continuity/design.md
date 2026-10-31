## Context
Native run a6e58ea5 lost S1 between acceptance and a second instruction. M1 paid but its retrieve was not admitted before cutoff; a generic missing-delivery unknown blocked H1. The original run remains immutable evidence.

## Goals / Non-Goals
Deliver one continuous scoped request, observable authorized progress and evidence-backed M1 absence grading. Preserve all prices, task weights/goals, clocks, fencing, refund authority and unknown safety. No historical regrading, mainnet or production acceptance.

## Decisions
A shared pure handoff builder feeds clipboard and manual fallback with nonauthorizing IDs, reviewed quote/selection and complete instructions. The native agent reads each actual task contract and continues until run.terminal is true.
current_task adds run {runId,status,terminal,terminalReason,cancellationReason}, state and retryAfterMs; waiting null responses recommend 1000 ms, issued/terminal responses use null. Existing authentication, owner/card/generation/mode checks run before projection. No new write endpoint.
M1 known absence requires a versioned, hash-bound closed action census, immutable cutoff, resolved original payment and authoritative BEF/source observations proving no retrieve was admitted. Sealed loaders/replayers repeat this validation. Any missing/foreign/tampered/contradictory proof or admitted pending/unknown retrieve remains unknown. Ordinary rubric failure advances the existing task lifecycle; no new compensation rule.

## Risks / Trade-offs
Incomplete census could fabricate zero: validate every admission and cross-source identity before permitting known absence. task:null can occur in several states: expose explicit server state and authoritative terminal flag. Reference worker success does not prove a native client.

## Migration Plan
Use additive response fields and unchanged historical data. Freeze all source before real captures. Capture actual browser request/clipboard, native MCP and independent PG/BEF/file effects. Preserve original run fingerprints before/after. Disable revised path or roll back code without rewriting admissions, results or ledger. Sync/archive only after every mandatory gate passes.

## Open Questions
No product approval is pending: owner explicitly approved these three fixes, BDD and real E2E, commit and push on 2026-10-31. Native/target/runtime evidence remains a measured gate.

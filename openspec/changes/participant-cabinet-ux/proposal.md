## Why

The current cabinet exposes internal launch-intent, release and credential vocabulary while hiding actionable task feedback. Participants need clear bonus prices, compact histories, contextual reporting and an administrator-only page boundary.

Status: implementation and listed BDD assertions approved on 2026-10-31 after independent review. Planning validation and approval are separate from runtime acceptance. See [approval](approval.md) and the [cross-change index](../../../docs/beta-usability-spec-plan.md).

## What Changes

- Replace technical launch wording with Training/Ranked actions, explicit prices, payment source and compact expandable histories.
- Format money for humans without reducing ledger precision; make help accessible by pointer, keyboard and touch.
- Expose useful Training feedback and context-linked screenshot reports while preserving Ranked secrecy and owner isolation.
- Return 404 for non-admin administration pages, hide administration navigation, and replace internal readiness codes with safe explanations.

Non-goals and evidence boundary: New financial arithmetic, prices or refund authority; a general trace/journal product; live Ranked coaching; changes to public eligibility; installer/refresh implementation; or weakening API authorization. A local reference adapter is not a participant-owned model run or target-host acceptance. No PvP fairness or settlement change is included.

## Capabilities

### New Capabilities

- `participant-cabinet-ux`: Participant cabinet and actionable diagnostics.

### Modified Capabilities

None of the three synchronized main capabilities is replaced in this planning packet. Integration with active deltas is recorded explicitly below and in design.md; existing active approval scopes are not silently amended.

## Impact

owner-web header, billing, runs, agent and report components; safe owner feedback/status projections and server page authorization. Existing role checks, exact ledger calculations, source reservations, billing/refund semantics and public eligibility are preserved.

Owns authenticated presentation and owner-context actions. ACI owns installer/refresh/handoff; BER owns execution truth; PBD owns anonymous publication; BTB owns timing policy.

Dependencies: Uses BER status taxonomy, ACI connection/handoff contract, PBD public route states and BTB phase labels. UI mocks alone do not establish any end-to-end gate.


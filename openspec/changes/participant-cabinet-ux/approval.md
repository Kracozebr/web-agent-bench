# Approval: participant-cabinet-ux

Date: 2026-10-31 (Europe/Moscow). Status: **approved for implementation and the listed executable assertions**.

## Decision reference

The owner explicitly approved all five packets in this chat: «Утверждаю все пять пакетов. Сделай коммит и пуш, затем начинай реализацию с сабагентами. Сначала закрой надёжность исполнения и оставшиеся проверки, с BDD и реальными end-to-end прогонами.»

This supersedes the 30 October planning-only boundary. Commit/push of the five reviewed plans, their approved implementation, listed BDD assertions/adapters and actual bounded local E2E qualification are authorized. Start with benchmark-execution-reliability and its outstanding catalog/recovery/replay checks. Existing user data and original failure evidence remain preserved.

## Agreed product decisions

- The participant's own native agent/model solves tasks; the platform supplies tools, isolated environment and verification.
- A user-launched installer automatically configures the selected client. Manual configuration instructions do not satisfy the normal setup requirement.
- Normal connections renew automatically until explicit revocation/security invalidation; manual 24-hour keys are an advanced legacy path.
- All twelve task-family descriptions, grading criteria, constraints and penalties are public. Exact Ranked cases, state fixtures and reference answers remain private; Training feedback is detailed and owner-private.
- Google open signup; bonus-code claim afterwards; only internal bonus USDC and simulated environment, no deposits/withdrawals or cash substitution.
- Current catalog: Training S1/M1/H1, weights 1/2/3 over six, full price 0.50; Ranked all twelve, weights sum 26, full price 1.00. Existing subset integer rounding, caps, 24-hour queue expiry, report-content/image retention until 30 UTC days after audited beta_ended_at and unified backup contracts remain.
- Preserve all required native paths: Codex CLI and Desktop, Claude Code and Desktop, Hermes. Existing decision to wait for all client families before beta release is not reduced by a Codex-only local pass.
- An owner-private launch intent is not a private/public mode selector; publication follows existing complete eligible Ranked rules. Admin page concealment is real server HTTP 404 for non-admin; API auth rules remain.

## Approved scope and remaining barriers

The requirement/scenario IDs, boundaries, observations, negative variants and durable effects in this packet's spec, BDD design and JSON contracts are approved as reviewed. Reconcile affected active deltas without weakening existing requirements or changing the approved scenario inventory. New assertions or a changed product boundary return to approval under docs/task-design.md.

Technical prerequisites remain explicit: native client/model access, safe installer integration points, target host/domain/HTTPS, qualified finite security/reconciliation parameters and source-bound evidence. Missing external prerequisites block only their actual acceptance gates, not independent local implementation. All runtime gates initially remain not_run and cannot be promoted by planning approval.

Timing measurement infrastructure is approved, but exact calibrated numerical runtime budgets still require the later table/approval gate described in BTB. Deferred task-preparation-prefetch implementation/enablement is not included. No real-money operation, deletion of original failure evidence, or automatic promotion to beta/production is authorized.

## Delivery and verification

Use actual browser controls through the running API/worker to independently verified durable PostgreSQL/BEF/file effects for user E2E. Native-client gates require the participant's actual model client. Preserve source/build/profile pins, paths/hashes, unknown states, existing financial source/refund authority, revocation and unified backup/restore. Sync/archive only when the applicable approved mandatory gates really pass.
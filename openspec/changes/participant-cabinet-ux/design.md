## Context

Proposed 2026-10-30 from the owner-approved direction and local inspection. The current cabinet exposes internal launch-intent, release and credential vocabulary while hiding actionable task feedback. Participants need clear bonus prices, compact histories, contextual reporting and an administrator-only page boundary. Implementation and listed assertions were approved on 2026-10-31; evidence status changes only after actual verification.

## Goals / Non-Goals

**Goals:** Replace technical launch wording with Training/Ranked actions, explicit prices, payment source and compact expandable histories. Format money for humans without reducing ledger precision; make help accessible by pointer, keyboard and touch. Expose useful Training feedback and context-linked screenshot reports while preserving Ranked secrecy and owner isolation. Return 404 for non-admin administration pages, hide administration navigation, and replace internal readiness codes with safe explanations.

**Non-Goals:** New financial arithmetic, prices or refund authority; a general trace/journal product; live Ranked coaching; changes to public eligibility; installer/refresh implementation; or weakening API authorization. All original beta target-host, Google, bonus, source-bound restore/recovery and native-client gates remain. No new code, Gherkin, mappers, registry entries, runtime profile or real-money actions are delivered by this draft.

## Decisions

### Owner journey and projection

Keep the current backend quote/reservation/cancellation APIs and server permissions. Display Training/Ranked rather than private/public intents; an intent is an owner-private request, while public card/score eligibility remains governed by BPC/BLP. Full Training contains S1/M1/H1; Ranked contains all twelve. Partial Training retains the existing whole-request ceiling formula over denominator six. Show the authoritative quote and bonus source before start, hide cash allocation in advanced details for this bonus-only profile, and explain insufficient balance without creating another launch.

Money display is presentation only: two decimal places using an explicit documented display rounding rule, exact micro-units in accessible details, and a nonzero less-than-0.01 marker. Server validations use exact units even if two values look identical after rounding. Histories use bounded server pagination with stable created_at plus unique ID cursor and an initial five-row viewport; scrolling must preserve complete authorized history and keyboard accessibility.

### Diagnostics, reports and admin

BER owns evidence-based error attribution and action truth; PCU maps stable allowlisted categories to readable text plus an optional sanitized support ID. Do not turn a user report into platform-failure authority or an automatic refund. Training detail can inspect authorized open-task traces and disclosed criteria; Ranked feedback remains terminal-only allowlisted reasons, with no new case/validator leakage. Current View results is too coarse and must be upgraded with evidence-linked causes, not fabricated textual explanations.

The existing BLP-REQ-007 and BLP-SC-011/014 exclude a chronological journal/trace viewer. PCU-REQ-005 explicitly proposes a narrow approval-time amendment permitting only owner-private action diagnostics for a completed Training task. It does not introduce a general run journal, active Training trace viewer, Ranked trace or public trace, and all unchanged secrecy/authorization clauses remain. Reconcile those exact legacy assertions before apply rather than claiming that timeline addition preserves them unchanged.

Report launch context is selected from server-owned run/task/action records; unlinked connection reports allow missing IDs. Client edition/version fields show their provenance (observed versus owner-declared versus unavailable) and remain optional when not observed. Reuse existing private normalized screenshot upload, size/quota enforcement, own-agent attachment audit, retention of report contents/context and images until 30 UTC days after audited beta_ended_at and combined backup/restore; no new image store or public support endpoint. Help works on click/focus/touch and reports validation safely.

Server page loading and role-bound header rendering must check verified subject/admin designation, not the email string in a client claim. Non-admin admin pages/subroutes return HTTP 404 before fetching or serializing private data; use private/no-store role responses to prevent cache leaks. Preserve existing private API 401/403 behavior, origin/CSRF protection and agent-role denial. Test authorized admin mutations plus independent database readback; hiding navigation is insufficient.

### Cross-change authority

Owns authenticated presentation and owner-context actions. ACI owns installer/refresh/handoff; BER owns execution truth; PBD owns anonymous publication; BTB owns timing policy.

Uses BER status taxonomy, ACI connection/handoff contract, PBD public route states and BTB phase labels. UI mocks alone do not establish any end-to-end gate.

The [integration index](../../../docs/beta-usability-spec-plan.md) lists active-delta overlap and the approval-time reconciliation. These new drafts do not supersede approved active requirements merely because they are newer. Before implementation, record exact affected legacy requirement/scenario mappings and approve coherent amendments to those active deltas; keep IDs and prior evidence history. No sync/archive is authorized here.

### Evidence and replay

Every scenario uses its real boundary in [bdd-harness-proposal.json](bdd-harness-proposal.json), with named observations, negative variants and durable effects. Runtime evidence carries frozen source/build/profile, sanitized principal/run/operation identifiers, authoritative event order, raw artifact paths and hashes, and independent observer identity. User journeys start through actual browser controls, follow running API/worker and persist in PostgreSQL; independently inspect final database/BEF/filesystem effects. Installer scenarios require actual native configuration and model client boundaries, not browser mocks. Private setup/fault injection and read-only inspection are permitted only for their named roles. Never retain credentials, sensitive provider data or raw personal identities in checked-in evidence.

Replays are read-only and never repeat economic commands. A missing external client, host, observer or unexecuted negative is `blocked` or `not_run`, not a green reference-model substitute. Planning validation checks structure, not runtime acceptance.

## Risks / Trade-offs

- Active-delta overlap can create two authorities: use the integration index and approval-time reconciliation before any apply.
- Local success can hide target/client gaps: retain separate per-edition and target-host mandatory gates.
- Readable UX can overstate certainty: display only durable known facts and preserve unknown attribution.
- New adapters can expose secrets: use secret references, protected stores and synthetic canaries, with no raw secret evidence.

## Migration Plan

1. Review this packet and all cross-change mappings; obtain explicit scenario/assertion and implementation approval.
2. Add only approved mirrors, mappers and real adapters in a later apply; keep all current runtime gates unchanged until rerun.
3. Prepare compatible migrations/config changes with an existing unified pre-migration backup of bonuses, results, reports, screenshots and evidence. Rehearse restore with writes disabled, original identities and retries preserved.
4. Qualify locally on frozen source, independently replay, then repeat required target/client gates before release. Missing host/domain or client access blocks that gate, not documentation work.
5. Roll back via disabled feature/profile and scoped configuration restoration without erasing journals, original evidence, account/ledger/report data or unobserved effects. Preserve outstanding fences/holds and revoked credentials on restore.
6. Sync/archive only after approved mandatory gates pass under docs/task-design.md; this planning work performs neither.

## Open Questions

No unresolved product choice is inferred. Agreed decisions are recorded in approval.md. Technical prerequisites and later calibration/security profile choices are explicitly gated in the decisions/tasks; if inspection proves a required client cannot support safe automatic setup, return that concrete limitation for a scope decision instead of silently dropping it.


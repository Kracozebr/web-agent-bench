## Context

Proposed 2026-10-30 from the owner-approved direction and local inspection. The root currently redirects to sign-in, task descriptions are not discoverable, and public results collapse unavailable service and empty data into one message. The owner approved public task-family descriptions and scoring rules while retaining private Ranked variants and answers. Implementation and listed assertions were approved on 2026-10-31; evidence status changes only after actual verification.

## Goals / Non-Goals

**Goals:** Provide an anonymous product homepage, twelve task-family descriptions, public rubrics/penalties and clear Training/Ranked pricing. Publish only an explicitly authored allowlisted description/rubric projection; retain sealed cases, baseline fixtures and reference answers privately. Keep the minimal existing public agent/best-result views and distinguish valid empty results, qualification restrictions and unready publication. Include accessible navigation, metadata and favicon without expanding into the full historical leaderboard product.

**Non-Goals:** Full historical/search/forum leaderboard scope, changed scoring/weights, publication of exact Ranked fixtures or solutions, new visibility triggers, private report/owner disclosure, and automatic cohort activation. All original beta target-host, Google, bonus, source-bound restore/recovery and native-client gates remain. No new code, Gherkin, mappers, registry entries, runtime profile or real-money actions are delivered by this draft.

## Decisions

### Public routes and disclosure

Root becomes a public product explanation with sign-in/cabinet navigation. Benchmark pages describe all twelve task families, Training eligibility/prices and outcome rubric with distinct latency/safety/cost/evidence dimensions. Public documents are authored safe projections linked to the active validated release. Do not treat runtime exposure flags as permission to dump the sealed manifest: public task-family criteria and names are distinct from exact case material. Explicitly reviewed synthetic examples are allowed only if they are not actual Ranked fixtures or reference solutions.

Publish goals, constraints, fractional-credit logic and safety penalties; retain secret case instances, seeds, state fixtures and reference answer values. Build/static/public API/hydration/cache tests use synthetic canaries rather than storing real secrets in fixtures. Unknown future internal manifest fields are private by default. Runtime issuance remains current-task-only and Training S1/M1/H1-only. No extra parallel versioned catalog is introduced; immutable admitted snapshots remain required.

Preserve BLP-REQ-009/010 and BLP-SC-013/015 fair-play/interpretation disclosures: Ranked forbids human solution assistance/manual execution; pre-start setup and technical confirmations without choosing/editing a solution are allowed; Training is exempt. State permitted open solutions, exact closed-case embargo, fixed-input best-run learnability and inability to independently verify owner-side autonomy. Public family descriptions are not evidence of unseen-case generalization. Replace legacy eight-task Training wording with the current three-task roster explicitly during approval-time BLP reconciliation.

### Existing results and release policy

Reuse /public/agents list/detail and the existing public-ranked API (new convenient navigation aliases may only redirect to them). This is not the full BLP historical/search/forum scope. First-public-action markers and best-result pointers retain BPC/BLP eligibility, exact fractions, denominator 26, coherent single-run components and stable equal-score behavior. An agent card without completed eligible score is not a zero-scoring run. Owner email, Google subject, private connection/report data, image URLs and bearer material never enter public cache keys or values.

The current local launcher omits the beta manifest: API responds PUBLIC_RESULTS_UNAVAILABLE. Render a truthful unavailable state; do not loosen qualification network guards or manufacture an empty successful list. Distinguish healthy empty cohort data, unknown agent, restricted qualification and unready/service failure. Preserve no-store on errors/restricted/private responses and coherent eligible cache invalidation. Public explanatory content can be previewed independently, but cohort results activation still needs all original target/client/operations/recovery/restore gates.

PBD-SC-004 explicitly retains BLP-SC-016/017 privacy/cache controls: unpublished cards match missing-card responses, committed first publication invalidates negative caches, and already-public cards without a selected-version score stay public without a fabricated ranked row. No setup/preflight/Training/failed run can become a first-public-action trigger.

### Inspiration boundary

BitGN public challenge pages expose family examples and link scoring rules; its Benchmarks page is a separate research section. Use this as information-architecture inspiration only. The project uses its own task goals, bonus pricing, evidence requirements and minimal results scope; no external content is copied as normative behavior.

### Cross-change authority

Owns anonymous discovery and the existing bounded public-results presentation. Integrates BPC minimal publication and benchmark-leaderboard-and-agent-pages (BLP) authoritative complete-ranked eligibility; preserves BTS runtime exposure and current-task issuance.

Can be authored in parallel. Eligible runtime publication requires BER complete ranked evidence and the existing configured cohort-release manifest; no automatic relaxation of qualification network guards.

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


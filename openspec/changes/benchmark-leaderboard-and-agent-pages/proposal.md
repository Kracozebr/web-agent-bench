## Why

Participants need one comparable overall leaderboard and a public agent page that
explains the best result without exposing private run diagnostics. The user chose
an overall score plus four difficulty indicators from that same ranked run.

Status: proposed planning packet; implementation/scenario approval is pending.

## What Changes

- Keep new cards private until a shared marker is committed atomically by the first
  forum publication or eligible ranked terminal event. Verify direct-route/cache
  privacy, competing triggers and durable public state after moderation.

- Consume only the coordinator's complete verified ranked-result handoff, retaining
  benchmark identity, all twelve outcomes and the achieving agent-version snapshot.
- Calculate the selected difficulty-only overall score and simple/medium/hard/ultra
  indicators, publishing the formula and keeping other measurements separate.
- Select one best run per agent per benchmark version, update automatically and
  handle duplicate, concurrent and out-of-order completion delivery durably.
- Share ranks for equal exact scores, show speed separately, and preserve current
  and historical benchmark-version boards without mixing or silent rescoring.
- Reflect active-version-only new training/ranked admission while accepting late
  eligible completion of already admitted queued/active runs into their own
  historical board. History links do not grant a new old-version run; lifecycle
  owns the atomic admission/activation and idempotency checks.
- Build anonymous English leaderboard and agent pages with safe public metadata,
  the same best run's overall/four indicators, and visible forum-message links.
- Publish the selected no-human-solution-assistance ranked rule, its technical-
  confirmation exception and the limitation that external autonomy is not verified.
- Provide owner-scoped compact result pages under the existing feedback-release
  rules; error reasons, task details and diagnostics do not enter public payloads.
- Verify actual application/database/browser projections, including no-result,
  pagination, metadata edits, moderation visibility and restart/rebuild behavior.

Non-goals: twelve task evaluators/rubrics, public per-task scores, public detailed
run cards/replay, private tool-call journals, additional difficulty leaderboards,
new score penalties, human-assistance detection/adjudication, hosted agents, PvP,
account merging or financial settlement.

The public disclosure level, difficulty weights, best-run selection, ties and
version separation are user-selected. Exact-score representation, display
rounding, representative selection on equal runs, rank numbering and read-model
mechanics are proposed engineering rules for review in the design.

## Capabilities

### New Capabilities

- `benchmark-leaderboard-and-agent-pages`: trusted result ingestion, versioned
  aggregate/tier scoring, durable best selection/ranks and public/private pages.

### Modified Capabilities

None. Preserve synchronized `benchmarking-core` and `realtime-pvp`. Consume the
proposed lifecycle, identity/access and forum contracts without implementing a
second coordinator, authentication authority, ledger or moderation system.

## Impact

Future TypeScript scoring/projection modules, PostgreSQL result/best/publication
records, bounded public and private HTTP read APIs, Next.js pages and Python/browser
acceptance adapters. This changes benchmark interpretation and public disclosure;
it does not change actual task execution, PvP fairness or customer settlement.

No product implementation, executable test, publication or result calculation
has run as part of writing this proposal.

Task-suite integration: detailed grading now has its own pending
benchmark-task-suite packet and actual full-suite gate. This packet retains
aggregation/projection authority and its explicitly labelled credit fixtures.
Public descriptions disclose the selected open/closed policy and fixed-input
external-agent limitations. Private closed results expose only score plus allowed
reason category without exact case parameters/answers; no new public metrics or
leaderboards are added.

## Why

The root currently redirects to sign-in, task descriptions are not discoverable, and public results collapse unavailable service and empty data into one message. The owner approved public task-family descriptions and scoring rules while retaining private Ranked variants and answers.

Status: implementation and listed BDD assertions approved on 2026-10-31 after independent review. Planning validation and approval are separate from runtime acceptance. See [approval](approval.md) and the [cross-change index](../../../docs/beta-usability-spec-plan.md).

## What Changes

- Provide an anonymous product homepage, twelve task-family descriptions, public rubrics/penalties and clear Training/Ranked pricing.
- Publish only an explicitly authored allowlisted description/rubric projection; retain sealed cases, baseline fixtures and reference answers privately.
- Keep the minimal existing public agent/best-result views and distinguish valid empty results, qualification restrictions and unready publication.
- Include accessible navigation, metadata and favicon without expanding into the full historical leaderboard product.

Non-goals and evidence boundary: Full historical/search/forum leaderboard scope, changed scoring/weights, publication of exact Ranked fixtures or solutions, new visibility triggers, private report/owner disclosure, and automatic cohort activation. A local reference adapter is not a participant-owned model run or target-host acceptance. No PvP fairness or settlement change is included.

## Capabilities

### New Capabilities

- `public-benchmark-discovery`: Public benchmark explanation and results.

### Modified Capabilities

None of the three synchronized main capabilities is replaced in this planning packet. Integration with active deltas is recorded explicitly below and in design.md; existing active approval scopes are not silently amended.

## Impact

public owner-web routes, content projections and metadata; existing public-ranked API/read model and cache behavior. No new scoring formula, mandatory training requirement, public private-report data, or production readiness claim.

Owns anonymous discovery and the existing bounded public-results presentation. Integrates BPC minimal publication and benchmark-leaderboard-and-agent-pages (BLP) authoritative complete-ranked eligibility; preserves BTS runtime exposure and current-task issuance.

Dependencies: Can be authored in parallel. Eligible runtime publication requires BER complete ranked evidence and the existing configured cohort-release manifest; no automatic relaxation of qualification network guards.


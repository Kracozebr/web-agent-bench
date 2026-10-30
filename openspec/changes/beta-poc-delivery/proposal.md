## Why

The owner needs a usable external beta within a target of 10–14 calendar days to learn whether people can connect their own agents, run the benchmark and report problems. HEAD `4e84d0e` proves local full12 execution and bounded local Codex transport/authentication, but the current local-only coordinator/profile, missing bonus codes and missing report surfaces prevent that beta.

## What Changes

- Deliver a bounded beta for 20–30 total participants using Google open registration, private agent management, public eligible-result summaries, internal bonus credits, and a capacity-limited queue.
- Add administrator-issued group bonus codes with a total redemption cap and one redemption per owner, plus single-use bearer codes claimed by their first valid redeemer. Commit redemption, capacity usage and the existing ledger grant atomically.
- Add a separately configured external HTTPS beta execution/readiness and MCP profile for Codex, Claude Code, Claude Desktop and Hermes. Preserve local profiles and real owner/agent authorization, isolate synthetic task environments and pin the actually tested client/auth/protocol matrix.
- Use one current Training roster containing S1/M1/H1 at weights 1/2/3 with fixed denominator 6 and a 0.5 internal-USDC bundle price. Price each selection once as `ceil(500000 × selected-weight-sum / 6)` micro-USDC. Keep the twelve-task Ranked12 catalog, order, weights, price, rubric and grading unchanged. Do not add a versioned catalog or backward-compatibility branch.
- Add minimal anonymous public card/best-result pages using the existing ranked publication marker and excluding private fields.
- Add 30-day post-beta report/screenshot retention and purge, including safe backup restore.
- Add owner and agent problem reports with private screenshots, bounded safe automatic context, and administrator list/detail/filter/status controls.
- Provide target-host restart, bounded admission, backup/restore, evidence retention and a small usage/support export sufficient for this experiment.
- Define a separate beta acceptance matrix and obligation map. Existing MVP gates retain their actual states; this proposal does not waive a required invariant of an included beta path.

Non-goals: real deposits/withdrawals, platform model credentials or inference billing, wallet onboarding/recovery work, forum, full historical leaderboard product, error rankings, general analytics, hosted agents, PvP, rental, RnD swarms and full production availability. Existing wallet implementation need not be removed. Benchmark validity is affected by external execution and evidence integration. The only task-profile amendment is the single current Training roster and its pricing specified here; Ranked12 tasks, weights, denominator, zeroing criteria and unknown semantics remain unchanged. No PvP fairness or real-money settlement change is proposed.

## Capabilities

### New Capabilities

- `beta-poc-delivery`: bounded external beta admission, bonus-code redemption, authenticated client execution, public verified score summaries and private controls, problem reports, administration and release evidence.

### Modified Capabilities

None of the three synchronized main capabilities changes its requirements. This capability adds a separately reviewed beta deployment boundary and composes the existing active OID/AAP/TBB/BRL/BTS rules; ownership and the exact extension beyond the local-only implementation are recorded in `design.md`. Local-profile approvals are not treated as approval of the external profile.

## Impact

- `packages/owner-identity`: beta runtime/configuration, transport/client registry, Google admission, bonus-code schema/migrations/transactions, current Training selection/quote/run bindings, report/image schema/routes/tools and private image validation/storage, 24-hour queue bounds, recovery and safe read projections.
- `packages/owner-web`: code issuance/redemption, private balance/run history, client setup instructions, owner report/image form, public result/card views and admin report/image controls, using existing auth and UI components.
- `packages/owner-acceptance`, `tests/bdd`, `tools`: after root review, implement the approved BPC-SC-014 current Training boundary and real browser/client/PostgreSQL/BEF evidence; update its scenario map, semantic contract and Gherkin mirror without adding an ID; write new validation evidence to fresh paths and leave frozen repository proof artifacts unchanged.
- `infrastructure/owner-identity`, `infrastructure/benchmark-environment`: external-host deployment, HTTPS, persistent data/evidence, bounded worker, backup/restore and controlled pause/restart.
- External prerequisites: target host/domain and DNS, Google OAuth project/callback/admin identity, pinned read-only source RPC and BEF data, the four client editions and participant-owned model access. Exact values belong in a validated non-secret deployment/client manifest, not invented fixtures.
- Planning source: [PoC delivery plan](../../../docs/poc-delivery-plan.md). Budget is a target, not a release gate override; day 2 is the explicit external-execution/client feasibility checkpoint.

Owner clarifications: code rules and same-host backup accepted; queue wait is 24 hours; screenshots are included; release waits for all four families; published cards/results are visible to everyone; reports/screenshots expire 30 days after beta closure. Google OAuth project must be created; only Codex access currently exists. Other client access must be arranged; server/domain selection is an explicit preparation task.

Status: the original beta scope remains approved as recorded below. The latest 30 October user override approves one current Training roster, S1/M1/H1 at weights 1/2/3 and denominator 6, with a 0.5-USDC bundle; it rejects a versioned catalog and backward-compatibility branches. Ranked12 remains unchanged. Root owns the separate deletion of exactly five local qualification runs and their dependent results; this planning change does not delete data, and accounts, agents, auth, codes, ledger and reports are retained. New validation evidence uses fresh paths; frozen repository proof artifacts remain unchanged. No additional real model runs, credit grants/spend or credential operations are authorized beyond the previously consumed 3.1 attempt. Existing gate results and task progress (3/45) remain unchanged; beta runtime gates remain `not_run`.

# Web3 Agent Bench · MVP UI prototype

This folder contains a static, browser-ready interface prototype for reviewing the MVP v1 owner and public-result flows. All interactions use local synthetic state. It is a design and behavior mock, not the benchmark service, a payment implementation, or runtime acceptance evidence.

## Run locally

From the repository root, start a static server:

```powershell
python -m http.server 4173 --bind 127.0.0.1 --directory prototypes/mvp-ui
```

Then open [http://127.0.0.1:4173](http://127.0.0.1:4173). No install, build, CDN, external font, or network access is needed. The application uses native ES modules and browser `localStorage` under `web3-agent-bench-mvp-ui-v1`. Open **Prototype scenarios → Reset demo** to restore the baseline fixtures. A private one-time dummy token is held only in page memory and is cleared on reload/reset.

From the repository root, `npm --prefix prototypes/mvp-ui run check` runs JavaScript syntax checks and the lightweight domain smoke checks in `smoke-check.mjs`. See the [review record](../../docs/ui-prototype-review.md) for browser checks and remaining boundaries.

## What the mock covers

- MVP v1 under a **simulated Controlled Base fork / controlled x402** label, with synthetic test funds only.
- S1–S4, M1–M4, H1–H3, and U1; 4 Simple, 4 Medium, 3 Hard, 1 Ultra. Weights are 1, 2, 3, and 5 by level; total ranked weight is 26. Closed tasks are S3, M2, H3, U1; the other eight are open.
- Full open-task training is 0.50 USDC, and a full ranked run is 1.00 USDC. Training subsets use their selected weight over the open-set weight of 15 and round the price upward once to integer micro-USDC.
- A resumable setup wizard with simulated invitation and Google/wallet authorization states, owner-provided client/model metadata, four independent disabled-by-default permissions, a separate cash-fallback switch, operation/day/category caps, connection-grant outcomes, one free preflight, and an explicit save.
- A launch handoff that copies only a service reference, mode, and opaque launch ID. Waiting for simulated agent acceptance creates no run, hold, charge, or timer. Acceptance creates one queued run with a source-aware hold; subsequent screens model preparation, one-time start debit, sequential task actions, cancellation, expiry, unknown evidence, proven platform recovery, and proven platform failure.
- A single coherent synthetic ranked result, versioned leaderboards, score-only rank assignment, and public profile variants for private, public-without-result, and public-ranked states. Public comparison fixtures are not owner-managed agents.
- Observable outcome, elapsed time, benchmark fee, and safety category appear as separate measures. Open-task owner feedback can be more detailed; closed-task feedback is limited to score and safe category.

The credits in the baseline fixture use units on a common 60-point scale and follow the current synthetic rubric proposals. S2 is 70%; M2 is 40%; M4 is 70%; H1/H2 are each 2/3; H3 is 30% because required data is delivered but the dependent swap does not complete; U1 is 25%. The selected run has an overall score of 61.73% across weight 26 (Simple 92.5%, Medium 77.5%, Hard 54.4%, Ultra 25%). The result, all four level values, elapsed time, fee, and declared agent version come from that one run. Time is never a ranking tiebreaker.

## Review scenarios

Use the scenario selector in the lower-left **Prototype scenarios** panel. Selecting a scenario replaces current local state; apply **Reset demo** to return to baseline.

| Scenario | Review path |
| --- | --- |
| Baseline demo | Overview, selected owner agent, versioned leaderboard with Atlas/Alder comparison fixtures, public profiles, and a preexisting coherent selected run. |
| Fresh profile · all permissions off | Start setup; verify default-deny permissions, invitation/sign-in, saved client choice, separate cash fallback and caps, grant success/refusal/expiry, one-time dummy fallback, one free preflight, and explicit private save. |
| Invalid invitation / authorization refused / expired connection | Follow the wizard error and retry paths; saved permission policy stays untouched. |
| Failed or pending preflight | Resolve a pending result or reset setup after a failure; neither state allows profile save. |
| Insufficient funds / cash fallback disabled / budget cap reached | Launch and accept the request to see a pre-admission rejection without a run or reservation. |
| Quote changed / bonus expired / permission removed before admission | Accept the already-created waiting request and verify the precise rejection. |
| Queue deadline / cancel before start | Inspect release of the original source hold with no charge. |
| Cancel after start | Inspect the retained fee and unranked terminal state. |
| Unknown outcome · reconcile | Choose either recovered complete evidence or evidence proving no service effect; unknown itself remains unranked and unresolved. |
| Proven platform recovery pause / client disconnect | Compare paused clock under proven platform recovery with a normal disconnect where time continues. |
| Proven platform failure | Inspect exclusion and source-aware refund from a proven unrecoverable platform failure. |
| Private public route / public profile with no result | Compare privacy-preserving 404-style behavior with a forum-only profile that contains no fabricated result. |
| Leaderboard tie | Compare equal scores at different elapsed times; ranks remain tied. |

## Scope boundary

Identity-provider sign-in, wallet authorization, client launches, agent acceptance, balances, bonus expiry, billing, task execution, platform recovery, and result publication are state simulations only. The page does not request, store, or transmit provider keys, wallet material, real balances, or chain data. Model/client names are owner-provided and unverified. There is no MCP, real x402, chain adapter, scoring service, forum action, voting, withdrawal, administration, or user-facing runtime guarantee. The “Controlled Base fork” and “controlled x402” labels describe the intended MVP fixture context, not a live connection.

The displayed 10-minute pre-start deadline is an illustrative local review value, pinned at admission. The production duration requires queue/load validation. Pending observations produce an unknown score; only explicit failed outcomes count as zero. Saving a removed run-mode permission cancels affected queued/preparing/active mock work under the corresponding release or retained-fee rule; an unresolved unknown outcome stays under reconciliation.

All production/runtime capability gates remain `not_run`. This prototype does not change the harness or claim BDD, chain, payment, security, economic-safety, or production readiness.

## Source provenance

The original export remains unmodified in the review/download source locations. A byte-for-byte source copy is included for portable provenance only; it is not the runnable corrected prototype:

- Original ZIP: `C:\Users\RND\Downloads\stitch_web3_agent_bench_prototype (2).zip`
- Included copy: [`source/stitch-export.zip`](source/stitch-export.zip) · 298,654 bytes · SHA-256 `A9EB40BEB222D62413D0866964F5BF69459C8E8C471241A460339DC8003D1BA4`
- Original `code.html` SHA-256 recorded at intake: `1815a04c8267f62b28380792b45afb4a7399e848ca7b5076f69729e092de65d5`

The corrected implementation is `index.html`, `styles.css`, `app.js`, `domain.js`, and `mock-data.js`; it is independent of the original export at runtime.

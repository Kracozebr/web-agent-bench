# Pilot validation plan

Date: 2026-10-22. Discovery plan, not normative OpenSpec, implementation approval
or results from an experiment. User-confirmed facts are separated from proposed
measurements and unselected operating parameters.

## User-confirmed inputs

- Detailed solutions to active-version tasks may be published on the forum and
  used by other participants. Disclose the limitation in forum/ranking policy:
  scores on fixed conditions do not establish unseen-task generalization. Pilot
  score improvement alone is not evidence of model improvement or unaided
  reasoning; publication is distinct from live human help, which remains forbidden.
- The user has 20–40 potential external participants with agents in the Claude,
  Codex, OpenClaw and Hermes families. They are potential participants, not
  confirmed signups, active users or a measured adoption count.
- Exact client editions/versions, the number of owners per client family and
  recruitment channels have not been supplied. Do not assume all Claude/Codex
  participants use a particular desktop, CLI or IDE edition.
- The pilot's primary question is willingness to pay after a free stage.
  Benchmark repeat usage, forum activity and operating economics remain
  secondary observations. Tournaments and rentals remain later product scope.
- The first pilot is invitation-only. Anonymous visitors can still read the
  public forum, leaderboard and agent pages. Later open registration reuses the
  same accounts; invitation admission and tester-bonus issuance are separate.
- The free stage uses limited personal tester bonuses at ordinary displayed
  tariffs, as selected by the user, rather than zeroing all pilot prices. Grant
  amounts and dates are deferred until closer to launch; existing issued terms
  remain fixed. Cash shortfalls require the owner's separate spending permission.
- Prices are configurable including zero. Existing forum starting prices are
  directly 0.01 USDC per message and 5 USDC per custom topic; the first message is included
  in the topic price. The user selected 1 USDC as the initial complete ranked-run
  price. Full training initially costs 0.5 USDC, with selected tasks/subsets
  priced proportionally to their difficulty-weight share of the eight available
  open tasks (sum 15 after the selected closed S3/M2/H3/U1 split). All eight open
  training tasks cost 0.5 USDC; ranked still includes all twelve with score weight sum 26.
  All prices remain configurable to zero. None establishes measured margins.
- The user deferred free/paid observation durations until closer to launch;
  neither a seven-day nor a fourteen-day free window is selected.
- The user selected administrator-granted promotional points for tester messages,
  custom topics, training and ranked runs, separate from real USDC balances. They
  cannot be withdrawn, transferred or spent on PvP/prize entries or other
  unapproved modes. Spend bonuses first; a USDC shortfall requires prior owner
  permission and compliance with agent limits. One bonus buys one nominal USDC
  of services; admins can set expiry at issuance, with no expiry by default and
  existing terms preserved. Allocated bonuses expiring in queue cancel before
  start without a debit or extra cash substitution; both holds are released. Agent
  limits count full nominal service value including bonuses.

## Proposed experiment

Admission is invitation-only for this first pilot. Proposed implementation for
the later identity/admission packet: an administrator issues a single-use opaque
invitation, the invitee authenticates with Google or wallet, and verified owner
activation plus redemption commit atomically. Retries and linked login methods
must not create duplicate participant accounts; abandoned authentication must not
consume an invitation. Neither a supplied email/address nor the invitation alone
proves the owner's identity. The owner distributes invitations; none has been
created or sent by this planning work.

In closed mode, participant activation precedes card creation, delegated access
and real-funding exposure. Public reads remain available. Later open registration
changes new-admission policy while preserving owner IDs, identities, balances,
agents and history. It neither grants bonuses nor changes prices automatically.

The single-use mechanism, expiry, safe stored verifiers, redemption audit and
admin/redeeming UI remain proposed design details. An unused invitation's
revocation is not an account ban or a withdrawal restriction. Identity/admission
still needs its own OpenSpec boundary scenarios; the existing agent-access
packet does not verify this gate. The proposed
[owner identity/admission packet](../openspec/changes/owner-identity-and-pilot-admission/proposal.md)
now defines 8 requirements and 12 mandatory planned scenarios, including actual
Google/wallet acceptance. No login or activation has been performed.

1. Verify environment feasibility and client access before using participant
   activity as demand evidence. A failed connection is an onboarding observation,
   not proof that the owner rejected the benchmark's value or price.
2. Invite the potential cohort and record the actual invited/participating counts
   and client editions. No messages or invitations have been sent by this agent.
3. Run the selected free stage using limited personal tester bonuses at ordinary
   displayed prices, with bounded resource admission. Amounts/dates remain open.
   Observe connection, first completed task/run, actual usage and support needs.
   Free usage is not paid demand; promotional grants and their consumption are
   not customer-paid revenue. Record their nominal coverage and actual resource cost.
4. Offer a clearly stated paid stage after the user's bonus no longer covers the
   purchase, preserving any issued grant terms rather than silently expiring it.
   Owners use their own USDC under the existing
   balance, permission and spending-limit model. Agents need no new owner approval
   for each permitted action. Zero-price free activity must not silently become
   an unaffordable or unannounced charge; price/quote/budget rules need design.
5. Measure non-refunded paid usage and repeat paid use, separately for benchmarks,
   training, messages and topics. Keep top-ups, internal charges, refunds and
   withdrawals as distinct events. Separate real-USDC and bonus portions of mixed
   payments; only the owner-funded non-refunded portion contributes to paid usage.
   A deposit alone is not a product purchase.
6. Review conversion counts, repeat purchases, reasons for non-use and attributable
   expenses. A later follow-up can measure retention beyond this experiment.

Observation windows will be chosen closer to launch. This plan does not select
calendar dates or estimate development duration. The initial complete ranked-run
price is 1 USDC, configurable including zero. It is an experimental starting
price, not a measured market optimum or demonstrated cost-covering tariff.
Confirm feasibility and observe unit costs before the paid stage. Full training
initially costs 0.5 USDC with proportional task/subset pricing; exact rounding
and numeric success/review thresholds remain open.

## Proposed measurements

Count distinct owners alongside agent counts; several agents belonging to one
owner do not establish several independent paying customers.

| Observation | Proposed definition | Interpretation boundary |
| --- | --- | --- |
| Recruitment funnel | Potential, actually invited, signed up, connected, completed first task/run, received paid offer | Report counts per stage and per client family, not only successful users. |
| Primary paid conversion | Distinct owners with at least one positive, non-refunded product charge funded by their own USDC / distinct owners shown the paid offer | Also report conversion among activated owners shown the offer, with both denominators/counts visible. Own test accounts and subsidized credits are separate. |
| Repeated paid usage | Owners with a subsequent distinct non-refunded paid purchase, plus timing/frequency | Retries of the same operation are not new purchases. A single first purchase is not proven retention. |
| Product mix | Benchmark/training/message/topic charges, purchasers and refunds separately | Posting once and buying a complete benchmark need not imply the same value proposition. |
| Agent participation | Agent-initiated permitted actions and sessions, linked to their owners | Owner-selected models are unverified; external inference cost remains unknown if not observed. The client independently pays its model API/subscription; no provider credential or token charge passes through the platform. Free-stage bonuses cover platform services only. |
| Operational economics | Non-refunded earned charges versus measured RPC, signing/provider fees, withdrawal gas, storage and other attributable operating expenses | Deposited-but-unused USDC is a customer claim, not earned revenue. Report incremental expense and allocated ongoing expense separately. |
| Failure/support | Connection failures, cancellations, platform-caused refunds, unresolved evidence and support effort | Keep product demand separate from inability to use the product. |

The cohort is a user-selected potential group. Its results cannot by themselves
establish overall market size, pricing optimum, long-term retention or readiness
for a public release. Report actual counts and the offered price/window rather
than extrapolating a population estimate from potential participants.

## Open decisions and handoff

- Free/paid observation windows (explicitly deferred), readiness and recruitment channel.
- Free-stage resource quotas and unit-cost review of the selected initial
  1 USDC ranked-run / 0.5 USDC full-training prices and proportional training subsets.
- Numeric success/review thresholds and how failures affect the observation window.
- Analytics event definitions, accessible owner/agent data, retention and operational
  expense measurement. No analytics provider is selected by this plan.

Continue `/opsx:explore` with these experiment choices and remaining capability
details. Carry accepted metrics into the later operations/billing proposals;
executable tests and implementation require the repository's scoped approval.

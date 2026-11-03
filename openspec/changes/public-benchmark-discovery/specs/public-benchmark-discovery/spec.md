# Public benchmark explanation and results

Status: approved for implementation on 2026-10-31; implementation in progress. Runtime for all 6 scenarios: `not_run`. [Design](../../design.md), [BDD packet](../../bdd-design.md), [approval](../../approval.md).

## ADDED Requirements

### Requirement: PBD-REQ-001 Explain the product before sign-in
Anonymous root and benchmark navigation SHALL explain participant-owned agents, the simulated bonus-only environment, Google signup, installation, Training/Ranked prices and what results measure. The homepage SHALL position the product as independent reliability, safety and performance evaluation infrastructure for Web3 AI agents, using the exact headline “Independent Reliability, Safety & Performance Benchmark for Web3 AI Agents” and explaining that access to money, smart contracts and paid services creates an infrastructure problem without a widely accepted independent comparison of agent safety, economy and reliability. Public copy SHALL NOT claim real-money, mainnet or production safety. Metadata and a favicon SHALL render on public and cabinet pages. Major homepage sections SHALL have consistent vertical spacing. Navigation SHALL expose one Published results entry at `/public`, with no duplicate results link in owner navigation. Public rules SHALL state that Ranked prohibits human solution assistance/manual execution, while pre-start setup and technical confirmations that do not choose/edit the solution are allowed; Training is exempt. Owner-side autonomy SHALL not be described as independently verified.

Scenario setup: Anonymous browser and healthy public web runtime

#### Scenario: PBD-SC-001 Explain the product before sign-in
- **WHEN** a visitor opens root, benchmark, installer entry and account navigation on desktop or mobile
- **THEN** public explanation and accessible calls to action SHALL load without mandatory login, and entering a private cabinet SHALL still require authentication; the versioned human-assistance rule, exception and Training exemption SHALL be visible or directly linked without treating technical confirmations alone as a violation

### Requirement: PBD-REQ-002 Publish descriptions and grading rules for twelve task families
Public documentation SHALL describe S1-S4, M1-M4, H1-H3 and U1 with goals, difficulty/weights, permitted tools, constraints, credit rules and safety penalties. Training eligibility SHALL be exactly S1/M1/H1; public descriptions SHALL not make other tasks trainable. The benchmark catalogue SHALL list each distinct validated release version that has been activated, mark the current version, and retain retired versions as completed history; repeated activations SHALL NOT create duplicate cards. The current `BTS-LOCAL-V2` release SHALL display as “Web3 Agent Bench v1” while its technical ID remains unchanged in run and history records. Selecting a version card SHALL open that version's public description and validated prices. The catalogue SHALL fail closed for unrecognized or inconsistent release history and SHALL not invent labels, prices, or rubric metadata. Every price/rubric projection SHALL be bound to its validated release. The public interpretation SHALL disclose permitted open-solution use, the exact closed-case embargo until retirement, fixed-input best-run learnability and inability to independently verify absence of human help. The current three-task Training roster SHALL replace obsolete eight-task Training wording while keeping runtime exposure distinct.

Scenario setup: Validated current release and reviewed explicitly authored public rubric content

#### Scenario: PBD-SC-002 Publish descriptions and grading rules for twelve task families
- **WHEN** the visitor browses current and completed benchmark-version cards, opens a version detail and compares its prices/rubric with release metadata
- **THEN** each distinct validated activated version SHALL appear once, with the active version marked and retired versions retained as history; current `BTS-LOCAL-V2` SHALL display as “Web3 Agent Bench v1”; a selected card SHALL open its version-specific public description; all twelve descriptions SHALL match denominator 26, Training denominator 6 and that version's prices without changing runtime exposure; missing/conflicting history SHALL not invent a version, price, or rubric; fixed-input/known-solution and unverified-autonomy limitations SHALL be stated without implying exact Ranked variants are open

### Requirement: PBD-REQ-003 Keep sealed Ranked cases outside every public projection
The public projection SHALL be built from an allowlist authored for disclosure, never by serializing a sealed manifest and removing known keys. Exact Ranked case variants, initial fixtures, seed-specific state, reference answers, privileged rubric implementation/hidden validators and private evidence SHALL remain absent from API, HTML, hydration, static artifacts, assets and caches. Public criteria are not secret solutions.

Scenario setup: Hidden case canaries and public description/rubric fixtures

#### Scenario: PBD-SC-003 Keep sealed Ranked cases outside every public projection
- **WHEN** anonymous and owner clients request public pages/API, inspect build artifacts and cache variants or request hidden paths
- **THEN** only approved task-family descriptions and grading rules SHALL be disclosed; knowledge of a task name SHALL not grant case or future-task access

### Requirement: PBD-REQ-004 Publish only authoritative complete Ranked results
`/public` SHALL be the canonical public results list; `/public/agents` SHALL redirect to it, while agent details SHALL remain under `/public/agents/{agentId}`. Public list/detail SHALL use existing minimal first-public-action/card and best-result eligibility contracts: only complete verified Ranked12 can have an official scored best result. Training, cancelled, incomplete, unknown, disqualified or refunded-excluded runs SHALL not be ranked. Known zero/partial credits remain eligible only inside a complete verified run. Unpublished cards SHALL be indistinguishable from missing cards on every anonymous surface; first publication SHALL invalidate prior negative caches, and already-public cards lacking a selected-version score SHALL remain public without an invented score, under BLP-SC-016/017.

Scenario setup: Actual coordinator complete ranked handoff and comparable ineligible variants

#### Scenario: PBD-SC-004 Publish only authoritative complete Ranked results
- **WHEN** a visitor opens anonymous list/detail after duplicate completion, concurrent better/equal result or forged publication data
- **THEN** `/public` SHALL show one coherent best result reflecting one authoritative run with version and separate metrics; `/public/agents` SHALL redirect to `/public`, details SHALL remain available, first-action cards SHALL never imply a completed score, and no private owner/report identity SHALL leak

### Requirement: PBD-REQ-005 Distinguish empty publication from restricted or unavailable service
Public presentation SHALL distinguish an eligible empty list, missing agent, qualification-network restriction and unconfigured/unready or failed results service. Qualification and cohort-release guards SHALL remain intact; public discovery can stay available without enabling results. Errors SHALL expose no internal origin or secret configuration.

Scenario setup: Empty healthy cohort release, qualification manifest, absent manifest and failed service

#### Scenario: PBD-SC-005 Distinguish empty publication from restricted or unavailable service
- **WHEN** anonymous visitors request list/detail and the service recovers or changes manifest state across cached responses
- **THEN** the correct empty, 404, restricted or unavailable explanation SHALL render with safe retry guidance; restricted/error responses SHALL not become cached successful public data

### Requirement: PBD-REQ-006 Keep public rollout separate from target beta acceptance
Publishing content or a local preview SHALL not enable public result release or mark beta ready. Cohort release SHALL require the existing target-host, all-client, financial, operations, recovery, restore and pilot gates. Current local unavailable-results behavior SHALL be documented as configuration rather than an empty leaderboard.

Scenario setup: Local development public pages and a not-yet-qualified target manifest

#### Scenario: PBD-SC-006 Keep public rollout separate from target beta acceptance
- **WHEN** content is built/deployed and operators attempt cohort activation with missing mandatory evidence or secret/public origin mismatch
- **THEN** content-only preview SHALL be distinguishable, missing release gates SHALL block result activation, and approved target publication SHALL retain exact source/profile evidence


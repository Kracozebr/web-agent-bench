# Public benchmark explanation and results

Status: approved for implementation on 2026-10-31. Runtime for all 6 scenarios: `not_run`. [Design](../../design.md), [BDD packet](../../bdd-design.md), [approval](../../approval.md).

## ADDED Requirements

### Requirement: PBD-REQ-001 Explain the product before sign-in
Anonymous root and benchmark navigation SHALL explain participant-owned agents, simulated bonus-only environment, Google signup, installation, Training/Ranked prices and what results measure. Public copy SHALL NOT claim real-money, mainnet or production safety. Metadata and a favicon SHALL render on public and cabinet pages. Public rules SHALL state that Ranked prohibits human solution assistance/manual execution, while pre-start setup and technical confirmations that do not choose/edit the solution are allowed; Training is exempt. Owner-side autonomy SHALL not be described as independently verified.

#### Scenario: PBD-SC-001 Explain the product before sign-in
- **GIVEN** Anonymous browser and healthy public web runtime
- **WHEN** a visitor opens root, benchmark, installer entry and account navigation on desktop or mobile
- **THEN** public explanation and accessible calls to action SHALL load without mandatory login, and entering a private cabinet SHALL still require authentication; the versioned human-assistance rule, exception and Training exemption SHALL be visible or directly linked without treating technical confirmations alone as a violation

### Requirement: PBD-REQ-002 Publish descriptions and grading rules for twelve task families
Public documentation SHALL describe S1-S4, M1-M4, H1-H3 and U1 with goals, difficulty/weights, permitted tools, constraints, credit rules and safety penalties. Training eligibility SHALL be exactly S1/M1/H1; public descriptions SHALL not make other tasks trainable. Published version and price/rubric projection SHALL be bound to a validated current release. The public interpretation SHALL disclose permitted open-solution use, the exact closed-case embargo until retirement, fixed-input best-run learnability and inability to independently verify absence of human help. The current three-task Training roster SHALL replace obsolete eight-task Training wording while keeping runtime exposure distinct.

#### Scenario: PBD-SC-002 Publish descriptions and grading rules for twelve task families
- **GIVEN** Validated current release and reviewed explicitly authored public rubric content
- **WHEN** the visitor reads all task-family pages and compares them with admission/scoring metadata
- **THEN** all twelve descriptions SHALL be consistent with denominator 26, Training denominator 6 and current prices without changing runtime exposure; missing or conflicting public metadata SHALL not invent a new active release; fixed-input/known-solution and unverified-autonomy limitations SHALL be stated with the versioned rubric, without implying that public descriptions make exact Ranked variants open

### Requirement: PBD-REQ-003 Keep sealed Ranked cases outside every public projection
The public projection SHALL be built from an allowlist authored for disclosure, never by serializing a sealed manifest and removing known keys. Exact Ranked case variants, initial fixtures, seed-specific state, reference answers, privileged rubric implementation/hidden validators and private evidence SHALL remain absent from API, HTML, hydration, static artifacts, assets and caches. Public criteria are not secret solutions.

#### Scenario: PBD-SC-003 Keep sealed Ranked cases outside every public projection
- **GIVEN** Hidden case canaries and public description/rubric fixtures
- **WHEN** anonymous and owner clients request public pages/API, inspect build artifacts and cache variants or request hidden paths
- **THEN** only approved task-family descriptions and grading rules SHALL be disclosed; knowledge of a task name SHALL not grant case or future-task access

### Requirement: PBD-REQ-004 Publish only authoritative complete Ranked results
Public list/detail SHALL use existing minimal first-public-action/card and best-result eligibility contracts: only complete verified Ranked12 can have an official scored best result. Training, cancelled, incomplete, unknown, disqualified or refunded-excluded runs SHALL not be ranked. Known zero/partial credits remain eligible only inside a complete verified run. Unpublished cards SHALL be indistinguishable from missing cards on every anonymous surface; first publication SHALL invalidate prior negative caches, and already-public cards lacking a selected-version score SHALL remain public without an invented score, under BLP-SC-016/017.

#### Scenario: PBD-SC-004 Publish only authoritative complete Ranked results
- **GIVEN** Actual coordinator complete ranked handoff and comparable ineligible variants
- **WHEN** a visitor opens anonymous list/detail after duplicate completion, concurrent better/equal result or forged publication data
- **THEN** one coherent best result SHALL reflect one authoritative run with version and separate metrics; first-action card SHALL never imply a completed score and no private owner/report identity SHALL leak

### Requirement: PBD-REQ-005 Distinguish empty publication from restricted or unavailable service
Public presentation SHALL distinguish an eligible empty list, missing agent, qualification-network restriction and unconfigured/unready or failed results service. Qualification and cohort-release guards SHALL remain intact; public discovery can stay available without enabling results. Errors SHALL expose no internal origin or secret configuration.

#### Scenario: PBD-SC-005 Distinguish empty publication from restricted or unavailable service
- **GIVEN** Empty healthy cohort release, qualification manifest, absent manifest and failed service
- **WHEN** anonymous visitors request list/detail and the service recovers or changes manifest state across cached responses
- **THEN** the correct empty, 404, restricted or unavailable explanation SHALL render with safe retry guidance; restricted/error responses SHALL not become cached successful public data

### Requirement: PBD-REQ-006 Keep public rollout separate from target beta acceptance
Publishing content or a local preview SHALL not enable public result release or mark beta ready. Cohort release SHALL require the existing target-host, all-client, financial, operations, recovery, restore and pilot gates. Current local unavailable-results behavior SHALL be documented as configuration rather than an empty leaderboard.

#### Scenario: PBD-SC-006 Keep public rollout separate from target beta acceptance
- **GIVEN** Local development public pages and a not-yet-qualified target manifest
- **WHEN** content is built/deployed and operators attempt cohort activation with missing mandatory evidence or secret/public origin mismatch
- **THEN** content-only preview SHALL be distinguishable, missing release gates SHALL block result activation, and approved target publication SHALL retain exact source/profile evidence


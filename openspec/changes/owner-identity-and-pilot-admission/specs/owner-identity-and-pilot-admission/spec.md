# Owner identity and pilot admission

Status: approved active delta; see ../../approval.md. Selected product choices and implementation configuration are distinguished in ../../design.md. Approval is not acceptance evidence.

## ADDED Requirements

### Requirement: OID-REQ-001 Authenticate Google and wallet identities through verified flows
The application SHALL support Google and the selected wallet SIWE profile through actual server-side verification before owner-session issuance. Correlation, signature/message context, nonce replay, issuer/audience/expiry and supported-profile checks SHALL reject invalid or unresolved identity claims. Wallet email and login signatures SHALL NOT establish Google ownership or payment authorization.

#### Scenario: OID-SC-001 Google authentication verifies the provider operation before session issuance
- **WHEN** Google callback and token exchanges complete through the declared provider transport while callers alter state, issuer, audience, expiry or supplied profile fields
- **THEN** only a verified correlated provider subject SHALL establish its owner authentication context, while invalid or unresolved exchanges SHALL create no authenticated owner session from caller claims

#### Scenario: OID-SC-002 Wallet login verifies SIWE purpose context and one-time nonce
- **WHEN** wallets sign actual SIWE messages and callers replay a nonce or change domain, URI, allowed chain, validity interval, signature or browser/link purpose
- **THEN** only the approved verified message SHALL authenticate its wallet identity once, while invalid or unsupported profiles SHALL fail without trusting supplied email or treating login as payment proof

### Requirement: OID-REQ-002 Gate closed pilot activation with invitation redemption
Closed pilot admission SHALL require verified authentication and valid invitation activation while public reads remain accessible. Under the proposed single-use mechanism redemption and owner activation SHALL commit atomically and idempotently; invalid or abandoned authentication SHALL NOT consume an invitation or grant participant effects.

#### Scenario: OID-SC-003 Invitation redemption activates one verified owner atomically
- **WHEN** two verified identities race for a valid single-use invitation and the winning activation response is lost before retry or worker restart
- **THEN** under the proposed invitation mechanism one owner activation and redemption SHALL commit together, retries SHALL recover that outcome and the competing identity SHALL gain no duplicate admission or bonus

#### Scenario: OID-SC-004 Invalid invitation or incomplete authentication cannot bypass closed admission
- **WHEN** an unadmitted or unverified principal submits invalid, expired, revoked or consumed invitations, abandons authentication, or directly calls participant-only routes
- **THEN** invalid activation SHALL not consume a valid invitation or create participant authority; closed-mode card, delegated-access and funding routes SHALL deny unadmitted principals while public reads remain available

### Requirement: OID-REQ-003 Link verified methods explicitly to one durable owner
An authenticated admitted owner SHALL explicitly prove an added identity and bind it to the same owner, agents and source balances. Linking SHALL NOT grant bonuses or payment authority. Under the proposed no-merge policy implicit email linking, foreign session substitution and identities already owned elsewhere SHALL reject without moving assets, roles or histories.

#### Scenario: OID-SC-005 Explicit verified linking preserves one owner across both methods
- **WHEN** an admitted owner explicitly proves its additional unclaimed Google or wallet identity and then signs in through either linked method
- **THEN** both methods SHALL resolve to the same stable owner, agents and source balances without another admission, deposit address or bonus, and the linking proof SHALL not substitute for withdrawal authorization

#### Scenario: OID-SC-006 Linking rejects identity collision and foreign-session substitution
- **WHEN** callers link a provider or wallet identity already owned by another account, substitute the current session or use email equality without a fresh explicit link flow
- **THEN** under the proposed conflict policy linking SHALL fail without merging accounts, moving assets or privileges, or attaching an identity to the wrong owner; existing identities and histories SHALL remain accessible to their original owners

### Requirement: OID-REQ-004 Apply admission policy without migrating existing accounts
Registration-mode changes SHALL be authorized and recorded under a policy revision, serialize with new activation and preserve existing owner IDs, identities, agents, balances and history. Returning admitted owners SHALL NOT require another invitation. Mode changes SHALL NOT automatically change prices, grant bonuses or freeze established financial rights.

#### Scenario: OID-SC-007 Registration mode changes preserve returning owners and stored data
- **WHEN** an administrator switches closed admission to open while activation requests race, and previously admitted linked owners return in closed or open mode
- **THEN** new admission SHALL follow one committed policy revision without duplicate activation or partial redemption, while returning owners retain their IDs, identities, agents, balances and history without another invitation or automatic credit

### Requirement: OID-REQ-005 Verify owner session and role boundaries
Owner controls SHALL use real session, expiry, origin/CSRF and resource-owner verification, rejecting foreign, expired, forged or agent authority. Under the proposed session separation logout SHALL invalidate the browser session without itself revoking agent-wide access or authorizing a withdrawal.

#### Scenario: OID-SC-008 Owner sessions enforce role expiry origin and logout boundaries
- **WHEN** expired or foreign owner sessions, forged role fields, cross-origin mutations and agent credentials access owner controls while an owner logs out of its browser
- **THEN** the real verifier SHALL reject invalid or foreign authority without protected effects, and under the proposed session separation browser logout SHALL invalidate that session without impersonating explicit agent-wide revocation, withdrawal proof or admin authority

### Requirement: OID-REQ-006 Restrict invitation and mode controls to authorized administrators
Actual administrator pages/APIs SHALL issue/revoke invitations and configure admission only for explicit verified administrator authority. Ordinary owners, agents, invitation possession and first signup SHALL NOT assign or gain administrator rights. Audit/history SHALL not disclose credential or invitation plaintext.

#### Scenario: OID-SC-009 Actual admin invitation controls require configured authority
- **WHEN** the configured verified administrator issues or revokes unused invitations and changes registration mode through the real UI while owners or agents request those controls or claim first-signup privilege
- **THEN** only scoped administrator operations SHALL persist safe invitation or policy audit, unauthorized requests SHALL have no effect, and signup or invitation possession SHALL never assign an administrator role

### Requirement: OID-REQ-007 Supply one admitted owner to actual product boundaries
Actual agent-card, delegated-access and funding handlers SHALL enforce owner admission and share the stable verified owner identity. Admission SHALL not issue tester bonuses. Bonus-only usage SHALL remain possible without withdrawal setup, while real funding SHALL retain the separate confirmation-method gate.

#### Scenario: OID-SC-010 Admission integrates real agent and funding gates without auto incentives
- **WHEN** a verified unadmitted identity and then the activated owner call actual agent-card, delegated-credential and funding-exposure handlers while bonus and withdrawal setup states differ
- **THEN** participant-only effects SHALL require admission, the admitted owner SHALL use its actual shared identity across services, admission SHALL grant no bonus, and bonus-only use SHALL not require withdrawal setup while real funding still does

### Requirement: OID-REQ-008 Separate local authentication evidence from actual provider compatibility
Actual browser/application acceptance SHALL verify sign-in, invitation and linking with real validation and labelled local provider fixtures. A separate mandatory actual Google plus selected wallet gate SHALL prove its own integration without money movement; missing environments SHALL remain blocked, not replaced with local fixture evidence. Evidence/replay SHALL retain safe operation identities and original paths/hashes without secrets or repeated authentication/product effects.

#### Scenario: OID-SC-011 Local sign-in invitation and linking pages use real verification
- **WHEN** synthetic owners use actual browser sign-in, invitation and link pages through the declared isolated provider fixture and cryptographic wallet verification, including failed or abandoned flows
- **THEN** the UI SHALL reflect actual committed authentication and admission state with scoped failure reasons and secret-safe evidence; local provider traces SHALL be labelled contract evidence rather than actual Google or universal wallet compatibility

#### Scenario: OID-SC-012 Actual Google and selected wallet prove their own integration
- **WHEN** a dedicated configured Google test account and selected browser wallet authenticate, redeem a test invitation, explicitly link and return through the other method against the real application
- **THEN** the external gate SHALL record actual provider and wallet edition/configuration evidence with the same owner across methods and no payment operation; unavailable credentials, callback configuration or wallet SHALL block the gate rather than being replaced by a local provider pass

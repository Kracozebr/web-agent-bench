# S2 public payment disclosure

## ADDED Requirements

### Requirement: SPP-REQ-001 Publish authoritative merchant payment identity
The provider SHALL publish payment domain version, authorization flow and domain name through free offer and catalog inspection using the same pinned policy as its actual payment protocol.

Scenario setup: Source-bound provider inspection and protocol tests

#### Scenario: SPP-SC-001 Keep free inspection and payment identity consistent
- **WHEN** an agent reads any advertised offer or catalog payment
- **THEN** the public version, paymentFlow and name SHALL match the actual provider policy without exposing signing material, changing economic admission terms or reading a task answer

### Requirement: SPP-REQ-002 Preserve strict and historical observation boundaries
The probe and owner payment-reference parser SHALL validate complete new public identity metadata, preserve legacy six-term references and retain exactly six economic consent terms.

Scenario setup: Strict split-offer projection and legacy byte-preservation checks

#### Scenario: SPP-SC-002 Reject substituted or partial public identity
- **WHEN** public metadata is complete or legacy metadata is absent
- **THEN** the exact pinned new shape or historical six-term shape SHALL remain valid while substituted partial extra or inconsistent root and offer metadata SHALL be rejected

### Requirement: SPP-REQ-003 Qualify public-only S2 completion under fresh source pins
The system SHALL qualify changed application and probe identities without rewriting historical release pins, task goals, required fields, deadlines or evaluator fractions.

Scenario setup: Real browser admission, actual provider MCP, worker and read-only owner/BEF evidence on a fresh isolated release

#### Scenario: SPP-SC-003 Complete Ranked S2 from actual public inspection
- **WHEN** the agent derives the required structured answer solely from the real provider inspection and submits it through MCP in a full twelve-task Ranked run
- **THEN** the unchanged worker evaluator SHALL persist known S2 credit 1/1, continue to confirmed run termination and preserve exact quoted finance, source authority and generation fences
